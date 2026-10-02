use crate::{
    PushIdentity,
    activation::sign_sha1,
    protocol::{Command, CourierError, FrameReader, Message, TIMEOUT},
};
use bytes::Bytes;
use plist::{Dictionary, Value};
use reqwest::Client;
use rsa::rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::{
    fmt, io,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::{
    io::AsyncWriteExt,
    net::TcpStream,
    time::{Instant, sleep_until, timeout},
};
use tokio_rustls::{
    TlsConnector,
    client::TlsStream,
    rustls::{
        self, ClientConfig, RootCertStore,
        crypto::ring,
        pki_types::{CertificateDer, ServerName},
    },
};

const KEEPALIVE: Duration = Duration::from_secs(60);

#[derive(Debug, Error)]
pub enum ConnectError {
    #[error("APS configuration request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("Invalid APS configuration plist: {0}")]
    Plist(#[from] plist::Error),
    #[error("Missing or invalid APS configuration field: {0}")]
    Configuration(&'static str),
    #[error("Invalid courier TLS hostname: {0}")]
    Hostname(#[from] rustls::pki_types::InvalidDnsNameError),
    #[error("TLS configuration failed: {0}")]
    Tls(#[from] rustls::Error),
    #[error("Courier connection failed: {0}")]
    Io(#[from] io::Error),
    #[error("Nonce signing failed: {0}")]
    Signing(#[from] rsa::Error),
    #[error("System clock precedes Unix epoch: {0}")]
    Clock(#[from] std::time::SystemTimeError),
    #[error("Courier handshake failed: {0}")]
    Courier(#[from] CourierError),
    #[error("APS rejected the connection with status {0}")]
    Rejected(u8),
    #[error("APS connection timed out")]
    Timeout,
}

/// A courier-issued token. Display is the lowercase hex used by AuthKit.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PushToken([u8; 32]);

impl PushToken {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for PushToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for PushToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PushToken([redacted])")
    }
}

pub struct Notification {
    pub id: u32,
    /// SHA-1 of the topic name.
    pub topic: [u8; 20],
    /// Unmodified bytes sharing the received frame's allocation.
    pub payload: Bytes,
}

/// The courier's response to an outgoing message, not a recipient delivery receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendStatus {
    Accepted,
    Rejected(u8),
}

#[derive(Debug, Error)]
pub enum SendError {
    #[error("APS message {0} is still awaiting acknowledgement")]
    PendingAcknowledgement(u32),
    #[error("APS payload is {size} bytes, exceeding the courier limit of {maximum}")]
    PayloadTooLarge { size: usize, maximum: u16 },
    #[error("Sending the APS message failed: {0}")]
    Courier(#[from] CourierError),
}

pub enum Event {
    Notification(Notification),
    Acknowledgement { id: u32, status: SendStatus },
}

/// A completed APS handshake and its live courier transport.
/// Call `receive` to drive notifications and keepalive. No tasks are spawned.
pub struct PushConnection {
    identity: PushIdentity,
    token: PushToken,
    stream: TlsStream<TcpStream>,
    reader: FrameReader,
    topics: Vec<[u8; 20]>,
    next_ping: Instant,
    pong_deadline: Option<Instant>,
    pending_send: Option<(u32, Instant)>,
    max_payload_size: u16,
}

impl PushConnection {
    /// Takes ownership of the identity without copying its private key.
    pub async fn connect(client: &Client, identity: PushIdentity) -> Result<Self, ConnectError> {
        Self::open(client, identity, None).await
    }

    /// Reuses a saved token and identity. Inspect `push_token` afterward in case
    /// the server returned a replacement.
    pub async fn resume(
        client: &Client,
        identity: PushIdentity,
        token: &PushToken,
    ) -> Result<Self, ConnectError> {
        Self::open(client, identity, Some(token)).await
    }

    async fn open(
        client: &Client,
        identity: PushIdentity,
        previous: Option<&PushToken>,
    ) -> Result<Self, ConnectError> {
        let (stream, reader, token, max_payload_size) =
            timeout(TIMEOUT, handshake(client, &identity, previous))
                .await
                .map_err(|_| ConnectError::Timeout)??;
        Ok(Self {
            identity,
            token,
            stream,
            reader,
            topics: Vec::new(),
            next_ping: Instant::now() + KEEPALIVE,
            pong_deadline: None,
            pending_send: None,
            max_payload_size,
        })
    }

    pub fn push_token(&self) -> &PushToken {
        &self.token
    }

    pub fn identity(&self) -> &PushIdentity {
        &self.identity
    }

    /// The courier's advertised payload limit, or the TLV limit if omitted.
    pub fn max_payload_size(&self) -> u16 {
        self.max_payload_size
    }

    /// Reuses the current identity/token and restores topics. Failed attempts
    /// leave the existing identity and token available for another attempt.
    /// An unacknowledged send has an unknown outcome and is not retried.
    pub async fn reconnect(&mut self, client: &Client) -> Result<(), ConnectError> {
        let (mut stream, reader, token, max_payload_size) = timeout(
            TIMEOUT,
            handshake(client, &self.identity, Some(&self.token)),
        )
        .await
        .map_err(|_| ConnectError::Timeout)??;
        Message::Filter {
            token: &token,
            topics: &self.topics,
        }
        .write(&mut stream)
        .await?;
        self.stream = stream;
        self.reader = reader;
        self.token = token;
        self.next_ping = Instant::now() + KEEPALIVE;
        self.pong_deadline = None;
        self.pending_send = None;
        self.max_payload_size = max_payload_size;
        Ok(())
    }

    /// Replaces the set of enabled notification topics.
    pub async fn set_topics(&mut self, topics: &[&str]) -> Result<(), CourierError> {
        let hashes = topics
            .iter()
            .map(|s| Sha1::digest(s.as_bytes()).into())
            .collect::<Vec<_>>();
        Message::Filter {
            token: &self.token,
            topics: &hashes,
        }
        .write(&mut self.stream)
        .await?;
        self.topics = hashes;
        Ok(())
    }

    /// Writes an outgoing message without waiting for its acknowledgement.
    /// Only one send may await acknowledgement at a time: the courier can omit
    /// its message ID. `receive` returns the supplied `id` in the acknowledgement.
    /// Use a new ID for each send. Payload bytes are sent unchanged.
    /// A successful write does not imply courier acceptance or recipient delivery.
    /// Reconnect after I/O errors, timeouts, or cancellation during the write.
    pub async fn send(&mut self, id: u32, topic: &str, payload: &[u8]) -> Result<(), SendError> {
        if let Some((id, _)) = self.pending_send {
            return Err(SendError::PendingAcknowledgement(id));
        }
        // Validate before marking the send in flight. The remaining fields
        // have fixed sizes and fit within the frame limit.
        if payload.len() > usize::from(self.max_payload_size) {
            return Err(SendError::PayloadTooLarge {
                size: payload.len(),
                maximum: self.max_payload_size,
            });
        }
        // Set before the write so cancellation cannot permit a second send.
        self.pending_send = Some((id, Instant::now() + TIMEOUT));
        Message::Send {
            token: &self.token,
            topic: &Sha1::digest(topic.as_bytes()).into(),
            id,
            payload,
        }
        .write(&mut self.stream)
        .await?;
        Ok(())
    }

    /// Receives the next notification or send acknowledgement, driving keepalive.
    /// Call `acknowledge` once a notification is accepted or stored.
    /// Send acknowledgements do not themselves require acknowledgement.
    /// An outgoing send times out after 30 seconds. Reconnect afterward; its
    /// outcome is unknown and it is not replayed.
    /// Reconnect after errors or cancellation during a keepalive write.
    pub async fn receive(&mut self) -> Result<Event, CourierError> {
        loop {
            let mut deadline = self.pong_deadline.unwrap_or(self.next_ping);
            if let Some((id, expires)) = self.pending_send {
                // Check before reading so incoming traffic cannot starve the timeout.
                if Instant::now() >= expires {
                    return Err(CourierError::AcknowledgementTimeout(id));
                }
                deadline = deadline.min(expires);
            }
            let frame = tokio::select! {
                frame = self.reader.read(&mut self.stream) => frame?,
                _ = sleep_until(deadline) => {
                    if let Some((id, expires)) = self.pending_send
                        && Instant::now() >= expires {
                        return Err(CourierError::AcknowledgementTimeout(id));
                    }
                    if self.pong_deadline.is_some() { return Err(CourierError::Timeout); }
                    Message::Ping.write(&mut self.stream).await?;
                    self.pong_deadline = Some(Instant::now() + TIMEOUT);
                    continue;
                }
            };
            match frame.command() {
                Command::Notification => {
                    let id = u32::from_be_bytes(
                        frame
                            .required(4)?
                            .try_into()
                            .map_err(|_| CourierError::InvalidField(4))?,
                    );
                    let token = frame.get(1).unwrap_or(self.token.as_bytes());
                    if token != self.token.as_bytes() {
                        return Err(CourierError::TokenMismatch);
                    }
                    let topic = frame
                        .required(2)?
                        .try_into()
                        .map_err(|_| CourierError::InvalidField(2))?;
                    return Ok(Event::Notification(Notification {
                        id,
                        topic,
                        payload: frame.into_field(3)?,
                    }));
                }
                Command::Ack => {
                    let Some((id, _)) = self.pending_send else {
                        continue;
                    };
                    let token = frame.get(1).unwrap_or(self.token.as_bytes());
                    if token != self.token.as_bytes() {
                        return Err(CourierError::TokenMismatch);
                    }
                    if let Some(received_id) = frame.get(4) {
                        let received_id = u32::from_be_bytes(
                            received_id
                                .try_into()
                                .map_err(|_| CourierError::InvalidField(4))?,
                        );
                        if received_id != id {
                            continue;
                        }
                    }
                    let [status] = frame.required(8)? else {
                        return Err(CourierError::InvalidField(8));
                    };
                    self.pending_send = None;
                    return Ok(Event::Acknowledgement {
                        id,
                        status: match status {
                            0 => SendStatus::Accepted,
                            status => SendStatus::Rejected(*status),
                        },
                    });
                }
                Command::Ping => Message::Pong.write(&mut self.stream).await?,
                Command::Pong => {
                    self.pong_deadline = None;
                    self.next_ping = Instant::now() + KEEPALIVE;
                }
                _ => {}
            }
        }
    }

    /// Acknowledges receipt of a notification returned by this connection.
    /// Reconnect after errors or cancellation during the write.
    pub async fn acknowledge(&mut self, notification: &Notification) -> Result<(), CourierError> {
        Message::Ack {
            token: &self.token,
            id: notification.id,
        }
        .write(&mut self.stream)
        .await
    }

    pub async fn close(mut self) -> io::Result<()> {
        timeout(TIMEOUT, self.stream.shutdown())
            .await
            .map_err(|_| io::ErrorKind::TimedOut)?
    }
}

async fn handshake(
    client: &Client,
    identity: &PushIdentity,
    previous: Option<&PushToken>,
) -> Result<(TlsStream<TcpStream>, FrameReader, PushToken, u16), ConnectError> {
    let body = client
        .get("https://init.push.apple.com/bag")
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    let mut bag: Dictionary = plist::from_bytes(&body)?;
    if let Some(Value::Data(data)) = bag.get("bag") {
        bag = plist::from_bytes(data)?;
    }
    let host = bag
        .get("APNSCourierHostname")
        .and_then(Value::as_string)
        .ok_or(ConnectError::Configuration("APNSCourierHostname"))?;
    let verified = bag
        .get("APNSVerifiedCourierHostname")
        .and_then(Value::as_string)
        .unwrap_or(host);
    let count = bag
        .get("APNSCourierHostcount")
        .and_then(Value::as_unsigned_integer)
        .filter(|count| (1..=1000).contains(count))
        .ok_or(ConnectError::Configuration("APNSCourierHostcount"))?;
    let target = format!("{}-{host}", 1 + u64::from(OsRng.next_u32()) % count);
    let server_name = ServerName::try_from(verified.to_owned())?;
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from_slice(crate::APPLE_ROOT_CA))?;
    let mut config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    // Select the signed Connect handshake without enabling packed APS frames.
    config.alpn_protocols = vec![b"apns-security-v3".to_vec()];
    let socket = TcpStream::connect((target.as_str(), 5223)).await?;
    let mut stream = TlsConnector::from(Arc::new(config))
        .connect(server_name, socket)
        .await?;

    let millis = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
    // APS nonce: discriminator 0, big-endian Unix milliseconds, 8 random bytes.
    let mut nonce = [0; 17];
    nonce[1..9].copy_from_slice(&millis.to_be_bytes());
    OsRng.fill_bytes(&mut nonce[9..]);
    let raw_signature = sign_sha1(identity.private_key(), &nonce)?;
    let mut signature = Vec::with_capacity(2 + raw_signature.len());
    // Apple's nonce signer prefixes its RSA/SHA-1 signature with these bytes.
    signature.extend_from_slice(&[1, 1]);
    signature.extend_from_slice(&raw_signature);
    Message::Connect {
        previous,
        certificate: identity.certificate(),
        nonce: &nonce,
        signature: &signature,
    }
    .write(&mut stream)
    .await?;
    let mut reader = FrameReader::default();
    let reply = reader.read(&mut stream).await?;
    if reply.command() != Command::Connected {
        return Err(CourierError::UnexpectedCommand(reply.command().code()).into());
    }
    let [status] = reply.required(1)? else {
        return Err(CourierError::InvalidField(1).into());
    };
    if *status != 0 {
        return Err(ConnectError::Rejected(*status));
    }
    let token = match reply.get(3) {
        Some(bytes) => PushToken(
            bytes
                .try_into()
                .map_err(|_| CourierError::InvalidField(3))?,
        ),
        None => previous.cloned().ok_or(CourierError::MissingField(3))?,
    };
    let max_payload_size = match reply.get(4) {
        Some(bytes) => u16::from_be_bytes(
            bytes
                .try_into()
                .map_err(|_| CourierError::InvalidField(4))?,
        ),
        None => u16::MAX,
    };
    Message::SetActive.write(&mut stream).await?;
    Ok((stream, reader, token, max_payload_size))
}
