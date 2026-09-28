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
        let (stream, reader, token) = timeout(TIMEOUT, handshake(client, &identity, previous))
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
        })
    }

    pub fn push_token(&self) -> &PushToken {
        &self.token
    }

    pub fn identity(&self) -> &PushIdentity {
        &self.identity
    }

    /// Reuses the current identity/token and restores topics. Failed attempts
    /// leave the existing identity and token available for another attempt.
    pub async fn reconnect(&mut self, client: &Client) -> Result<(), ConnectError> {
        let (mut stream, reader, token) = timeout(
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

    /// Receives the next notification, driving keepalive while waiting.
    /// Call `acknowledge` once the notification is accepted or stored.
    /// Reconnect after errors or cancellation during a keepalive write.
    pub async fn receive(&mut self) -> Result<Notification, CourierError> {
        loop {
            let deadline = self.pong_deadline.unwrap_or(self.next_ping);
            let frame = tokio::select! {
                frame = self.reader.read(&mut self.stream) => frame?,
                _ = sleep_until(deadline) => {
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
                    let topic = frame
                        .required(2)?
                        .try_into()
                        .map_err(|_| CourierError::InvalidField(2))?;
                    let token = frame.get(1).unwrap_or(self.token.as_bytes());
                    if token != self.token.as_bytes() {
                        return Err(CourierError::TokenMismatch);
                    }
                    return Ok(Notification {
                        id,
                        topic,
                        payload: frame.into_field(3)?,
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
) -> Result<(TlsStream<TcpStream>, FrameReader, PushToken), ConnectError> {
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
    roots.add(CertificateDer::from_slice(include_bytes!(
        "../certs/AppleRootCA.der"
    )))?;
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
    Message::SetActive.write(&mut stream).await?;
    Ok((stream, reader, token))
}
