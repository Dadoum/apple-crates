use crate::PushToken;
use bytes::{Bytes, BytesMut};
use std::ops::Range;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

const MAX_FRAME_SIZE: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Command {
    Connect,
    Connected,
    Filter,
    Notification,
    Ack,
    Ping,
    Pong,
    SetState,
    Unknown(u8),
}

impl Command {
    pub fn code(self) -> u8 {
        match self {
            Self::Connect => 7,
            Self::Connected => 8,
            Self::Filter => 9,
            Self::Notification => 10,
            Self::Ack => 11,
            Self::Ping => 12,
            Self::Pong => 13,
            Self::SetState => 20,
            Self::Unknown(code) => code,
        }
    }
}

/// Outgoing messages borrow their fields and encode directly into one wire buffer.
pub(crate) enum Message<'a> {
    Connect {
        previous: Option<&'a PushToken>,
        certificate: &'a [u8],
        nonce: &'a [u8; 17],
        signature: &'a [u8],
    },
    Filter {
        token: &'a PushToken,
        topics: &'a [[u8; 20]],
    },
    Send {
        token: &'a PushToken,
        topic: &'a [u8; 20],
        id: u32,
        payload: &'a [u8],
    },
    Ack {
        token: &'a PushToken,
        id: u32,
    },
    Ping,
    Pong,
    SetActive,
}

impl Message<'_> {
    pub async fn write(self, stream: &mut (impl AsyncWrite + Unpin)) -> Result<(), CourierError> {
        let frame = match self {
            Self::Connect {
                previous,
                certificate,
                nonce,
                signature,
            } => {
                let mut frame = Frame::new(Command::Connect);
                if let Some(token) = previous {
                    frame.push(1, token.as_bytes())?;
                }
                frame.push(2, [1])?; // Connect state; Apple's disconnect path sends 2.
                // Presence flags used by rustpush. The Windows client sends 0x4c
                // on connect and 0x48 for presence; individual bits are unverified.
                frame.push(5, 0x41u32.to_be_bytes())?;
                frame.push(12, certificate)?;
                frame.push(13, nonce)?;
                frame.push(14, signature)?;
                // Protocol version used by rustpush. Windows sends 5; macOS 27
                // sends 12 with additional capabilities we do not implement.
                frame.push(16, 9u16.to_be_bytes())?;
                frame
            }
            Self::Filter { token, topics } => {
                let mut frame = Frame::new(Command::Filter);
                frame.push(1, token.as_bytes())?;
                for topic in topics {
                    frame.push(2, topic)?;
                }
                frame
            }
            Self::Send {
                token,
                topic,
                id,
                payload,
            } => {
                let mut frame = Frame::new(Command::Notification);
                frame.push(4, id.to_be_bytes())?;
                // Outgoing messages reverse the incoming token/topic fields.
                frame.push(1, topic)?;
                frame.push(2, token.as_bytes())?;
                frame.push(3, payload)?;
                frame
            }
            Self::Ack { token, id } => {
                let mut frame = Frame::new(Command::Ack);
                frame.push(1, token.as_bytes())?;
                frame.push(4, id.to_be_bytes())?;
                frame.push(8, [0])?; // Success.
                frame
            }
            Self::Ping => Frame::new(Command::Ping),
            Self::Pong => Frame::new(Command::Pong),
            Self::SetActive => {
                let mut frame = Frame::new(Command::SetState);
                frame.push(1, [1])?;
                // rustpush's state interval. INT_MAX is observed; "infinite" is unverified.
                frame.push(2, 0x7fff_ffffu32.to_be_bytes())?;
                frame
            }
        };
        frame.write(stream).await
    }
}

#[derive(Debug, Error)]
pub enum CourierError {
    #[error("Courier I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("APS frame exceeds the size limit")]
    FrameTooLarge,
    #[error("APS field {0} exceeds the wire size limit")]
    FieldTooLarge(u8),
    #[error("Truncated APS field")]
    TruncatedField,
    #[error("Missing APS field {0}")]
    MissingField(u8),
    #[error("Invalid APS field {0}")]
    InvalidField(u8),
    #[error("Unexpected APS command {0}")]
    UnexpectedCommand(u8),
    #[error("The message belongs to another push token")]
    TokenMismatch,
    #[error("Courier operation timed out")]
    Timeout,
    #[error("APS message {0} was not acknowledged before the deadline; reconnect before retrying")]
    AcknowledgementTimeout(u32),
}

// command:u8, length:u32, then (id:u8, length:u16, value), all big endian.
// Fields borrow the wire buffer instead of allocating a Vec for each TLV.
pub(crate) struct Frame {
    bytes: BytesMut,
}

impl Frame {
    fn new(command: Command) -> Self {
        Self {
            bytes: BytesMut::from(&[command.code(), 0, 0, 0, 0][..]),
        }
    }

    pub fn command(&self) -> Command {
        match self.bytes[0] {
            7 => Command::Connect,
            8 => Command::Connected,
            9 => Command::Filter,
            10 => Command::Notification,
            11 => Command::Ack,
            12 => Command::Ping,
            13 => Command::Pong,
            20 => Command::SetState,
            code => Command::Unknown(code),
        }
    }

    fn push(&mut self, id: u8, value: impl AsRef<[u8]>) -> Result<(), CourierError> {
        let value = value.as_ref();
        let size = u16::try_from(value.len()).map_err(|_| CourierError::FieldTooLarge(id))?;
        if self.bytes.len() - 5 + 3 + value.len() > MAX_FRAME_SIZE {
            return Err(CourierError::FrameTooLarge);
        }
        self.bytes.extend_from_slice(&[id]);
        self.bytes.extend_from_slice(&size.to_be_bytes());
        self.bytes.extend_from_slice(value);
        let length = (self.bytes.len() - 5) as u32;
        self.bytes[1..5].copy_from_slice(&length.to_be_bytes());
        Ok(())
    }

    fn field_range(&self, id: u8) -> Option<Range<usize>> {
        let mut offset = 5;
        while offset < self.bytes.len() {
            let key = self.bytes[offset];
            let size =
                u16::from_be_bytes([self.bytes[offset + 1], self.bytes[offset + 2]]) as usize;
            offset += 3;
            if key == id {
                return Some(offset..offset + size);
            }
            offset += size;
        }
        None
    }

    pub fn get(&self, id: u8) -> Option<&[u8]> {
        self.field_range(id).map(|range| &self.bytes[range])
    }

    pub fn required(&self, id: u8) -> Result<&[u8], CourierError> {
        self.get(id).ok_or(CourierError::MissingField(id))
    }

    pub fn into_field(self, id: u8) -> Result<Bytes, CourierError> {
        let range = self.field_range(id).ok_or(CourierError::MissingField(id))?;
        Ok(self.bytes.freeze().slice(range))
    }

    async fn write(&self, stream: &mut (impl AsyncWrite + Unpin)) -> Result<(), CourierError> {
        tokio::time::timeout(TIMEOUT, async {
            stream.write_all(&self.bytes).await?;
            stream.flush().await
        })
        .await
        .map_err(|_| CourierError::Timeout)??;
        Ok(())
    }
}

#[derive(Default)]
pub(crate) struct FrameReader {
    // Retained when keepalive interrupts a read.
    buffer: BytesMut,
}

impl FrameReader {
    pub async fn read(
        &mut self,
        stream: &mut (impl AsyncRead + Unpin),
    ) -> Result<Frame, CourierError> {
        loop {
            if self.buffer.len() >= 5 {
                let length = u32::from_be_bytes(self.buffer[1..5].try_into().unwrap()) as usize;
                if length > MAX_FRAME_SIZE {
                    return Err(CourierError::FrameTooLarge);
                }
                if self.buffer.len() >= length + 5 {
                    let mut offset = 5;
                    while offset < length + 5 {
                        if offset + 3 > length + 5 {
                            return Err(CourierError::TruncatedField);
                        }
                        let size =
                            u16::from_be_bytes([self.buffer[offset + 1], self.buffer[offset + 2]])
                                as usize;
                        offset += 3 + size;
                        if offset > length + 5 {
                            return Err(CourierError::TruncatedField);
                        }
                    }
                    return Ok(Frame {
                        bytes: self.buffer.split_to(length + 5),
                    });
                }
            }
            self.buffer.reserve(4096);
            if stream.read_buf(&mut self.buffer).await? == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
            }
        }
    }
}
