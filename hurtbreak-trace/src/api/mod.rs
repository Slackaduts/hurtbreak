use core::fmt;

pub mod write;
pub mod read;

#[derive(Debug)]
pub enum TraceError<E> {
    Io(E),
    Truncated,
    BadMagic,
    UnsupportedVersion(u8),
    UnknownRecordType(u8),
    VarintOverflow,
    CrcMismatch { expected: u8, got: u8 },
}

impl<E: fmt::Display> fmt::Display for TraceError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::Truncated => write!(f, "unexpected end of data"),
            Self::BadMagic => write!(f, "invalid magic bytes"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported version: {}", v),
            Self::UnknownRecordType(t) => write!(f, "unknown record type: 0x{:02x}", t),
            Self::VarintOverflow => write!(f, "varint overflow"),
            Self::CrcMismatch { expected, got } => {
                write!(f, "CRC mismatch: expected 0x{:02x}, got 0x{:02x}", expected, got)
            }
        }
    }
}

pub use write::{
    MAGIC, VERSION, RecordType, TraceFlags, Header,
    crc8_smbus, crc8_continue, encode_varint, decode_varint,
    TraceWriter,
};

pub use read::{
    Record, TraceReader,
};
