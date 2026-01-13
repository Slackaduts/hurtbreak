pub mod read;
pub mod write;

use std::io::Write;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TraceError {
    #[error("buffer overflow")]
    Overflow,
    #[error("invalid state")]
    InvalidState,
    #[error("invalid magic bytes")]
    InvalidMagic,
    #[error("invalid endian byte: {0}")]
    InvalidEndian(u8),
    #[error("CRC mismatch: expected {expected:#04x}, got {actual:#04x}")]
    CrcMismatch { expected: u8, actual: u8 },
    #[error("unknown record type: {0:#04x}")]
    UnknownRecordType(u8),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Endian {
    Little = 0x00,
    Big = 0x01,
}

pub struct TraceContext<'a, W: Write> {
    writer: &'a mut W,
    endian: Endian,
}

pub struct TraceStepBuilder<'a, 'b, W: Write> {
    ctx: &'b mut TraceContext<'a, W>,
    buf: Vec<u8>,
    field_count: u8,
}

fn crc8(data: &[u8]) -> u8 {
    let mut crc = 0u8;
    for &b in data {
        crc ^= b;
        for _ in 0..8 {
            crc = if crc & 0x80 != 0 {
                (crc << 1) ^ 0x07
            } else {
                crc << 1
            };
        }
    }
    crc
}

fn encode_varint(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut b = (v & 0x7F) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
    out
}
