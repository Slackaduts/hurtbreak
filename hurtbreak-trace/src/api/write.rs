use bytemuck::{Pod, Zeroable};
use embedded_io::Write;
use crate::api::TraceError;

pub const MAGIC: [u8; 4] = *b"HURT";
pub const VERSION: u8 = 0x02;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordType {
    SessionStart = 0x01,
    Mutation = 0x02,
    ResponseFingerprint = 0x03,
    Novel = 0x04,
    StateTransition = 0x05,
    Goal = 0x06,
    Timeout = 0x07,
    Marker = 0x08,
}

impl RecordType {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(Self::SessionStart),
            0x02 => Some(Self::Mutation),
            0x03 => Some(Self::ResponseFingerprint),
            0x04 => Some(Self::Novel),
            0x05 => Some(Self::StateTransition),
            0x06 => Some(Self::Goal),
            0x07 => Some(Self::Timeout),
            0x08 => Some(Self::Marker),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TraceFlags {
    pub trimmed: bool,
    pub responses_included: bool,
}

impl TraceFlags {
    pub fn to_byte(self) -> u8 {
        (if self.trimmed { 0x01 } else { 0 }) | (if self.responses_included { 0x02 } else { 0 })
    }
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C, packed)]
pub struct Header {
    pub magic: [u8; 4],
    pub version: u8,
    pub flags: u8,
    pub endian: u8,
    pub start_time: [u8; 8],
}

impl Header {
    pub fn new(flags: TraceFlags, start_time_ms: u64) -> Self {
        Self {
            magic: MAGIC,
            version: VERSION,
            flags: flags.to_byte(),
            endian: 0x00,
            start_time: start_time_ms.to_le_bytes(),
        }
    }

    pub fn start_time_ms(&self) -> u64 {
        u64::from_le_bytes(self.start_time)
    }
}

pub fn crc8_smbus(data: &[u8]) -> u8 {
    let mut crc = 0u8;
    for &b in data {
        crc ^= b;
        for _ in 0..8 {
            crc = if crc & 0x80 != 0 { (crc << 1) ^ 0x07 } else { crc << 1 };
        }
    }
    crc
}

pub fn encode_varint(mut value: usize, buf: &mut [u8; 10]) -> usize {
    let mut i = 0;
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf[i] = byte;
        i += 1;
        if value == 0 {
            break;
        }
    }
    i
}

pub fn decode_varint(data: &[u8]) -> Option<(usize, usize)> {
    let mut value: usize = 0;
    let mut shift = 0;
    for (i, &byte) in data.iter().enumerate() {
        value |= ((byte & 0x7F) as usize) << shift;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
    None
}

fn write_all<W: Write>(w: &mut W, buf: &[u8]) -> Result<(), W::Error> {
    let mut written = 0;
    while written < buf.len() {
        let n = w.write(&buf[written..])?;
        written += n;
    }
    Ok(())
}

pub fn crc8_continue(mut crc: u8, data: &[u8]) -> u8 {
    for &b in data {
        crc ^= b;
        for _ in 0..8 {
            crc = if crc & 0x80 != 0 { (crc << 1) ^ 0x07 } else { crc << 1 };
        }
    }
    crc
}

pub struct TraceWriter<W> {
    inner: W,
}

impl<W: Write> TraceWriter<W> {
    pub fn new(
        mut writer: W,
        flags: TraceFlags,
        start_time_ms: u64,
    ) -> Result<Self, TraceError<W::Error>> {
        let header = Header::new(flags, start_time_ms);
        write_all(&mut writer, bytemuck::bytes_of(&header)).map_err(TraceError::Io)?;
        Ok(Self { inner: writer })
    }

    pub fn write_record(
        &mut self,
        rec_type: RecordType,
        payload: &[u8],
    ) -> Result<(), TraceError<W::Error>> {
        let mut len_buf = [0u8; 10];
        let len_n = encode_varint(payload.len(), &mut len_buf);

        let rec_type_byte = rec_type as u8;
        let mut crc = crc8_smbus(&[rec_type_byte]);
        crc = crc8_continue(crc, &len_buf[..len_n]);
        crc = crc8_continue(crc, payload);

        write_all(&mut self.inner, &[rec_type_byte]).map_err(TraceError::Io)?;
        write_all(&mut self.inner, &len_buf[..len_n]).map_err(TraceError::Io)?;
        write_all(&mut self.inner, payload).map_err(TraceError::Io)?;
        write_all(&mut self.inner, &[crc]).map_err(TraceError::Io)
    }

    pub fn flush(&mut self) -> Result<(), W::Error> {
        self.inner.flush()
    }

    pub fn into_inner(self) -> W {
        self.inner
    }
}