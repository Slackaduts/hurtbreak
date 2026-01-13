use crate::api::{Endian, TraceError, crc8};
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use std::io::Read;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceHeader {
    pub version: u8,
    pub mode: u8,
    pub endian: Endian,
    pub start_time: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub id: u8,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    SessionStart { seed: u64, tripwire_id: u64 },
    Step { seed: u64, fields: Vec<Field> },
    GoalReached { goal_id: u64 },
    FailedStep { seed: u64 },
    Unknown { rec_type: u8, payload: Vec<u8> },
}

fn read_varint<R: Read>(r: &mut R) -> Result<(u64, Vec<u8>), TraceError> {
    let mut val = 0u64;
    let mut shift = 0;
    let mut bytes = Vec::new();
    loop {
        let b = r.read_u8()?;
        bytes.push(b);
        val |= ((b & 0x7F) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
    }
    Ok((val, bytes))
}

fn read_u64<R: Read>(r: &mut R, endian: Endian) -> Result<u64, TraceError> {
    Ok(match endian {
        Endian::Little => r.read_u64::<LittleEndian>()?,
        Endian::Big => r.read_u64::<BigEndian>()?,
    })
}

fn read_i64<R: Read>(r: &mut R, endian: Endian) -> Result<i64, TraceError> {
    Ok(match endian {
        Endian::Little => r.read_i64::<LittleEndian>()?,
        Endian::Big => r.read_i64::<BigEndian>()?,
    })
}

pub fn read_header<R: Read>(r: &mut R) -> Result<TraceHeader, TraceError> {
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic)?;
    if &magic != b"HURT" {
        return Err(TraceError::InvalidMagic);
    }

    let version = r.read_u8()?;
    let mode = r.read_u8()?;
    let endian_byte = r.read_u8()?;
    let endian = match endian_byte {
        0x00 => Endian::Little,
        0x01 => Endian::Big,
        _ => return Err(TraceError::InvalidEndian(endian_byte)),
    };
    let start_time = read_i64(r, endian)?;

    Ok(TraceHeader {
        version,
        mode,
        endian,
        start_time,
    })
}

pub fn read_record<R: Read>(r: &mut R, endian: Endian) -> Result<Option<Record>, TraceError> {
    let rec_type = match r.read_u8() {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    };

    let mut record_bytes = vec![rec_type];
    let (length, len_bytes) = read_varint(r)?;
    record_bytes.extend(&len_bytes);

    let payload_len = length.saturating_sub(1) as usize;
    let mut payload = vec![0u8; payload_len];
    r.read_exact(&mut payload)?;
    record_bytes.extend(&payload);

    let crc = r.read_u8()?;
    let expected = crc8(&record_bytes);
    if expected != crc {
        return Err(TraceError::CrcMismatch {
            expected,
            actual: crc,
        });
    }

    let record = parse_payload(rec_type, &payload, endian)?;
    Ok(Some(record))
}

fn parse_payload(rec_type: u8, payload: &[u8], endian: Endian) -> Result<Record, TraceError> {
    let mut cursor = std::io::Cursor::new(payload);
    match rec_type {
        0x01 => {
            let seed = read_u64(&mut cursor, endian)?;
            let (tripwire_id, _) = read_varint(&mut cursor)?;
            Ok(Record::SessionStart { seed, tripwire_id })
        }
        0x02 => {
            let seed = read_u64(&mut cursor, endian)?;
            let field_count = cursor.read_u8()?;
            let mut fields = Vec::with_capacity(field_count as usize);
            for _ in 0..field_count {
                let id = cursor.read_u8()?;
                let (len, _) = read_varint(&mut cursor)?;
                let mut data = vec![0u8; len as usize];
                cursor.read_exact(&mut data)?;
                fields.push(Field { id, data });
            }
            Ok(Record::Step { seed, fields })
        }
        0x03 => {
            let (goal_id, _) = read_varint(&mut cursor)?;
            Ok(Record::GoalReached { goal_id })
        }
        0x04 => {
            let seed = read_u64(&mut cursor, endian)?;
            Ok(Record::FailedStep { seed })
        }
        _ => Ok(Record::Unknown {
            rec_type,
            payload: payload.to_vec(),
        }),
    }
}

pub struct TraceReader<R: Read> {
    reader: R,
    pub header: TraceHeader,
}

impl<R: Read> TraceReader<R> {
    pub fn new(mut reader: R) -> Result<Self, TraceError> {
        let header = read_header(&mut reader)?;
        Ok(Self { reader, header })
    }
}

impl<R: Read> Iterator for TraceReader<R> {
    type Item = Result<Record, TraceError>;

    fn next(&mut self) -> Option<Self::Item> {
        match read_record(&mut self.reader, self.header.endian) {
            Ok(Some(record)) => Some(Ok(record)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}
