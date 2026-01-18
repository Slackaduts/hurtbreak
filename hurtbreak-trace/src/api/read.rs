use embedded_io::Read;
use crate::api::{Header, RecordType, TraceError, MAGIC, VERSION, crc8_smbus, crc8_continue, decode_varint};

fn read_exact<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<(), TraceError<R::Error>> {
    let mut read = 0;
    while read < buf.len() {
        let n = r.read(&mut buf[read..]).map_err(TraceError::Io)?;
        if n == 0 {
            return Err(TraceError::Truncated);
        }
        read += n;
    }
    Ok(())
}

pub struct Record<'a> {
    pub rec_type: RecordType,
    pub payload: &'a [u8],
}

pub struct TraceReader<R> {
    inner: R,
    header: Header,
}

impl<R: Read> TraceReader<R> {
    pub fn new(mut reader: R) -> Result<Self, TraceError<R::Error>> {
        let mut header_buf = [0u8; 15];
        read_exact(&mut reader, &mut header_buf)?;

        let header: Header = *bytemuck::from_bytes(&header_buf);

        if header.magic != MAGIC {
            return Err(TraceError::BadMagic);
        }
        if header.version != VERSION {
            return Err(TraceError::UnsupportedVersion(header.version));
        }

        Ok(Self { inner: reader, header })
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn read_record<'a>(
        &mut self,
        buf: &'a mut [u8],
    ) -> Result<Option<Record<'a>>, TraceError<R::Error>> {
        let mut type_buf = [0u8; 1];
        match self.inner.read(&mut type_buf) {
            Ok(0) => return Ok(None),
            Ok(_) => {}
            Err(e) => return Err(TraceError::Io(e)),
        }

        let rec_type_byte = type_buf[0];
        let rec_type = RecordType::from_u8(rec_type_byte)
            .ok_or(TraceError::UnknownRecordType(rec_type_byte))?;

        let mut varint_buf = [0u8; 10];
        let mut varint_len = 0;
        loop {
            let mut b = [0u8; 1];
            read_exact(&mut self.inner, &mut b)?;
            varint_buf[varint_len] = b[0];
            varint_len += 1;
            if b[0] & 0x80 == 0 {
                break;
            }
            if varint_len >= 10 {
                return Err(TraceError::VarintOverflow);
            }
        }

        let (payload_len, _) = decode_varint(&varint_buf[..varint_len])
            .ok_or(TraceError::VarintOverflow)?;

        if payload_len > buf.len() {
            return Err(TraceError::Truncated);
        }

        let payload_buf = &mut buf[..payload_len];
        read_exact(&mut self.inner, payload_buf)?;

        let mut crc_buf = [0u8; 1];
        read_exact(&mut self.inner, &mut crc_buf)?;
        let stored_crc = crc_buf[0];

        let mut computed_crc = crc8_smbus(&[rec_type_byte]);
        computed_crc = crc8_continue(computed_crc, &varint_buf[..varint_len]);
        computed_crc = crc8_continue(computed_crc, payload_buf);

        if computed_crc != stored_crc {
            return Err(TraceError::CrcMismatch {
                expected: stored_crc,
                got: computed_crc,
            });
        }

        Ok(Some(Record {
            rec_type,
            payload: payload_buf,
        }))
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}