use crate::api::{Endian, TraceContext, TraceError, TraceStepBuilder, crc8, encode_varint};
use byteorder::{BigEndian, LittleEndian, WriteBytesExt};

fn write_u64<W: std::io::Write>(w: &mut W, endian: Endian, v: u64) -> Result<(), TraceError> {
    match endian {
        Endian::Little => w.write_u64::<LittleEndian>(v)?,
        Endian::Big => w.write_u64::<BigEndian>(v)?,
    }
    Ok(())
}

fn write_i64<W: std::io::Write>(w: &mut W, endian: Endian, v: i64) -> Result<(), TraceError> {
    match endian {
        Endian::Little => w.write_i64::<LittleEndian>(v)?,
        Endian::Big => w.write_i64::<BigEndian>(v)?,
    }
    Ok(())
}

fn write_record<W: std::io::Write>(
    w: &mut W,
    rec_type: u8,
    payload: &[u8],
) -> Result<(), TraceError> {
    let mut record = vec![rec_type];
    let len = payload.len() + 1; // payload + CRC
    record.extend(encode_varint(len as u64));
    record.extend(payload);
    record.push(crc8(&record));
    w.write_all(&record)?;
    Ok(())
}

pub fn hurt_write_header<W: std::io::Write>(
    w: &mut W,
    version: u8,
    mode: u8,
    endian: Endian,
    start_time: i64,
) -> Result<TraceContext<'_, W>, TraceError> {
    w.write_all(b"HURT")?;
    w.write_all(&[version, mode, endian as u8])?;
    write_i64(w, endian, start_time)?;
    Ok(TraceContext { writer: w, endian })
}

impl<'a, W: std::io::Write> TraceContext<'a, W> {
    pub fn write_session_start(&mut self, seed: u64, tripwire_id: u64) -> Result<(), TraceError> {
        let mut payload = Vec::new();
        write_u64(&mut payload, self.endian, seed)?;
        payload.extend(encode_varint(tripwire_id));
        write_record(self.writer, 0x01, &payload)
    }

    pub fn write_goal_reached(&mut self, goal_id: u64) -> Result<(), TraceError> {
        let payload = encode_varint(goal_id);
        write_record(self.writer, 0x03, &payload)
    }

    pub fn write_failed_step(&mut self, seed: u64) -> Result<(), TraceError> {
        let mut payload = Vec::new();
        write_u64(&mut payload, self.endian, seed)?;
        write_record(self.writer, 0x04, &payload)
    }

    pub fn begin_step(&mut self, seed: u64) -> Result<TraceStepBuilder<'a, '_, W>, TraceError> {
        let mut buf = Vec::new();
        write_u64(&mut buf, self.endian, seed)?;
        buf.push(0); // placeholder for field_count
        Ok(TraceStepBuilder {
            ctx: self,
            buf,
            field_count: 0,
        })
    }
}

impl<'a, 'b, W: std::io::Write> TraceStepBuilder<'a, 'b, W> {
    pub fn add(&mut self, id: u8, data: &[u8]) -> Result<(), TraceError> {
        self.buf.push(id);
        self.buf.extend(data);
        self.field_count += 1;
        Ok(())
    }

    pub fn finish(mut self) -> Result<(), TraceError> {
        self.buf[8] = self.field_count;
        write_record(self.ctx.writer, 0x02, &self.buf)
    }
}
