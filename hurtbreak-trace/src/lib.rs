#![no_std]

pub mod api;

pub use api::{
    Header, Record, RecordType, TraceError, TraceFlags,
    TraceReader, TraceWriter,
    MAGIC, VERSION,
    crc8_smbus, crc8_continue, encode_varint, decode_varint,
};

#[cfg(test)]
mod tests {
    extern crate std;
    use std::vec::Vec;
    use std::io::Write as _;

    use crate::{RecordType, TraceFlags, TraceReader, TraceWriter, encode_varint, MAGIC, VERSION};

    struct VecWriter(Vec<u8>);

    impl embedded_io::ErrorType for VecWriter {
        type Error = core::convert::Infallible;
    }

    impl embedded_io::Write for VecWriter {
        fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            self.0.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    struct SliceReader<'a> {
        data: &'a [u8],
        pos: usize,
    }

    impl embedded_io::ErrorType for SliceReader<'_> {
        type Error = core::convert::Infallible;
    }

    impl embedded_io::Read for SliceReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            let remaining = &self.data[self.pos..];
            let n = buf.len().min(remaining.len());
            buf[..n].copy_from_slice(&remaining[..n]);
            self.pos += n;
            Ok(n)
        }
    }

    #[test]
    fn write_and_read_rust_test_hurt() {
        let flags = TraceFlags { trimmed: false, responses_included: true };
        let mut writer = TraceWriter::new(VecWriter(Vec::new()), flags, 1700000000000)
            .expect("failed to create writer");

        // SessionStart
        let mut payload = [0u8; 64];
        let mut i = 0;
        payload[i..i+8].copy_from_slice(&0xDEADBEEFu64.to_le_bytes()); i += 8;
        payload[i..i+8].copy_from_slice(&0xCAFEBABEu64.to_le_bytes()); i += 8;
        let name = b"MockProtocol";
        let mut vbuf = [0u8; 10];
        let vlen = encode_varint(name.len(), &mut vbuf);
        payload[i..i+vlen].copy_from_slice(&vbuf[..vlen]); i += vlen;
        payload[i..i+name.len()].copy_from_slice(name); i += name.len();
        writer.write_record(RecordType::SessionStart, &payload[..i]).unwrap();

        // Novel
        writer.write_record(RecordType::Novel, &[]).unwrap();

        // Timeout
        writer.write_record(RecordType::Timeout, &5000u32.to_le_bytes()).unwrap();

        // Marker
        let tag = b"checkpoint_1";
        let mut payload = [0u8; 32];
        let mut i = 0;
        let vlen = encode_varint(tag.len(), &mut vbuf);
        payload[i..i+vlen].copy_from_slice(&vbuf[..vlen]); i += vlen;
        payload[i..i+tag.len()].copy_from_slice(tag); i += tag.len();
        writer.write_record(RecordType::Marker, &payload[..i]).unwrap();

        let data = writer.into_inner().0;

        // Verify header
        assert_eq!(&data[0..4], &MAGIC);
        assert_eq!(data[4], VERSION);
        assert_eq!(data[5], 0x02);
        assert_eq!(data[6], 0x00);
        assert!(data.len() > 15);

        // Write to file
        let mut file = std::fs::File::create("rust_test.hurt").expect("failed to create file");
        file.write_all(&data).expect("failed to write file");

        // Read it back
        let mut reader = TraceReader::new(SliceReader { data: &data, pos: 0 })
            .expect("failed to create reader");

        assert_eq!(reader.header().magic, MAGIC);
        assert_eq!(reader.header().version, VERSION);
        assert_eq!(reader.header().start_time_ms(), 1700000000000);

        let mut buf = [0u8; 256];

        // SessionStart
        let rec = reader.read_record(&mut buf).unwrap().unwrap();
        assert_eq!(rec.rec_type, RecordType::SessionStart);

        // Novel
        let rec = reader.read_record(&mut buf).unwrap().unwrap();
        assert_eq!(rec.rec_type, RecordType::Novel);
        assert_eq!(rec.payload.len(), 0);

        // Timeout
        let rec = reader.read_record(&mut buf).unwrap().unwrap();
        assert_eq!(rec.rec_type, RecordType::Timeout);
        assert_eq!(rec.payload, &5000u32.to_le_bytes());

        // Marker
        let rec = reader.read_record(&mut buf).unwrap().unwrap();
        assert_eq!(rec.rec_type, RecordType::Marker);

        // EOF
        let rec = reader.read_record(&mut buf).unwrap();
        assert!(rec.is_none());
    }
}