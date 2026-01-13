pub mod api;

#[cfg(test)]
mod tests {
    #[test]
    fn write_hurt_file() -> Result<(), crate::api::TraceError> {
        let mut file = std::fs::File::create("./rust_test.hurt")?;

        let mut ctx = crate::api::write::hurt_write_header(
            &mut file,
            0x01,
            0x01,
            crate::api::Endian::Little,
            1766371438000,
        )?;
        ctx.write_session_start(0xDEADBEEF, 42)?;

        let mut step = ctx.begin_step(0xCAFEBABE)?;
        step.add(0, &[1, 2, 3, 4])?;
        step.add(1, &[0xFF])?;
        step.finish()?;

        ctx.write_goal_reached(42)?;

        Ok(())
    }

    #[test]
    fn read_hurt_file() -> Result<(), crate::api::TraceError> {
        let file = std::fs::File::open("./rust_test.hurt")?;
        let reader = crate::api::read::TraceReader::new(file)?;

        println!("Header: {:?}", reader.header);

        for record in reader {
            println!("Record: {:?}", record?);
        }

        Ok(())
    }
}
