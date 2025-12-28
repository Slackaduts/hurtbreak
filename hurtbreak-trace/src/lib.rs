use std::io::{self, Write};

#[repr(u8)]
pub enum StepType {
    START,
    STEP,
    WIN,
    LOSS,
}

#[repr(C)]
pub struct Header {
    version: i8,
    mode: i8,
    timestamp: i32,
}

#[repr(C)]
pub struct Record<'a> {
    record_type: u8,
    length: u32,
    payload: &'a [u8],
    crc: u8,
}
