pub use hurtbreak_derive::Fuzzable;

pub mod protocols;
pub mod attack;

#[cfg(feature = "async")]
pub mod async_ext;

pub trait Fuzzable {
    fn fuzz(&mut self);
}

pub trait Protocol {
    fn payload(&self) -> Vec<u8>;
}
