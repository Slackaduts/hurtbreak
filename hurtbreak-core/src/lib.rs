pub use hurtbreak_derive::Fuzzable;

pub mod protocols;
pub mod attack;

pub trait Fuzzable {
    fn fuzz(&mut self);
}

pub trait Protocol {
    fn payload(&self) -> Vec<u8>;
}
