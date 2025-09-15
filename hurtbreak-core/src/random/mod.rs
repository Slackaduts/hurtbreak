/// Provides randomization interface for the library.
///
/// Swap the default implementation out if you would prefer a different algorithm or randomization solution.
pub trait FuzzerRNG {
    fn fuzz_numeric<T: FuzzableNumber>(lb: Option<T>, ub: Option<T>) -> T {
        let min = lb.unwrap_or(T::min());
        let max = ub.unwrap_or(T::max());
        T::fuzz(min, max)
    }
    fn choice<T: Clone>(&self, slice: &[T]) -> Option<T>;
    fn alphabetic(&self) -> u8;
}

#[cfg(feature = "std_rng")]
pub use default_impls::{DefaultRNG, DEFAULT_RNG};

/// Provides primarily default fuzzing implementation ergonomics.
///
/// Abstracts the constants and fastrand::$type calling logic.
pub trait FuzzableNumber: Sized {
    fn fuzz(lb: Self, ub: Self) -> Self;
    fn min() -> Self;
    fn max() -> Self;
}

/// Automates the default implementation (via fastrand::$type) of single-value number randomization.
#[cfg(feature = "std_rng")]
macro_rules! impl_fuzzable_integer {
    ($type:ident) => {
        impl FuzzableNumber for $type {
            fn fuzz(lb: Self, ub: Self) -> Self {
                fastrand::$type(lb..ub)
            }

            fn max() -> Self {
                <$type>::MAX
            }

            fn min() -> Self {
                <$type>::MIN
            }
        }
    };
}

#[cfg(feature = "std_rng")]
mod default_impls {
    use super::*;

    // Implement FuzzableNumber for stdlib
    impl_fuzzable_integer!(usize);
    impl_fuzzable_integer!(u8);
    impl_fuzzable_integer!(i8);
    impl_fuzzable_integer!(u16);
    impl_fuzzable_integer!(i16);
    impl_fuzzable_integer!(u32);
    impl_fuzzable_integer!(i32);
    impl_fuzzable_integer!(u64);
    impl_fuzzable_integer!(i64);
    impl_fuzzable_integer!(u128);
    impl_fuzzable_integer!(i128);

    /// Default implementation of FuzzerRNG using fastrand
    pub struct DefaultRNG;

    impl FuzzerRNG for DefaultRNG {
        fn choice<T: Clone>(&self, slice: &[T]) -> Option<T> {
            fastrand::choice(slice).cloned()
        }

        fn alphabetic(&self) -> u8 {
            fastrand::alphabetic() as u8
        }
    }

    /// Global instance of the default RNG
    pub static DEFAULT_RNG: DefaultRNG = DefaultRNG;
}
