# Abstract
`hurtbreak-derive` is the primary derive macro for giving randomization/mutation methods to data types in [[hurtbreak|hurtbreak]].
# Goals
- Clean it the fuck up
- Have a compile time `proc-macro` read a provided toml for [[Fuzzable]] impl
- Output C header files (See [[hurtbreak-c]]) for use in embedded applications