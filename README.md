# Hurtbreak
A protocol-agnostic fuzzer. 

## Features
- Highly polymorphic in design- Can scaffold out a fuzzer or bruteforcer for essentially anything with identical top-level logic.
- Primarily a tech demo currently- Documentation and more polished code forthcoming.
- Designed to require as few dependencies as possible so this code can be served anywhere


## Immediate plans
- Add support for hardware RNG
- Stop using fastrand crate and make the randomization itself modular


## Future plans
- Support for `#![no_std]`
- Default implementations for ModBUS, CAN
- Ideally, I think this project has potential in embedded applications.

## Contributions
Contributions are welcome but this project isn't polished enough and I might decide to change the entire design- Please voice your idea in an issue first.
