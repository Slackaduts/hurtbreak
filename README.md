# Hurtbreak
A protocol-agnostic fuzzer. 

## Features
- Highly polymorphic in design- Can scaffold out a fuzzer or bruteforcer for essentially anything with identical top-level logic.
- Designed to require as few dependencies as possible so this code can be served anywhere, feature flags can be used to limit the libdeps.

## CLI Usage

```bash
# Basic TCP fuzzing with 100 iterations
hurtbreak launch tcp --max-tries 100

# TCP fuzzing with fixed port
hurtbreak launch tcp --field port=8080 --max-tries 50

# USB fuzzing with device address and output to JSON
hurtbreak launch usb --field device_address=1 --max-tries 200 --output results.json

# Multiple field specifications
hurtbreak launch tcp --field port=443 --field host=192.168.1.1 --max-tries 1000
```

## Immediate plans
- Add support for hardware RNG
- Stop using fastrand crate and make the randomization itself modular


## Future plans
- Support for `#![no_std]`
- Default implementations for ModBUS, CAN
- Ideally, I think this project has potential in embedded applications.

## Contributions
Contributions are welcome but this project isn't polished enough and I might decide to change the entire design- Please voice your idea in an issue first.
