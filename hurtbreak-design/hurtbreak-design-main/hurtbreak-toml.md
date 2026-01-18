# Abstract
`hurtbreak-toml` is the module for compile-time creation of [[Fuzzable]], [[Tripwire]] from a unified data spec.
# `spec.toml` format
## File Structure
```toml
version = 1

[structs.<Name>]      # Fuzzable payloads
[responses.<Name>]    # Response datagrams (same syntax as structs)
[tripwires.<Name>]    # Attack flow definitions
```
## Structs / Responses
```toml
[structs.PacketName]
size = <bytes>                    # Required if using offsets
endian = "big" | "little" | "native"  # Default: native

fields = [
    { id = <u16>, name = "<str>", type = "<type>", <...attrs> },
]
```
### Field Types
| Type | Offset Format | Attributes |
|------|---------------|------------|
| `u8`, `u16`, `u32`, `u64` | `offset = N` | `endian`, `range`, `values`, `skip`, `pass`, `compute` |
| `i8`, `i16`, `i32`, `i64` | `offset = N` | same |
| `bytes` | `offset = N, len = M` | `max_len`, `skip` |
| `raw` | `offset = [start, end)` | `mutate = "random" \| "bitflip"`, `skip` |
| `bits` | `offset = [byte, bit, width]` | `range`, `values`, `skip` |
| `bit` | `offset = [byte, bit]` | `skip` |
| `string` | `offset = N, len = M` | `values`, `skip` |
### Field Attributes
```toml
# Mutation
range = [min, max]
values = [0x01, 0x02, 0x03]       # or ["GET", "POST"]
pattern = "u8.u8.u8.u8"
delimiter = "."
mutate = "random" | "bitflip"
skip = true

# Ordering
pass = <u8>                       # Higher = later (default: 1)

# Computed fields
compute = { algo = "<algo>", over = [<refs>] }

# Endianness override
endian = "big" | "little"
```
### Compute Reference Types
```toml
over = [
    { field = <id> },             # Field by ID
    { bytes = [start, end) },     # Byte range
]
```
### Algorithms
`crc8`, `crc16`, `crc16-ccitt`, `crc32`, `crc32c`, `sum8`, `sum16`, `xor8`, `md5`, `sha1`, `sha256`
## Tripwires
```toml
[tripwires.AttackName]
input = "StructName"              # Fuzzable to send
output = "ResponseName"           # Response to match

[[tripwires.AttackName.steps]]
id = <u8>
match = [<conditions>]            # All must match (AND)
mutate = [<field_ids>]            # Fields to mutate this step
on_match = { advance = <step_id> } | { goal = "<goal_id>" }
on_fail = { stay = true } | { advance = <step_id> }

[[tripwires.AttackName.goals]]
id = "<str>"
on_timeout = true                 # Optional: timeout triggers goal
```
### Match Conditions
```toml
match = [
    { field = <id>, eq = <value> },
    { field = <id>, neq = <value> },
    { field = <id>, range = [min, max] },
    { field = <id>, one_of = [v1, v2, v3] },
    { field = <id>, any = true },         # Any value matches
]
```
### Branch Actions
```toml
on_match = { advance = 2 }        # Go to step 2
on_match = { goal = "success" }   # Reach goal
on_match = { branch = [          # Conditional branching
    { if = [{ field = 1, eq = 0x00 }], then = { advance = 2 } },
    { if = [{ field = 1, eq = 0xFF }], then = { goal = "error" } },
    { else = { stay = true } }
]}
on_fail = { stay = true }         # Retry current step
```
## Complete Example
```toml
version = 1

[structs.Request]
size = 16
endian = "big"
fields = [
    { id = 1, name = "magic", type = "u16", offset = 0, values = [0xCAFE], skip = true },
    { id = 2, name = "cmd", type = "u8", offset = 2, range = [0, 255] },
    { id = 3, name = "seq", type = "u8", offset = 3, range = [0, 255] },
    { id = 4, name = "payload", type = "raw", offset = [4, 14], mutate = "random" },
    { id = 5, name = "crc", type = "u16", offset = 14, pass = 2, compute = { algo = "crc16", over = [{ bytes = [0, 14] }] } },
]

[responses.Response]
size = 8
endian = "big"
fields = [
    { id = 1, name = "status", type = "u8", offset = 0 },
    { id = 2, name = "seq", type = "u8", offset = 1 },
    { id = 3, name = "data", type = "raw", offset = [2, 8] },
]

[tripwires.Handshake]
input = "Request"
output = "Response"

[[tripwires.Handshake.steps]]
id = 1
match = [{ field = 1, eq = 0x00 }]
mutate = [2, 4]
on_match = { advance = 2 }
on_fail = { stay = true }

[[tripwires.Handshake.steps]]
id = 2
match = [{ field = 1, eq = 0x01 }, { field = 2, range = [0, 10] }]
mutate = [4]
on_match = { goal = "success" }
on_fail = { branch = [
    { if = [{ field = 1, eq = 0xFF }], then = { goal = "error_state" } },
    { else = { stay = true } }
]}

[[tripwires.Handshake.goals]]
id = "success"

[[tripwires.Handshake.goals]]
id = "crash"
on_timeout = true

[[tripwires.Handshake.goals]]
id = "error_state"
```
## Validation Rules
1. All `id` values unique within struct
2. Offsets must not overlap
3. Offsets must cover entire `size` (no gaps)
4. `compute.over` field refs must exist and have lower `pass`
5. `input`/`output` must reference defined structs/responses
6. Step `id` values unique within tripwire
7. All `advance` targets must reference existing step IDs
8. All `goal` targets must reference existing goal IDs