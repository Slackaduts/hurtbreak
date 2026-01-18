# Abstract
`hurtbreak-c` is the C code/module generator, compiling relevant [[hurtbreak]] mutation and tracing methods on embedded targets.

# Goals
- Rust `build.rs` should give us `.h` C header files
	- This will allow us to both use Rust and optionally use our build processes to run [[hurtbreak]] on obscure targets where it wouldn't normally run
	- User would just import the generated functions and implement their own fuzzer using our methods
# Dependencies

| Crate | Purpose |
|-------|---------|
| `hurtbreak-toml` | Parse spec.toml into IR |
| `hurtbreak-core` | Trait definitions, algorithm constants |

# Module Structure
```
hurtbreak-c/
├── Cargo.toml
├── src/
│   └── lib.rs              # Codegen logic
├── runtime/                # Shipped C11 runtime (user copies to project)
│   ├── hurtbreak_rt.h      # Runtime declarations
│   ├── prng.c              # PRNG implementation
│   ├── crc.c               # CRC implementations
│   └── hash.c              # Hash implementations (optional, larger)
└── README.md
```
# Public API
## Functions
### `generate_c`
Generates C header and source files from a parsed spec.
```rust
pub fn generate_c(spec: &SpecFile, config: &CodegenConfig) -> Result<GeneratedOutput, CodegenError>;
```
**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `spec` | `&SpecFile` | Parsed IR from `hurtbreak-toml` |
| `config` | `&CodegenConfig` | Output configuration |
**Returns:** `Result<GeneratedOutput, CodegenError>`
### `write_files`
Writes generated output to filesystem.
```rust
pub fn write_files(output: &GeneratedOutput, dir: &Path) -> Result<(), std::io::Error>;
```
---
## Types
### `CodegenConfig`
```rust
pub struct CodegenConfig {
    /// Prefix for all generated symbols (default: "hb_")
    pub symbol_prefix: String,
    
    /// Generate tripwire state machine code
    pub include_tripwire: bool,
    
    /// Include hash algorithms (increases code size)
    pub include_hash: bool,
    
    /// Target C standard (C99 or C11)
    pub c_standard: CStandard,
    
    /// Generate static assertions for struct sizes
    pub emit_static_asserts: bool,
}

pub enum CStandard {
    C99,
    C11,  // default
}
```
### `GeneratedOutput`
```rust
pub struct GeneratedOutput {
    /// spec.h contents
    pub header: String,
    
    /// spec.c contents
    pub source: String,
    
    /// tripwire.h contents (if include_tripwire)
    pub tripwire_header: Option<String>,
    
    /// tripwire.c contents (if include_tripwire)
    pub tripwire_source: Option<String>,
}
```
### `CodegenError`
```rust
pub enum CodegenError {
    /// Field type not supported in C codegen
    UnsupportedType { field_id: u16, type_name: String },
    
    /// Compute algorithm not implemented
    UnsupportedAlgorithm { name: String },
    
    /// Struct size exceeds limit
    StructTooLarge { name: String, size: usize },
    
    /// Offset validation failed
    InvalidOffset { field_id: u16, reason: String },
}
```

---

# Generated C API

## Header: `spec.h`

### Struct Definitions

For each `[structs.*]` and `[responses.*]` in spec.toml:
```c
#ifndef HURTBREAK_SPEC_H
#define HURTBREAK_SPEC_H

#include <stdint.h>
#include "hurtbreak_rt.h"

/* Struct: NetworkPacket (size: 256 bytes) */
typedef struct __attribute__((packed)) {
    uint16_t port;          /* id = 1, offset = 0 */
    uint32_t addr;          /* id = 2, offset = 2 */
    uint8_t payload[248];   /* id = 3, offset = 6, raw */
    uint16_t checksum;      /* id = 4, offset = 254, computed */
} NetworkPacket;

/* Field ID constants */
#define NETWORKPACKET_FIELD_PORT      1
#define NETWORKPACKET_FIELD_ADDR      2
#define NETWORKPACKET_FIELD_PAYLOAD   3
#define NETWORKPACKET_FIELD_CHECKSUM  4

/* Static size validation (C11) */
#if __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(NetworkPacket) == 256, "NetworkPacket size mismatch");
#endif

#endif /* HURTBREAK_SPEC_H */
```

### Function Declarations
```c
/*
 * Mutate all fields in pass order.
 * Automatically calls compute functions after mutation passes.
 */
void hb_mutate_NetworkPacket(NetworkPacket* pkt, uint64_t* seed);

/*
 * Mutate a single field by ID.
 * Does NOT trigger computed fields - call hb_compute_* manually if needed.
 */
void hb_mutate_NetworkPacket_field(NetworkPacket* pkt, uint16_t field_id, uint64_t* seed);

/*
 * Compute field 4 (checksum) from its dependencies.
 */
void hb_compute_NetworkPacket_checksum(NetworkPacket* pkt);

/*
 * Serialize struct to byte buffer.
 * Returns number of bytes written.
 */
size_t hb_serialize_NetworkPacket(const NetworkPacket* pkt, uint8_t* buf, size_t buf_len);

/*
 * Deserialize byte buffer to struct.
 * Returns 0 on success, -1 on error.
 */
int hb_deserialize_NetworkPacket(NetworkPacket* pkt, const uint8_t* buf, size_t buf_len);

/*
 * Get field value by ID.
 * Writes to out_buf, returns byte length of field, or -1 if invalid ID.
 */
int hb_get_field_NetworkPacket(const NetworkPacket* pkt, uint16_t field_id, uint8_t* out_buf, size_t buf_len);

/*
 * Set field value by ID.
 * Returns 0 on success, -1 on error.
 */
int hb_set_field_NetworkPacket(NetworkPacket* pkt, uint16_t field_id, const uint8_t* value, size_t value_len);
```
---
## Source: `spec.c`
### Mutation Implementations
```c
#include "spec.h"

void hb_mutate_NetworkPacket(NetworkPacket* pkt, uint64_t* seed) {
    /* Pass 1: regular fields */
    hb_mutate_NetworkPacket_field(pkt, NETWORKPACKET_FIELD_PORT, seed);
    hb_mutate_NetworkPacket_field(pkt, NETWORKPACKET_FIELD_ADDR, seed);
    hb_mutate_NetworkPacket_field(pkt, NETWORKPACKET_FIELD_PAYLOAD, seed);
    
    /* Pass 2: computed fields */
    hb_compute_NetworkPacket_checksum(pkt);
}

void hb_mutate_NetworkPacket_field(NetworkPacket* pkt, uint16_t field_id, uint64_t* seed) {
    switch (field_id) {
        case NETWORKPACKET_FIELD_PORT:
            /* range = [1, 65535] */
            pkt->port = (uint16_t)hb_rand_range(seed, 1, 65535);
            break;
            
        case NETWORKPACKET_FIELD_ADDR:
            /* pattern = u8.u8.u8.u8 packed */
            pkt->addr = ((uint32_t)hb_rand_u8(seed) << 24)
                      | ((uint32_t)hb_rand_u8(seed) << 16)
                      | ((uint32_t)hb_rand_u8(seed) << 8)
                      | ((uint32_t)hb_rand_u8(seed));
            break;
            
        case NETWORKPACKET_FIELD_PAYLOAD:
            /* raw, mutate = "random" */
            for (size_t i = 0; i < 248; i++) {
                pkt->payload[i] = hb_rand_u8(seed);
            }
            break;
            
        case NETWORKPACKET_FIELD_CHECKSUM:
            /* computed field - no direct mutation */
            break;
            
        default:
            break;
    }
}

void hb_compute_NetworkPacket_checksum(NetworkPacket* pkt) {
    /* algo = "crc16", over = [{ bytes = [0, 254] }] */
    pkt->checksum = hb_crc16((const uint8_t*)pkt, 254);
}
```
### Serialization
```c
size_t hb_serialize_NetworkPacket(const NetworkPacket* pkt, uint8_t* buf, size_t buf_len) {
    if (buf_len < sizeof(NetworkPacket)) {
        return 0;
    }
    memcpy(buf, pkt, sizeof(NetworkPacket));
    return sizeof(NetworkPacket);
}

int hb_deserialize_NetworkPacket(NetworkPacket* pkt, const uint8_t* buf, size_t buf_len) {
    if (buf_len < sizeof(NetworkPacket)) {
        return -1;
    }
    memcpy(pkt, buf, sizeof(NetworkPacket));
    return 0;
}
```
---
## Header: `tripwire.h`
Generated if `include_tripwire = true` and `[tripwires.*]` present in spec.
```c
#ifndef HURTBREAK_TRIPWIRE_H
#define HURTBREAK_TRIPWIRE_H

#include "spec.h"

/* Step result codes */
typedef enum {
    HB_STEP_STAY,       /* Retry current step */
    HB_STEP_ADVANCE,    /* Move to next step */
    HB_STEP_GOAL,       /* Goal reached */
    HB_STEP_TIMEOUT,    /* No response (may be goal) */
} hb_step_result_t;

/* Tripwire state */
typedef struct {
    uint8_t current_step;
    uint8_t goal_reached;       /* 0 = none, >0 = goal ID */
    uint64_t seed;
} hb_tripwire_Handshake_t;

/*
 * Initialize tripwire state.
 */
void hb_tripwire_Handshake_init(hb_tripwire_Handshake_t* tw, uint64_t initial_seed);

/*
 * Evaluate response and determine next action.
 */
hb_step_result_t hb_tripwire_Handshake_evaluate(
    hb_tripwire_Handshake_t* tw,
    const ResponsePacket* resp
);

/*
 * Get mutation spec for current step.
 * Writes field IDs to mutate into out_fields.
 * Returns count of fields.
 */
size_t hb_tripwire_Handshake_get_mutate_fields(
    const hb_tripwire_Handshake_t* tw,
    uint16_t* out_fields,
    size_t max_fields
);

/*
 * Prepare next request datagram.
 * Mutates only fields relevant to current step.
 */
void hb_tripwire_Handshake_prepare(
    hb_tripwire_Handshake_t* tw,
    RequestPacket* req
);

/*
 * Handle timeout (no response).
 * Returns HB_STEP_GOAL if timeout is a goal condition, else HB_STEP_STAY.
 */
hb_step_result_t hb_tripwire_Handshake_timeout(hb_tripwire_Handshake_t* tw);

/*
 * Reset tripwire to initial state.
 */
void hb_tripwire_Handshake_reset(hb_tripwire_Handshake_t* tw);

/*
 * Get current step ID.
 */
uint8_t hb_tripwire_Handshake_current_step(const hb_tripwire_Handshake_t* tw);

/*
 * Get goal ID if reached, 0 otherwise.
 */
uint8_t hb_tripwire_Handshake_goal(const hb_tripwire_Handshake_t* tw);

#endif /* HURTBREAK_TRIPWIRE_H */
```
---
## Source: `tripwire.c`
```c
#include "tripwire.h"

void hb_tripwire_Handshake_init(hb_tripwire_Handshake_t* tw, uint64_t initial_seed) {
    tw->current_step = 1;
    tw->goal_reached = 0;
    tw->seed = initial_seed;
}

hb_step_result_t hb_tripwire_Handshake_evaluate(
    hb_tripwire_Handshake_t* tw,
    const ResponsePacket* resp
) {
    switch (tw->current_step) {
        case 1:
            /* match = [{ field = 1, eq = 0x00 }] */
            if (resp->status == 0x00) {
                tw->current_step = 2;
                return HB_STEP_ADVANCE;
            }
            return HB_STEP_STAY;
            
        case 2:
            /* match = [{ field = 1, eq = 0x01 }] */
            if (resp->status == 0x01) {
                tw->goal_reached = 1;  /* goal = "success" */
                return HB_STEP_GOAL;
            }
            return HB_STEP_STAY;
            
        default:
            return HB_STEP_STAY;
    }
}

size_t hb_tripwire_Handshake_get_mutate_fields(
    const hb_tripwire_Handshake_t* tw,
    uint16_t* out_fields,
    size_t max_fields
) {
    switch (tw->current_step) {
        case 1:
            /* mutate = [2, 3] */
            if (max_fields >= 2) {
                out_fields[0] = 2;
                out_fields[1] = 3;
                return 2;
            }
            break;
        case 2:
            /* no specific fields */
            return 0;
    }
    return 0;
}

void hb_tripwire_Handshake_prepare(
    hb_tripwire_Handshake_t* tw,
    RequestPacket* req
) {
    uint16_t fields[16];
    size_t count = hb_tripwire_Handshake_get_mutate_fields(tw, fields, 16);
    
    for (size_t i = 0; i < count; i++) {
        hb_mutate_RequestPacket_field(req, fields[i], &tw->seed);
    }
    
    /* Run computed fields */
    hb_compute_RequestPacket_checksum(req);
}

hb_step_result_t hb_tripwire_Handshake_timeout(hb_tripwire_Handshake_t* tw) {
    /* Check if timeout is goal for current step */
    /* goal "crash" has on_timeout = true */
    tw->goal_reached = 2;  /* crash goal ID */
    return HB_STEP_GOAL;
}

void hb_tripwire_Handshake_reset(hb_tripwire_Handshake_t* tw) {
    tw->current_step = 1;
    tw->goal_reached = 0;
    /* Note: does not reset seed - call init() for full reset */
}

uint8_t hb_tripwire_Handshake_current_step(const hb_tripwire_Handshake_t* tw) {
    return tw->current_step;
}

uint8_t hb_tripwire_Handshake_goal(const hb_tripwire_Handshake_t* tw) {
    return tw->goal_reached;
}
```
---
# C Runtime API
## Header: `hurtbreak_rt.h`
```c
#ifndef HURTBREAK_RT_H
#define HURTBREAK_RT_H

#include <stdint.h>
#include <stddef.h>

/*
 * PRNG - xorshift64
 */
uint64_t hb_rand_next(uint64_t* seed);
uint8_t hb_rand_u8(uint64_t* seed);
uint16_t hb_rand_u16(uint64_t* seed);
uint32_t hb_rand_u32(uint64_t* seed);
uint64_t hb_rand_u64(uint64_t* seed);
uint64_t hb_rand_range(uint64_t* seed, uint64_t min, uint64_t max);

/*
 * CRC algorithms
 */
uint8_t hb_crc8(const uint8_t* data, size_t len);
uint16_t hb_crc16(const uint8_t* data, size_t len);
uint16_t hb_crc16_ccitt(const uint8_t* data, size_t len);
uint32_t hb_crc32(const uint8_t* data, size_t len);
uint32_t hb_crc32c(const uint8_t* data, size_t len);

/*
 * Simple checksums
 */
uint8_t hb_sum8(const uint8_t* data, size_t len);
uint16_t hb_sum16(const uint8_t* data, size_t len);
uint8_t hb_xor8(const uint8_t* data, size_t len);

/*
 * Hash algorithms (optional, compile with -DHB_INCLUDE_HASH)
 */
#ifdef HB_INCLUDE_HASH
void hb_md5(const uint8_t* data, size_t len, uint8_t out[16]);
void hb_sha1(const uint8_t* data, size_t len, uint8_t out[20]);
void hb_sha256(const uint8_t* data, size_t len, uint8_t out[32]);
#endif

/*
 * C standard compatibility
 */
#if __STDC_VERSION__ >= 201112L
    #define HB_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#else
    #define HB_STATIC_ASSERT(cond, msg)
#endif

#endif /* HURTBREAK_RT_H */
```
---
# Codegen Rules
## Type Mapping

| Spec Type | C Type | Size |
|-----------|--------|------|
| `u8` | `uint8_t` | 1 |
| `u16` | `uint16_t` | 2 |
| `u32` | `uint32_t` | 4 |
| `u64` | `uint64_t` | 8 |
| `i8` | `int8_t` | 1 |
| `i16` | `int16_t` | 2 |
| `i32` | `int32_t` | 4 |
| `i64` | `int64_t` | 8 |
| `bytes` | `uint8_t[]` | explicit |
| `raw` | `uint8_t[]` | from offset range |
| `string` | `char[]` | explicit max_len |
## Mutation Strategy Mapping

| Spec | Generated C |
|------|-------------|
| `range = [min, max]` | `hb_rand_range(seed, min, max)` |
| `values = [...]` | Switch on `hb_rand_range(seed, 0, count-1)` |
| `pattern = "u8.u8.u8.u8"` | Packed byte generation |
| `mutate = "random"` | Loop with `hb_rand_u8(seed)` |
| `mutate = "bitflip"` | XOR with random mask |
| `skip = true` | No mutation function body |
## Compute Algorithm Mapping

| Spec | Generated C |
|------|-------------|
| `algo = "crc8"` | `hb_crc8(buf, len)` |
| `algo = "crc16"` | `hb_crc16(buf, len)` |
| `algo = "crc16-ccitt"` | `hb_crc16_ccitt(buf, len)` |
| `algo = "crc32"` | `hb_crc32(buf, len)` |
| `algo = "crc32c"` | `hb_crc32c(buf, len)` |
| `algo = "sum8"` | `hb_sum8(buf, len)` |
| `algo = "sum16"` | `hb_sum16(buf, len)` |
| `algo = "xor8"` | `hb_xor8(buf, len)` |
| `algo = "md5"` | `hb_md5(buf, len, out)` |
| `algo = "sha256"` | `hb_sha256(buf, len, out)` |
## Over Reference Resolution
For `compute.over` entries:

| Reference | Generated Buffer Construction |
|-----------|------------------------------|
| `{ field = N }` | Copy field bytes in declaration order |
| `{ bytes = [start, end) }` | Direct pointer + length |
| Mixed | Allocate temp buffer, copy fields, then byte ranges, in order |

---
# Integration: build.rs Usage
```rust
// build.rs
use hurtbreak_c::{generate_c, write_files, CodegenConfig, CStandard};
use hurtbreak_toml::parse_spec_file;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=spec.toml");
    
    let spec = parse_spec_file("spec.toml").expect("Failed to parse spec");
    
    let config = CodegenConfig {
        symbol_prefix: "hb_".to_string(),
        include_tripwire: true,
        include_hash: false,
        c_standard: CStandard::C11,
        emit_static_asserts: true,
    };
    
    let output = generate_c(&spec, &config).expect("Codegen failed");
    
    write_files(&output, Path::new("generated/")).expect("Failed to write files");
}
```
---
# CLI Usage
The `hurtbreak-cli` exposes codegen:
```bash
# Generate C files from spec
hurtbreak codegen --target c --spec spec.toml --out ./generated/

# With options
hurtbreak codegen --target c \
    --spec spec.toml \
    --out ./generated/ \
    --prefix "myfuzz_" \
    --no-tripwire \
    --include-hash \
```

---
# Embedded User Example
Complete example of using generated code on embedded target:
```c
/* main.c - User's embedded firmware */
#include "generated/spec.h"
#include "generated/tripwire.h"
#include "hurtbreak_rt/hurtbreak_rt.h"

/* User implements these */
extern int transport_send(const uint8_t* buf, size_t len);
extern int transport_recv(uint8_t* buf, size_t max_len, uint32_t timeout_ms);
extern void log_seed(uint64_t seed);
extern void log_goal(uint8_t goal_id);

int main(void) {
    RequestPacket req = {0};
    ResponsePacket resp;
    hb_tripwire_Handshake_t tripwire;
    
    /* Initialize with seed (could come from hardware RNG) */
    hb_tripwire_Handshake_init(&tripwire, 0xDEADBEEF12345678ULL);
    
    while (1) {
        /* Prepare request based on current tripwire step */
        hb_tripwire_Handshake_prepare(&tripwire, &req);
        
        /* Serialize and send */
        uint8_t tx_buf[256];
        size_t tx_len = hb_serialize_RequestPacket(&req, tx_buf, sizeof(tx_buf));
        transport_send(tx_buf, tx_len);
        
        /* Receive response */
        uint8_t rx_buf[64];
        int rx_len = transport_recv(rx_buf, sizeof(rx_buf), 1000);
        
        hb_step_result_t result;
        
        if (rx_len <= 0) {
            /* Timeout */
            result = hb_tripwire_Handshake_timeout(&tripwire);
        } else {
            /* Deserialize and evaluate */
            hb_deserialize_ResponsePacket(&resp, rx_buf, rx_len);
            result = hb_tripwire_Handshake_evaluate(&tripwire, &resp);
        }
        
        /* Check result */
        switch (result) {
            case HB_STEP_STAY:
                /* Retry */
                break;
                
            case HB_STEP_ADVANCE:
                /* Moved to next step */
                log_seed(tripwire.seed);
                break;
                
            case HB_STEP_GOAL:
                /* Success! */
                log_goal(hb_tripwire_Handshake_goal(&tripwire));
                log_seed(tripwire.seed);
                return 0;
                
            case HB_STEP_TIMEOUT:
                /* Handled above */
                break;
        }
    }
}
```
---
# Constraints

| Constraint | Limit | Rationale |
|------------|-------|-----------|
| Max struct size | 65535 bytes | `uint16_t` length fields |
| Max fields per struct | 255 | `uint8_t` field count in trace |
| Max tripwire steps | 255 | `uint8_t` step index |
| Max goals per tripwire | 255 | `uint8_t` goal ID |
| Symbol name length | 63 chars | C standard identifier limit |

---
# Error Handling
Codegen fails with descriptive error if:
- Field offsets overlap
- Field offsets leave gaps (unless explicitly marked)
- `size` doesn't match sum of field sizes
- Unknown algorithm in `compute`
- Unsupported type for C target
- Duplicate field IDs
- Circular compute dependencies
- Reserved symbol name collision