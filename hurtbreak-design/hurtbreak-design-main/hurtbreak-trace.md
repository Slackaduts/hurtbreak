# hurtbreak-trace

Minimal binary trace format for recording fuzzing sessions.

## Overview

`.hurt` files store mutation and response data from protocol fuzzing runs. The format prioritizes:

- **Reproducibility** — Seeds and mutations enable deterministic replay
- **Minimal size** — Only stores what can't be derived
- **Integrity** — Per-record CRC8 for corruption detection
- **Portability** — Simple format, little-endian, no alignment requirements

## File Structure

```
┌─────────────────────────────────────┐
│            HEADER (15 bytes)        │
├─────────────────────────────────────┤
│            RECORD 0                 │
├─────────────────────────────────────┤
│            RECORD 1                 │
├─────────────────────────────────────┤
│              ...                    │
└─────────────────────────────────────┘
```

## Header

Fixed size: **15 bytes**

|Offset|Size|Field|Description|
|---|---|---|---|
|0x00|4|magic|`"HURT"` (0x48 0x55 0x52 0x54)|
|0x04|1|version|Format version (0x02)|
|0x05|1|flags|Bit flags|
|0x06|1|endian|Always 0x00 (little-endian)|
|0x07|8|start_time|Session start (unix milliseconds, u64 LE)|

### Flags

|Bit|Name|Description|
|---|---|---|
|0|trimmed|Only mutated field values stored|
|1|responses_included|Full response bytes in StateTransition/Goal records|
|2-7|reserved|Must be zero|

## Record Format

All records use Type-Length-Value with trailing CRC:

```
┌────────┬────────────────┬─────────────────┬────────┐
│ 1 byte │ 1-10 bytes     │ variable        │ 1 byte │
│ type   │ length (varint)│ payload         │ CRC8   │
└────────┴────────────────┴─────────────────┴────────┘
```

- **type** — Record type (see below)
- **length** — Payload length as unsigned LEB128 varint
- **payload** — Type-specific data
- **CRC8** — CRC-8/SMBUS over `[type | length bytes | payload]`

## Record Types

|Code|Name|Description|
|---|---|---|
|0x01|SessionStart|Session metadata, must be first record|
|0x02|Mutation|Field mutations for one iteration|
|0x03|ResponseFingerprint|Response characteristics (19 bytes fixed)|
|0x04|Novel|Marker indicating previous mutation was novel|
|0x05|StateTransition|Protocol state advanced, includes full response|
|0x06|Goal|Goal reached, includes full response|
|0x07|Timeout|Transport timeout occurred|
|0x08|Marker|User-defined annotation|

### 0x01 — SessionStart

|Field|Type|Description|
|---|---|---|
|initial_seed|u64 LE|RNG seed for session|
|spec_hash|u64 LE|Hash of spec (for replay validation)|
|spec_name_len|varint|Length of spec name|
|spec_name|UTF-8|Spec identifier|

### 0x02 — Mutation

|Field|Type|Description|
|---|---|---|
|rng_state|u64 LE|RNG state before mutation|
|field_count|u8|Number of fields mutated (max 255)|
|fields|repeated|See below|

Each field entry:

|Field|Type|Description|
|---|---|---|
|field_id|u16 LE|Field ID from spec|
|value_len|varint|Length of value|
|value|bytes|Mutated value|

### 0x03 — ResponseFingerprint

Fixed size: **19 bytes**

|Field|Type|Description|
|---|---|---|
|struct_hash|u64 LE|Structural hash of response|
|timing|u8|Quantized latency bucket (0-255)|
|length|u16 LE|Response length in bytes|
|prefix|[u8; 4]|First 4 bytes of response|
|suffix|[u8; 4]|Last 4 bytes of response|

### 0x04 — Novel

**Empty payload** (0 bytes)

Presence indicates the previous mutation/response pair was novel.

### 0x05 — StateTransition

|Field|Type|Description|
|---|---|---|
|from_state|u8|Previous state ID|
|to_state|u8|New state ID|
|goal_hint|varint|Distance to goal (0 = at goal)|
|response_len|varint|Length of response|
|response|bytes|Full response datagram|

### 0x06 — Goal

|Field|Type|Description|
|---|---|---|
|goal_id_len|varint|Length of goal ID|
|goal_id|UTF-8|Goal name (e.g., "crash", "auth_bypass")|
|response_len|varint|Length of response|
|response|bytes|Full response datagram|

### 0x07 — Timeout

Fixed size: **4 bytes**

|Field|Type|Description|
|---|---|---|
|elapsed_ms|u32 LE|Time waited before timeout|

### 0x08 — Marker

|Field|Type|Description|
|---|---|---|
|tag_len|varint|Length of tag|
|tag|UTF-8|User-defined annotation|

## Varint Encoding

Unsigned LEB128:

```
Value 0-127:      1 byte   [0xxxxxxx]
Value 128-16383:  2 bytes  [1xxxxxxx] [0xxxxxxx]
...
```

## CRC-8/SMBUS

Polynomial: `x⁸ + x² + x + 1` (0x07), init: 0x00

## Constraints

|Constraint|Limit|
|---|---|
|Max fields per mutation|255|
|Max field ID|65535|
|Max states|255|
|Varint max|~2^63 (practical: keep payloads under 64KB)|

## File Extension

`.hurt` — **H**urtbreak **U**nified **R**eproducible **T**race