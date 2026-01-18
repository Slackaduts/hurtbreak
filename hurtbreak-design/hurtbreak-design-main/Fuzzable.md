# Abstract
`Fuzzable` is the trait that users implement to describe how a given datagram is mutated. with syntax specified by [[hurtbreak-derive]].
# Goals
- Output C header files so the mutation itself can be built into embedded logic on anything
- Ingest a spec file so python/C callers can define their own Fuzzable impls