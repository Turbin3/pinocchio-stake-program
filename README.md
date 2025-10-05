# Pinocchio Stake

Pinocchio build of Solana’s Stake program with native wire compatibility.

## What’s here

- Native instruction set and data layout
- Host (std) + SBF (no_std)

## Build

Host/dev build:

```
cd program
cargo build
```

SBF build:

```
cargo-build-sbf --no-default-features --features sbf --manifest-path program/Cargo.toml
ls program/target/deploy/pinocchio_stake.so
```

## Test

All tests:

```
cd program
cargo test --features e2e -- --nocapture
```

## ProgramTest (local)

- Build SBF: `cargo-build-sbf --no-default-features --features sbf --manifest-path program/Cargo.toml`
- Pin bench: `make -C program pt-pin`
- Native snapshot: `make -C program pt-native`
## Bench marking

`make -C program bench-csv` then `make -C program bench-diff BASE=program/benchmarks/prev.csv`

## Notes

- ProgramTest prefers BPF and loads `pinocchio_stake.so` under the Stake program ID.
