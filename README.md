# Pinocchio Stake

A Pinocchio implementation of the Solana staking program, providing a type-safe and developer-friendly interface for Solana stake operations.

## Overview

This project is a Pinocchio version of the [official Solana stake program](https://github.com/solana-program/stake), designed to leverage Pinocchio's enhanced development experience while maintaining full compatibility with Solana's staking functionality.

## Features

- Wire-compatible instruction set with the native Stake program
- Clear separation of instruction handlers and state
- Host-friendly dev builds (`std` + `no-entrypoint`); SBF builds with real entrypoint
- End-to-end tests using Solana ProgramTest, including stake lifecycle matrices
- Seed-based authorization support (checked and non-checked variants)

## Repository Layout

- `program/src/entrypoint.rs` — instruction dispatch and minimal payload parsing
- `program/src/instruction/*` — instruction handlers (initialize, authorize, delegate, split, merge, withdraw, move*, etc.)
- `program/src/state/*` — program-local representations of stake state, history, vote state, etc.
- `program/src/helpers/*` — utilities for signer collection, state IO, and shared logic
- `program/tests/*` — ProgramTest suites and adapters

## Build

Host/dev build (default features):

```
cd program
cargo build
```

SBF build (shared object to load in ProgramTest):

```
cargo-build-sbf --no-default-features --features sbf --manifest-path program/Cargo.toml
ls program/target/deploy
```

You should see `pinocchio_stake.so` under `program/target/deploy`.

## Test

Run the full end-to-end test suite (ProgramTest):

```
cd program
cargo test --features e2e -- --nocapture
```

Run a focused ProgramTest:

```
# Checked instruction suite
cargo test --test program_test --features e2e program_test_stake_checked_instructions -- --nocapture

# Split matrix (stake lifecycle)
cargo test --test program_test --features e2e program_test_split:: -- --nocapture
```

Seed-gated tests:

```
cargo test --test authorize_with_seed --features seed -- --nocapture
```

Smoke tests and small unit-style tests:

```
cargo test --test smoke -- --nocapture
cargo test --test split -- --nocapture
```

Helpful flags:

```
RUST_LOG=solana_runtime::message_processor=debug cargo test --features e2e -- --nocapture
RUST_BACKTRACE=1 cargo test --features e2e -- --nocapture
```
## Run Benchmarks

cargo test --test bench --features e2e -- --ignored --nocapture

## Development Notes

- Default features configure `std` and `no-entrypoint` for ergonomic development and testing.
- The `sbf` feature switches to the chain entrypoint; use `cargo-build-sbf` to produce the `.so`.
- ProgramTest in this repo is configured to prefer BPF and loads the `.so` under the canonical Stake program ID. Ensure `program/target/deploy/pinocchio_stake.so` exists before running ProgramTest.
- Tests use an adapter (`tests/common/pin_adapter.rs`) to translate Solana SDK instructions into the program’s account order and wire format.

## License

Proprietary or as per repository policy.

