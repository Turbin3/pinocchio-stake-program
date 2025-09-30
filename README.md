# Pinocchio Stake

This is a Pinocchio build of Solana’s Stake program. It speaks the same wire format as the native Stake program and can be dropped into ProgramTest under the canonical Stake ID.

## What’s here

- Same instruction set and data layout as Solana’s Stake program
- Handlers split out under `program/src/instruction/*`
- No-std on SBF, std on host; no heap in hot paths
- ProgramTest coverage for the usual stake flows

## Build

Host/dev build (default features):

```
cd program
cargo build
```

SBF build (used by ProgramTest):

```
cargo-build-sbf --no-default-features --features sbf --manifest-path program/Cargo.toml
ls program/target/deploy/pinocchio_stake.so
```

## Test

Run everything:

```
cd program
cargo test --features e2e -- --nocapture
```

Run a specific set:

```
cargo test --test program_test --features e2e program_test_split:: -- --nocapture
```

Helpful flags:

```
RUST_LOG=solana_runtime::message_processor=debug cargo test --features e2e -- --nocapture
RUST_BACKTRACE=1 cargo test --features e2e -- --nocapture
```
## Bench marking

cargo test --test bench --features e2e -- --ignored --nocapture

## Notes

- ProgramTest is set to prefer BPF and loads the built `.so` under the Stake program ID. Make sure `program/target/deploy/pinocchio_stake.so` exists before running tests.
- Tests use the native stake instruction builders; no custom client code is required.

## License

See repository policy.
