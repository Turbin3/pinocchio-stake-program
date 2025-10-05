SHELL := /bin/bash

.PHONY: bench-csv bench-diff pt-pin pt-native dump-instructions

bench-csv:
	@mkdir -p benchmarks
	@echo "Running CU bench (this takes a moment)..."
	@cargo test bench_pinocchio_vs_native -- --ignored --nocapture \
		| grep -E '^(name,pin,native)|^[a-z_]+,[0-9]+,[0-9]+$$' \
		> benchmarks/current.csv
	@echo "Wrote benchmarks/current.csv"

bench-diff:
	@python3 scripts/bench_diff.py benchmarks/current.csv $(BASE) || true
	@echo "Use: make bench-diff BASE=benchmarks/prev.csv"

# Developer convenience: run ProgramTest benches locally (not CI)
pt-pin:
	@echo "Building SBF artifact and running Pinocchio ProgramTest..."
	@cargo-build-sbf --no-default-features --features sbf --manifest-path Cargo.toml
	@cargo test --features e2e --test program_test -- --nocapture

pt-native:
	@echo "Running native parity snapshot bench (ignored by default)..."
	@cargo test --features e2e --test native_parity -- --ignored --nocapture

dump-instructions:
	@bash scripts/dump_instructions.sh
