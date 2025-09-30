SHELL := /bin/bash

.PHONY: bench-csv bench-diff

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

