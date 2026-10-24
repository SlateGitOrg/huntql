# huntql — one command gates everything: `make check`.
CARGO ?= cargo
BIN := $(or $(CARGO_TARGET_DIR),target)/release/huntql
COVERAGE_MIN ?= 85

.PHONY: check fmt-check lint test coverage build demo eval bench fixtures golden loc clean

check: fmt-check lint test coverage

fmt-check:
	$(CARGO) fmt --all -- --check

lint:
	$(CARGO) clippy --all-targets --locked -- -D warnings

test:
	$(CARGO) test --locked

# Line coverage over the whole crate (unit + integration + CLI tests).
coverage:
	$(CARGO) llvm-cov --locked --summary-only --fail-under-lines $(COVERAGE_MIN)

build:
	$(CARGO) build --release --locked

demo: build
	@echo "## huntql demo — synthetic Zeek logs in fixtures/demo (see fixtures/demo/truth.json)"
	@echo
	@echo '$$ huntql explain "conn | where dport == 443 | stats count() by src | sort -count | head 10"'
	@$(BIN) -d fixtures/demo explain "conn | where dport == 443 | stats count() by src | sort -count | head 10"
	@echo
	@echo '$$ huntql run examples/hunt.hql --stats'
	@$(BIN) -d fixtures/demo run examples/hunt.hql --stats
	@echo
	@echo '$$ huntql query "conn | where duration > 30"   # a type error, rendered with its span'
	@$(BIN) -d fixtures/demo query "conn | where duration > 30" || true

eval: build
	$(BIN) eval

bench: build
	./scripts/bench.sh

# Regenerate the committed fixtures (byte-identical for the same version).
fixtures: build
	$(BIN) gen --out fixtures/demo --seed 7 --hours 12 --hosts 25 --beacons 6
	$(BIN) gen --out fixtures/json --seed 11 --hours 3 --hosts 6 --beacons 2 --log-format json

golden:
	UPDATE_GOLDEN=1 $(CARGO) test --test golden

# Line counts quoted in the README.
loc:
	@printf 'source lines (src/, excluding blank lines, // comments and #[cfg(test)] modules): '
	@for f in $$(find src -name '*.rs'); do awk '/^#\[cfg\(test\)\]/{exit} {print}' $$f; done | grep -v '^[[:space:]]*$$' | grep -v '^[[:space:]]*//' | wc -l | tr -d ' '
	@printf 'integration/property/golden test code (tests/*.rs): '
	@cat tests/*.rs | wc -l | tr -d ' '

clean:
	$(CARGO) clean
