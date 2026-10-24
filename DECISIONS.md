# Decisions

Rulings made while building huntql without a product owner in the loop.
Format: `- Ruling: <what> — <why> — <cost if wrong>`.

## Language and planner

- Ruling: Hand-written lexer and recursive-descent parser, no parser generator — exact byte spans and tailored messages ("did you forget a `|`?", "use `==`") are the point of the project, and the grammar is small — more code to maintain if the grammar grows a lot.
- Ruling: Stage names (`where`, `stats`, ...) are contextual identifiers; only `and or not in by as true false null` are reserved — every Zeek field name stays usable without quoting — an operator name cannot be used as a log source name.
- Ruling: Strict typing with literal coercion (string literal → addr/time/subnet when compared with one) instead of implicit numeric/duration mixing — `duration > 30` is a classic silent bug (seconds? microseconds?) and a plan-time error with a hint is friendlier — users must type `30s`.
- Ruling: `/` on numbers always yields `float` — integer division surprises analysts computing ratios — `orig_bytes / 1024` is a float, not a truncated int.
- Ruling: Output column names for `fields`/`stats by` are the names as written (`src`, not `id.orig_h`) — tables read the way the query was written — after `fields src`, the name `id.orig_h` no longer resolves (the suggestion engine points at `src`).
- Ruling: `eval` may not overwrite an existing field (error, use `rename`) — avoids silently shadowing a Zeek column — slightly more typing.
- Ruling: `rename` is schema-only (no runtime operator) — zero cost — none.
- Ruling: Unaggregated aggregation names derive from the argument (`avg(duration)` → `avg_duration`); duplicates are a plan error asking for `as` — predictable names usable later in the pipeline — complex expressions need an alias.
- Ruling: `sort | head` is always fused into TopK, with arrival order as the final tie-breaker — O(k) memory and results identical to stable sort + head (property-tested) — none known.
- Ruling: Column pruning stops at the first schema-replacing operator, and pipelines that output the raw source schema decode every column — simple and obviously correct — a `where` + `head` over a raw log still decodes all columns.

## Execution

- Ruling: Push-based executor with `Flow::Stop` for early termination — simplest way to get streaming plus `head` short-circuit without iterator lifetimes through trait objects — no parallelism; one core.
- Ruling: Global `max_groups` limit (default 2,000,000) that fails the query instead of spilling to disk — the spec asks for documented bounded memory; a clear error is better than OOM — very high-cardinality group-bys need `--max-groups` raised and enough RAM.
- Ruling: `beacon` keeps at most `max_events` (20,000) timestamps per group, the first ones seen — bounds memory on chatty channels (20k ≈ one connection every 4.3 s for 24 h) — for longer captures the score reflects the first 20k connections only.
- Ruling: `stats` groups and hunting-operator outputs are emitted in deterministic order (first-seen order for `stats`; explicit sort keys for `stack`, `rare`, `first_seen`, `beacon`) — golden tests and reproducible reports — none.
- Ruling: Unparseable values become null and malformed rows are skipped, both counted and warned about once per kind, instead of aborting — Zeek logs from live sensors are routinely truncated mid-line — a badly corrupted file yields partial results (visible in the warning).
- Ruling: Schemas for conn/dns/http/ssl are built in and extended from the first file's header — queries type-check before reading data, yet custom Zeek fields work — if rotated files disagree on extra columns, only the first file's extras are known.

## Beacon scoring and evaluation

- Ruling: Score = `0.5·max(s_jit, s_acf) + 0.2·min + 0.15·s_skew + 0.15·s_size` — either periodicity view can carry a beacon (interval stats for jittered timers, autocorrelation for channels with interleaved noise) and agreement adds a bonus — weights are hand-set, not learned.
- Ruling: Jitter is modelled as "sleep minus up to j" (`P·(1 − j·U)`), the Cobalt-Strike-style convention — it is the most common public implant convention — implants that add jitter symmetrically or use other distributions are not represented in the evaluation.
- Ruling: The autocorrelation feature was reworked three times on *training seeds only* after concrete failures: (1) raw pair counts let two bursts create n·m "periodic" pairs → bursts are collapsed and occupancy is binary; (2) a global uniform baseline flagged diurnal browsing → the baseline is the channel's own hit rate at off-period lags; (3) `(hit − off)/(1 − off)` exploded for dense channels → lags with `off > 0.5` are skipped; plus `e/(e+8)` and `m/(m+4)` shrinkage for small samples — each fix is documented in `docs/ARCHITECTURE.md` — the feature is still heuristic and was not validated on real traffic.
- Ruling: Held-out evaluation seeds are 5001–5050; training seeds 1–20 are used for design iteration and threshold selection — during development one early run also looked at seeds 1001–1020, so those were retired and never used for reported numbers — if the generator itself is biased toward this detector's assumptions, held-out seeds cannot reveal it (see README Limitations).
- Ruling: Default `min_score = 0.5` for the `beacon` operator — the F1-optimal combined threshold chosen on training seeds was 0.499; 0.5 is that value rounded — on real networks the right threshold will differ; analysts should sort by score rather than trust a cut-off.
- Ruling: Default `min_count = 10` — interval statistics from fewer than ~10 connections are noise — hourly beacons need ≥ 10 hours of data to be scored.
- Ruling: Ground truth positives are only the planted beacons; benign *periodic* services (NTP, update checks with fixed timers) are deliberately not generated — the evaluation measures periodicity detection against hard non-periodic negatives (Poisson pollers, log-normal sync clients, bursty browsing) — on real networks such benign timers will (correctly) score high and need allow-listing; precision on real data will be lower.
- Ruling: No external datasets — no public Zeek dataset ships beacon ground truth at varying jitter, and the contract forbids live malware — all evaluation is on synthetic data, stated prominently.

## Tooling

- Ruling: Own SplitMix64 PRNG instead of `rand` — byte-identical fixtures across platforms and dependency upgrades (checked by a test) — weaker statistical quality than modern PRNGs, irrelevant here.
- Ruling: Own radix-2 FFT (≈50 lines) instead of `rustfft` — one dependency fewer; sizes are powers of two ≤ 2^18 — slower than an optimised FFT for very large series.
- Ruling: Simple line-based REPL on stdin (no `rustyline`) — works identically in a terminal and a pipe, so it is fully testable — no line editing or history in interactive use.
- Ruling: Coverage gate is line coverage ≥ 85% over the whole crate via `cargo llvm-cov` — the CLI is exercised by integration tests, so excluding it is unnecessary — CI needs `cargo-llvm-cov` installed (done in the workflow).
- Ruling: MSRV 1.82 (uses `Option::is_none_or`) — keeps code idiomatic — older toolchains cannot build it.
