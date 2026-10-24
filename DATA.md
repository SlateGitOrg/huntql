# Data

huntql ships **no third-party data**. Everything under `fixtures/` is
synthetic output of huntql's own generator (`huntql gen`, `src/gen/mod.rs`),
committed so tests and the demo run offline.

| Path | How it was produced | Size | License |
|---|---|---|---|
| `fixtures/demo/{conn,dns,http,ssl}.log`, `truth.json` | `huntql gen --out fixtures/demo --seed 7 --hours 12 --hosts 25 --beacons 6` (Zeek TSV) | ~5.1 MB | MIT (this repository) |
| `fixtures/json/{conn,dns,http,ssl}.json`, `truth.json` | `huntql gen --out fixtures/json --seed 11 --hours 3 --hosts 6 --beacons 2 --log-format json` (Zeek NDJSON) | ~0.3 MB | MIT (this repository) |
| `tests/golden/*.out` | `UPDATE_GOLDEN=1 cargo test --test golden` over the fixtures above | small | MIT |

`make fixtures` regenerates both directories; `tests/cli.rs` asserts the
committed files are byte-identical to fresh generator output.

## What the synthetic data contains

* Internal hosts in `10.20.0.0/16`, a resolver at `10.20.0.53`.
* Benign servers in `198.18.0.0/15` (RFC 2544 benchmarking range) named
  under the reserved `.example`, `example.com/.net/.org` names (RFC 2606).
* Planted C2 servers in `203.0.113.0/24` (RFC 5737 TEST-NET-3) named
  `<random>.test` (RFC 6761).
* Benign traffic: diurnal Poisson browsing sessions with DNS/TLS/HTTP
  records, Poisson "update" pollers and log-normal "sync" clients.
* Planted artifacts: periodic beacons (period, jitter, dropped check-ins,
  interleaved traffic recorded in `truth.json`), one implant user agent, one
  implant JA3 string, and ~30 NXDOMAIN lookups of random-looking names from
  one host.

The JA3 strings are arbitrary 32-hex-digit tokens chosen for the generator;
they are not claimed to correspond to any real client.

## Evaluation data

`huntql eval` generates its scenarios in memory (training seeds 1–20,
held-out seeds 5001–5050 by default; 24 h, 40 hosts, 8 beacons each) and
writes nothing to disk. `scripts/bench.sh` generates larger conn logs under
`target/bench` and deletes them afterwards.

No real network traffic, PCAPs or third-party datasets are used anywhere.
