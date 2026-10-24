# Threat model

huntql is a **defensive, offline analysis tool**: it reads Zeek logs that a
defender already collected and answers queries about them. It does not
capture traffic, connect to hosts, or take any action on a network.

## Assets and trust boundaries

| Asset | Where it comes from | Trust |
|---|---|---|
| Zeek log files | the analyst's sensors, copied to local disk | **untrusted content**: field values are attacker-influenced (hostnames, URIs, user agents, certificate subjects) |
| Query text / query files | the analyst | trusted intent, but may be malformed |
| Results | printed to the analyst's terminal or a pipe | must faithfully reflect the logs |

## Threats considered

1. **Malicious field values in logs.** An attacker controls strings such as
   `user_agent`, `uri`, `query` and `server_name`.
   * huntql never executes, evaluates or interpolates log content; values are
     data only. Regexes come from the query, never from logs.
   * Table output replaces tabs/newlines in cells and truncates cells at 60
     characters; TSV output replaces tabs/newlines; JSON output is produced by
     `serde_json`, so a crafted value cannot forge extra rows or columns.
     Terminal escape sequences are *not* stripped from table output — pipe
     untrusted results through `--format json` if that matters (see
     Limitations in README).
   * Zeek `\xHH` escapes are decoded only into the in-memory string.
2. **Resource exhaustion via crafted logs.** A log with millions of distinct
   keys could exhaust memory in grouping operators. Every blocking operator is
   capped by `--max-groups` (default 2,000,000) and fails cleanly;
   `beacon` stores at most `max_events` timestamps per group; streaming
   operators hold no rows. Regexes use the `regex` crate (linear time, no
   catastrophic backtracking). Very long single lines are still read into
   memory whole.
3. **Malformed input.** Truncated lines, wrong column counts, invalid JSON,
   bad timestamps and unknown types are skipped or read as null and counted;
   they never panic the process (lexer/parser/planner totality is
   property-tested on arbitrary input).
4. **Evasion of the hunting analytics.** These are heuristics, not
   guarantees. Known blind spots, by design of the scoring: beacons with very
   high jitter (≥ 80%), beacons heavily mixed with interactive traffic on the
   same channel, beacons that rotate destinations or ports (grouping by
   `src, dst, dport` splits them; group on names instead, e.g.
   `ssl | eval d = sld(server_name) | beacon by src, d`), and very slow beacons with fewer than
   `min_count` connections in the window. Benign periodic services (NTP,
   update agents with fixed timers) score as periodic and need allow-listing.
   Results are leads for an analyst, not verdicts.

## Out of scope

* Live capture, sensors, or Zeek itself.
* Authenticating log provenance (huntql trusts that the files are the
  sensor's output).
* Multi-user deployment: there is no server, no network listener and no
  stored state.

## Ethics

All bundled data is synthetic and uses reserved documentation/benchmark
address ranges and reserved DNS names. The generator produces *log records
describing* beacon-like timing; it contains no implant, no network code and
nothing that can contact a real system.
