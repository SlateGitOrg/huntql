#!/usr/bin/env bash
# Throughput and peak-memory benchmark for huntql.
#
# Generates two synthetic conn logs (small: 50 hosts x 24h, large: 200 hosts
# x 96h, ~16x the rows), runs a fixed set of queries over each, and prints a
# Markdown table with rows scanned, wall time, throughput, the executor's
# peak retained state and the process's peak RSS. Streaming and top-k
# queries should keep the same RSS at 16x the input; grouping queries grow
# with the number of groups. Data lives under target/bench and is removed
# afterwards unless KEEP=1.
set -euo pipefail

cd "$(dirname "$0")/.."
BIN=${BIN:-${CARGO_TARGET_DIR:-target}/release/huntql}
OUT=target/bench
[ -x "$BIN" ] || { echo "build first: cargo build --release" >&2; exit 1; }

# measure CMD...: sets RSS_KB (peak resident set, KiB) and STATS (huntql --stats line).
measure() {
  local tmp; tmp=$(mktemp)
  if [ "$(uname)" = "Darwin" ]; then
    /usr/bin/time -l "$@" >/dev/null 2>"$tmp"
    RSS_KB=$(awk '/maximum resident set size/ {printf "%d", $1/1024}' "$tmp")
  else
    /usr/bin/time -v "$@" >/dev/null 2>"$tmp"
    RSS_KB=$(awk -F: '/Maximum resident set size/ {gsub(/ /,"",$2); printf "%d", $2}' "$tmp")
  fi
  STATS=$(grep -- '^-- ' "$tmp" || true)
  rm -f "$tmp"
}

"$BIN" gen --out "$OUT/small" --seed 1 --hosts 50 --hours 24 --logs conn >/dev/null
"$BIN" gen --out "$OUT/large" --seed 1 --hosts 200 --hours 96 --logs conn >/dev/null

queries=(
  "conn | where dport == 443 | head 10"
  "conn | where dport == 443 | stats count() by src | sort -count | head 10"
  "conn | sort -orig_bytes | head 10"
  "conn | stats count(), avg(duration) by src, dst"
  "conn | beacon"
  "conn | stats count() by uid"
)

echo "| query | data | rows scanned | time (ms) | rows/s | peak state | peak RSS (MiB) |"
echo "|---|---|---|---|---|---|---|"
for q in "${queries[@]}"; do
  for size in small large; do
    measure "$BIN" -d "$OUT/$size" query "$q" --format tsv --stats
    # STATS: "-- scanned N rows, emitted M, peak state P rows/groups, T ms"
    rows=$(sed -E 's/.*scanned ([0-9]+) rows.*/\1/' <<<"$STATS")
    state=$(sed -E 's/.*peak state ([0-9]+) .*/\1/' <<<"$STATS")
    ms=$(sed -E 's/.* ([0-9.]+) ms.*/\1/' <<<"$STATS")
    rate=$(awk -v r="$rows" -v m="$ms" 'BEGIN { if (m > 0) printf "%.0f", r / (m / 1000); else print "-" }')
    printf '| `%s` | %s | %s | %s | %s | %s | %.1f |\n' "${q//|/\\|}" "$size" "$rows" "$ms" "$rate" "$state" "$(awk -v k="$RSS_KB" 'BEGIN{print k/1024}')"
  done
done

[ "${KEEP:-0}" = "1" ] || rm -rf "$OUT"
