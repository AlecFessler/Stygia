#!/usr/bin/env bash
# Smoke test for callgraph_http: starts the daemon against the per-(arch,
# commit_sha) DB, hits every public endpoint, and asserts each response
# is non-empty and contains an expected substring. Exits non-zero on
# the first failure (other endpoints still attempted; final tally
# determines exit code).
#
# Usage:
#   tools/callgraph_http/test/smoke.sh                 # uses default DB dir
#   tools/callgraph_http/test/smoke.sh /path/to/db     # explicit DB file
#
# This script expects a real DB built by tools/indexer (not the legacy
# seed.sql stub). If the DB is missing the script tells you how to
# build one and exits.

set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
STYGIA_ROOT="$(cd -- "$HERE/../../.." && pwd)"
PORT="${CALLGRAPH_HTTP_PORT:-18190}"

if [[ $# -ge 1 ]]; then
    DB_PATH="$1"
    DB_DIR="$(dirname "$DB_PATH")"
else
    DB_DIR="$STYGIA_ROOT/tools/callgraph_http/test/dbs"
    DB_PATH="$(ls "$DB_DIR"/x86_64-*.db 2>/dev/null | head -1 || true)"
fi

if [[ -z "$DB_PATH" || ! -f "$DB_PATH" ]]; then
    echo "smoke: no callgraph DB found." >&2
    echo "  build one with: bash tests/test.sh dead-code  (or run the indexer manually)" >&2
    exit 2
fi

HEAD_SHA="$(cd "$STYGIA_ROOT" && git rev-parse HEAD 2>/dev/null || echo unknown)"
DB_SHA="$(sqlite3 "$DB_PATH" "SELECT value FROM meta WHERE key='commit_sha'" 2>/dev/null || echo unknown)"

CALLGRAPH_BIN="$STYGIA_ROOT/tools/callgraph_http/zig-out/bin/callgraph_http"
if [[ ! -x "$CALLGRAPH_BIN" ]]; then
    (cd "$STYGIA_ROOT/tools/callgraph_http" && zig build) >&2 || { echo "build failed" >&2; exit 2; }
fi

echo "smoke: DB=$DB_PATH (sha=$DB_SHA)"
echo "       repo HEAD=$HEAD_SHA"
echo "       port=$PORT"

"$CALLGRAPH_BIN" --db-dir "$DB_DIR" --port "$PORT" --git-root "$STYGIA_ROOT" >/tmp/callgraph_http_smoke.log 2>&1 &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true; wait 2>/dev/null || true' EXIT

for _ in $(seq 1 20); do
    if curl -fsS "http://127.0.0.1:$PORT/api/arches" >/dev/null 2>&1; then break; fi
    sleep 0.1
done

BASE="http://127.0.0.1:$PORT"
fail=0
ok=0
ok()  { ok=$((ok+1));   printf "[OK ] %s\n" "$1"; }
bad() { fail=$((fail+1)); printf "[FAIL] %s : %s\n" "$1" "$2"; }
probe() {
    local name="$1" url="$2" expect="$3"
    local resp
    resp=$(curl -fsS "$url" 2>&1) || { bad "$name" "curl failed"; return; }
    [[ -z "$resp" ]] && { bad "$name" "empty response"; return; }
    if [[ -n "$expect" ]] && ! printf '%s' "$resp" | grep -qE "$expect"; then
        bad "$name" "missing expected pattern '$expect'"
        return
    fi
    ok "$name"
}

# A first git-tracked file is needed for diff_hunks; pick the top one
# from the head commit.
DIFF_PATH="$(cd "$STYGIA_ROOT" && git show --pretty='' --name-only "$DB_SHA" 2>/dev/null | head -1 || echo build.zig)"
# Spaces only — slashes go raw, the server's query-string parser handles them.
DIFF_PATH_ENC="$(printf '%s' "$DIFF_PATH" | sed 's| |%20|g')"

# 26 endpoints — must stay aligned with the route table in src/main.zig.
probe arches             "$BASE/api/arches"                                                       'x86_64'
probe find               "$BASE/api/find?q=halt"                                                  'halt'
probe loc                "$BASE/api/loc?name=arch.x64.cpu.halt"                                   'cpu'
probe fn_source          "$BASE/api/fn_source?name=arch.x64.cpu.halt"                             'pub fn'
probe callers            "$BASE/api/callers?name=arch.x64.cpu.halt"                               'arch'
probe entries            "$BASE/api/entries"                                                      'main.kEntry'
probe entries_filter     "$BASE/api/entries?kind=boot"                                            'kEntry'
probe modules            "$BASE/api/modules"                                                      'arch'
probe modules_inbound    "$BASE/api/modules?direction=in"                                         '.'
probe trace              "$BASE/api/trace?name=arch.x64.power.doShutdown&depth=3"                 'doShutdown'
probe trace_compact      "$BASE/api/trace?name=arch.x64.power.doShutdown&depth=3&format=compact"  'doShutdown'
probe reaches_yes        "$BASE/api/reaches?from=arch.x64.power.doShutdown&to=arch.x64.cpu.halt"  'path|hops'
probe reaches_no         "$BASE/api/reaches?from=arch.x64.cpu.halt&to=main.kMain"                 'no path'
probe type               "$BASE/api/type?name=memory.address.VAddr"                               'VAddr'
probe src_bin            "$BASE/api/src_bin?name=arch.x64.cpu.halt"                               'hlt'
probe src_bin_at         "$BASE/api/src_bin_at?at=arch/x64/cpu.zig:430"                           'hlt'
probe bin_addr2line      "$BASE/api/bin_addr2line?addr=0xffffffff8000f815"                       'cpu.zig'
probe bin_dataflow_reg   "$BASE/api/bin_dataflow_reg?name=arch.x64.cpu.halt&reg=rsp"             '.'
probe graph              "$BASE/api/graph"                                                        'definitions'
probe source             "$BASE/api/source?path=arch/x64/cpu.zig&start=425&end=435"               'pub fn'
probe commits            "$BASE/api/commits?limit=2"                                              '.'
probe load_commit        "$BASE/api/load_commit?sha=$DB_SHA"                                      'ready'
probe load_commit_status "$BASE/api/load_commit/status?sha=$DB_SHA"                               'ready'
probe diff               "$BASE/api/diff?sha=$DB_SHA"                                             '.'
probe diff_files         "$BASE/api/diff_files?sha=$DB_SHA"                                       '.'
probe diff_hunks         "$BASE/api/diff_hunks?sha=$DB_SHA&path=$DIFF_PATH_ENC"                   '.'
probe findings           "$BASE/api/findings?limit=3"                                             '.'

echo
total=$((ok + fail))
echo "smoke: $ok / $total endpoints OK"
if [[ $fail -gt 0 ]]; then
    echo "       (server log at /tmp/callgraph_http_smoke.log)"
    exit 1
fi
