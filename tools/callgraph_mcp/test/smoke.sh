#!/usr/bin/env bash
# Smoke test for callgraph_mcp: speaks JSON-RPC over stdio, exercises every
# `callgraph_*` tool, asserts each returns a result (not an error).
#
# Usage:
#   tools/callgraph_mcp/test/smoke.sh                # uses default DB dir
#   tools/callgraph_mcp/test/smoke.sh /path/to/db    # explicit DB file

set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ZAG_ROOT="$(cd -- "$HERE/../../.." && pwd)"

if [[ $# -ge 1 ]]; then
    DB_PATH="$1"
else
    DB_PATH="$(ls "$ZAG_ROOT"/tools/callgraph_http/test/dbs/x86_64-*.db 2>/dev/null | head -1 || true)"
fi

if [[ -z "$DB_PATH" || ! -f "$DB_PATH" ]]; then
    echo "smoke: no callgraph DB found." >&2
    echo "  build one with: bash tests/test.sh dead-code  (or run the indexer manually)" >&2
    exit 2
fi

CALLGRAPH_BIN="$ZAG_ROOT/tools/callgraph_mcp/zig-out/bin/callgraph_mcp"
if [[ ! -x "$CALLGRAPH_BIN" ]]; then
    (cd "$ZAG_ROOT/tools/callgraph_mcp" && zig build) >&2 || { echo "build failed" >&2; exit 2; }
fi

DB_SHA="$(sqlite3 "$DB_PATH" "SELECT value FROM meta WHERE key='commit_sha'" 2>/dev/null || echo unknown)"
echo "smoke: DB=$DB_PATH (sha=$DB_SHA)"

REQ_FILE="$(mktemp)"
trap 'rm -f "$REQ_FILE"' EXIT

# Build a single JSON-RPC stream: initialize + 15 tool calls.
{
    cat <<JSON
{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"callgraph_arches","arguments":{}}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"callgraph_find","arguments":{"q":"halt","limit":3}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"callgraph_loc","arguments":{"name":"arch.x64.cpu.halt"}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"callgraph_src","arguments":{"name":"arch.x64.cpu.halt"}}}
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"callgraph_callers","arguments":{"name":"arch.x64.cpu.halt"}}}
{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"callgraph_reaches","arguments":{"from":"arch.x64.power.doShutdown","to":"arch.x64.cpu.halt"}}}
{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"callgraph_entries","arguments":{}}}
{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"callgraph_modules","arguments":{}}}
{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"callgraph_trace","arguments":{"entry":"arch.x64.power.doShutdown","depth":2}}}
{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"callgraph_type","arguments":{"name":"memory.address.VAddr"}}}
{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"callgraph_src_bin","arguments":{"name":"arch.x64.cpu.halt"}}}
{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"callgraph_src_bin_at","arguments":{"at":"arch/x64/cpu.zig:430"}}}
{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"callgraph_bin_dataflow_reg","arguments":{"name":"arch.x64.cpu.halt","reg":"rsp"}}}
{"jsonrpc":"2.0","id":14,"method":"tools/call","params":{"name":"callgraph_bin_addr2line","arguments":{"addr":"0xffffffff8000f815"}}}
{"jsonrpc":"2.0","id":15,"method":"tools/call","params":{"name":"callgraph_commits","arguments":{"limit":3}}}
{"jsonrpc":"2.0","id":16,"method":"tools/call","params":{"name":"callgraph_findings","arguments":{"limit":3}}}
JSON
} > "$REQ_FILE"

OUT_FILE="$(mktemp)"
trap 'rm -f "$REQ_FILE" "$OUT_FILE"' EXIT

"$CALLGRAPH_BIN" --db "$DB_PATH" --git-root "$ZAG_ROOT" < "$REQ_FILE" > "$OUT_FILE" 2>/tmp/callgraph_mcp_smoke.err

# Tools 1..15: each must have id:N with "result", not "error".
fail=0
ok=0
declare -A NAMES=(
    [1]=arches [2]=find [3]=loc [4]=src [5]=callers
    [6]=reaches [7]=entries [8]=modules [9]=trace [10]=type
    [11]=src_bin [12]=src_bin_at [13]=bin_dataflow_reg
    [14]=bin_addr2line [15]=commits [16]=findings
)
for id in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16; do
    name="${NAMES[$id]}"
    if grep -qE "\"id\":${id},.*\"result\":" "$OUT_FILE"; then
        ok=$((ok+1)); printf "[OK ] %s\n" "$name"
    elif grep -qE "\"id\":${id},.*\"error\":" "$OUT_FILE"; then
        msg="$(grep -oE "\"id\":${id},[^}]*\"message\":\"[^\"]*\"" "$OUT_FILE" | head -1)"
        fail=$((fail+1)); printf "[FAIL] %s : %s\n" "$name" "$msg"
    else
        fail=$((fail+1)); printf "[FAIL] %s : no response\n" "$name"
    fi
done

echo
total=$((ok + fail))
echo "smoke: $ok / $total tools OK"
if [[ $fail -gt 0 ]]; then
    echo "       (stderr at /tmp/callgraph_mcp_smoke.err)"
    exit 1
fi
