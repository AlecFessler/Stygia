#!/bin/bash
# Supplementary traces -- NOT part of the canonical five-shape union.
#
# Two blind spots in the five shapes, both of which Stygia will hit for real:
#   S1  PATH search with a realistic multi-entry PATH. The canonical shapes use a
#       single-entry PATH where every command resolves on the first try, so the
#       ENOENT probing storm that a real PATH produces never appears.
#   S2  Direct applet execution. ash resolves pwd/true/false as BUILTINS, so the
#       standalone applets -- and getcwd, which the pwd applet uses -- never run.
set -u
S=/tmp/claude-1000/-home-alec-Stygia/b7abdd81-1519-482b-9c0e-fa593991b36b/scratchpad
BIN=$S/tr/bin
OUT=$S/traces_supp
WORK=$S/tr/work

rm -rf "$OUT"
mkdir -p "$OUT"

fixtures() {
	rm -rf "$WORK"; mkdir -p "$WORK/sub"
	echo alpha > "$WORK/a.txt"; echo beta > "$WORK/b.txt"
	echo gamma > "$WORK/c.txt"; echo notxt > "$WORK/d.dat"
	echo nested > "$WORK/sub/e.txt"
}

run() {
	local name=$1 path=$2; shift 2
	local d="$OUT/$name"; mkdir -p "$d"
	printf '%s\n' "$@" > "$d/ARGV"
	echo "$path" > "$d/PATH"
	local q; q=$(printf '%q ' "$@")
	fixtures
	cat > "$d/run.sh" <<EOF
#!/bin/bash
cd $(printf '%q' "$WORK") || exit 1
exec env -i PATH=$(printf '%q' "$path") HOME=$(printf '%q' "$WORK") \\
     PWD=$(printf '%q' "$WORK") TERM=linux SHELL=$(printf '%q' "$BIN/sh") \\
     /usr/bin/strace -ff -v -s 256 -qq -o $(printf '%q' "$d/t") $q
EOF
	chmod +x "$d/run.sh"
	script -qec "$d/run.sh" /dev/null < /dev/null > "$d/console.log" 2>&1
}

# S1: realistic multi-entry PATH, target resolves only in the LAST entry.
run S1-path-search "/nonexistent-a:/nonexistent-b:/nonexistent-c:$BIN" \
    "$BIN/sh" -c 'ls a.txt; cat a.txt'

# S2: direct applet execs -- exercises the pwd/true/false applets, not builtins.
run S2-applets-direct "$BIN" \
    "$BIN/sh" -c '"$0"/pwd; "$0"/true; "$0"/false; "$0"/ls -l a.txt; "$0"/cat a.txt' "$BIN"

echo "=== console ==="
for d in "$OUT"/*/; do echo "--- $(basename "$d")"; cat "$d/console.log"; done
echo
echo "=== syscalls unique to supplementary (vs canonical union) ==="
grep -hoE '^[a-z_][a-z0-9_]*\(' "$OUT"/*/t.* | tr -d '(' | sort -u > "$S/supp_names.txt"
grep -hoE '^[a-z_][a-z0-9_]*\(' "$S"/traces/*/t.* | tr -d '(' | sort -u > "$S/canon_names.txt"
comm -23 "$S/supp_names.txt" "$S/canon_names.txt"
echo "=== errnos in supplementary ==="
grep -ho '= -1 E[A-Z]*' "$OUT"/*/t.* | sort | uniq -c
