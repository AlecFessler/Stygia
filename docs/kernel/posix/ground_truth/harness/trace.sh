#!/bin/bash
# Ground-truth syscall trace harness for static-musl busybox (Stygia POSIX segment 1).
# Runs the five invocation shapes from POSIX_TRANSITION_PLAN.md §5.1 under strace.
#
# All shapes run under a pty (via script(1)) because the Stygia target is a
# console-attached shell: without a tty, ash never takes the interactive path and
# the TCGETS/TIOCGWINSZ/TIOCGPGRP ioctls -- the ones §6 calls critical -- never fire.
#
# Each shape's command is materialised into its own run.sh with printf %q quoting.
# Interpolating the command into `script -c "..."` instead makes the OUTER shell
# perform the pipeline / redirection / glob, so busybox never issues those calls.
set -u
S=/tmp/claude-1000/-home-alec-Stygia/b7abdd81-1519-482b-9c0e-fa593991b36b/scratchpad
BIN=$S/tr/bin
OUT=$S/traces
WORK=$S/tr/work

rm -rf "$OUT" "$WORK"
mkdir -p "$OUT" "$WORK"

make_fixtures() {
	rm -rf "$WORK"
	mkdir -p "$WORK/sub"
	echo alpha  > "$WORK/a.txt"
	echo beta   > "$WORK/b.txt"
	echo gamma  > "$WORK/c.txt"
	echo notxt  > "$WORK/d.dat"
	echo nested > "$WORK/sub/e.txt"
	cat > "$WORK/script.sh" <<'EOS'
# busybox ash script exercised by shape 5
echo script-start
x=1
if [ "$x" = 1 ]; then
	echo branch-taken
fi
for f in a b c; do
	echo "loop $f"
done
pwd
cd sub
pwd
cd ..
ls a.txt
echo script-end
EOS
}

# run_shape <name> <argv...>
run_shape() {
	local name=$1; shift
	local d="$OUT/$name"
	mkdir -p "$d"
	[ -f "$d/stdin" ] || : > "$d/stdin"

	# record the exact argv, one element per line, unambiguously
	printf '%s\n' "$@" > "$d/ARGV"

	local q; q=$(printf '%q ' "$@")

	make_fixtures
	cat > "$d/run.sh" <<EOF
#!/bin/bash
cd $(printf '%q' "$WORK") || exit 1
exec env -i PATH=$(printf '%q' "$BIN") HOME=$(printf '%q' "$WORK") \\
     PWD=$(printf '%q' "$WORK") TERM=linux SHELL=$(printf '%q' "$BIN/sh") \\
     /usr/bin/strace -ff -v -s 256 -qq -o $(printf '%q' "$d/t") $q
EOF
	chmod +x "$d/run.sh"
	script -qec "$d/run.sh" /dev/null < "$d/stdin" > "$d/console.log" 2>&1

	# counts summary (separate run; -c is mutually exclusive with per-call output)
	make_fixtures
	cat > "$d/run_c.sh" <<EOF
#!/bin/bash
cd $(printf '%q' "$WORK") || exit 1
exec env -i PATH=$(printf '%q' "$BIN") HOME=$(printf '%q' "$WORK") \\
     PWD=$(printf '%q' "$WORK") TERM=linux SHELL=$(printf '%q' "$BIN/sh") \\
     /usr/bin/strace -f -qq -c -o $(printf '%q' "$d/summary.txt") $q
EOF
	chmod +x "$d/run_c.sh"
	script -qec "$d/run_c.sh" /dev/null < "$d/stdin" > "$d/console_c.log" 2>&1
}

# ---- shape 1: interactive-style session --------------------------------------
mkdir -p "$OUT/01-interactive"
cat > "$OUT/01-interactive/stdin" <<'EOS'
echo hello
ls
pwd
cd sub
pwd
cd ..
exit
EOS
run_shape 01-interactive "$BIN/sh" -i

# ---- shape 2: pipeline -------------------------------------------------------
run_shape 02-pipeline "$BIN/sh" -c 'ls | cat'

# ---- shape 3: redirection ----------------------------------------------------
run_shape 03-redirect "$BIN/sh" -c 'echo hi > f; cat < f'

# ---- shape 4: glob -----------------------------------------------------------
run_shape 04-glob "$BIN/sh" -c 'ls *.txt'

# ---- shape 5: script invocation ----------------------------------------------
run_shape 05-script "$BIN/sh" script.sh

echo "=== trace files ==="
find "$OUT" -name 't.*' | sort | sed "s|$OUT/||"
echo
echo "=== console output per shape ==="
for d in "$OUT"/*/; do
	echo "--- $(basename "$d")"
	cat "$d/console.log"
	echo
done
