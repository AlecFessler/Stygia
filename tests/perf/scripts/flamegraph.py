#!/usr/bin/env python3
"""Kprof sample-mode flame graph renderer.

Reads a `[KPROF]`-framed dump (see `kernel/kprof/dump.zig`) from a
path or stdin and emits a self-contained flame graph SVG on stdout.
The kernel has already resolved each `ip` to a symbol via its own
DWARF (post-KASLR) before printing, so this script never touches
kernel.elf — it just parses names out of the `sym=...` field.

Record grouping, per CPU, in emission order:

  kind=4 (leaf)         starts a new stack, sym = leaf function
  kind=5 (sample_frame) arg=1..N appends a caller frame onto the
                        current stack in increasing depth order

A stack terminates at the next kind=4 on the same CPU or at any
non-sample record. Stacks are folded by identity (same caller→leaf
path collapses to one entry with a count) and rendered as a
bottom-up flame graph: outermost caller at the bottom, sampled
instruction at the top, width proportional to the fraction of
samples reaching that frame.

Usage:
  parse-dump-from-file:   flamegraph.py dump.log > flame.svg
  parse-dump-from-stdin:  ./run.sh | flamegraph.py - > flame.svg
"""

from __future__ import annotations

import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import IO, Iterable


KPROF_PREFIX = "[KPROF] "
REC_RE = re.compile(
    r"^\[KPROF\] rec "
    r"cpu=(?P<cpu>\d+) "
    r"tsc=(?P<tsc>\d+) "
    r"kind=(?P<kind>\d+) "
    r"id=(?P<id>\d+) "
    r"ip=0x(?P<ip>[0-9a-fA-F]+) "
    r"arg=0x(?P<arg>[0-9a-fA-F]+) "
    r"sym=(?P<sym>\S+)\s*$"
)

KIND_SAMPLE = 4
KIND_SAMPLE_FRAME = 5


# ── Parse ────────────────────────────────────────────────────────────

@dataclass
class InFlight:
    """One call stack still being assembled from a kind=4 leaf plus
    any kind=5 frames with strictly increasing arg depth."""
    frames: list[str] = field(default_factory=list)  # idx 0 = leaf, last = deepest caller
    last_depth: int = 0                              # 0 = leaf, 1 = first caller, ...


def parse_stacks(stream: IO[str]) -> list[list[str]]:
    """Return a list of stacks. Each stack is [leaf, caller1, caller2, ...].

    We key in-flight assembly by CPU so interleaved per-CPU dump
    sections don't contaminate each other (dump order is per-CPU
    contiguous today, but tsc still matters within a CPU)."""
    per_cpu: dict[int, InFlight] = defaultdict(InFlight)
    done: list[list[str]] = []

    def flush(cpu: int) -> None:
        buf = per_cpu.get(cpu)
        if buf is not None and buf.frames:
            done.append(buf.frames)
        per_cpu[cpu] = InFlight()

    for line in stream:
        if not line.startswith(KPROF_PREFIX):
            continue
        m = REC_RE.match(line.rstrip("\r\n"))
        if m is None:
            continue

        cpu = int(m.group("cpu"))
        kind = int(m.group("kind"))
        arg = int(m.group("arg"), 16)
        sym = m.group("sym")

        if kind == KIND_SAMPLE:
            # Start of a new stack. Flush anything in flight first.
            flush(cpu)
            per_cpu[cpu].frames = [sym]
            per_cpu[cpu].last_depth = 0
        elif kind == KIND_SAMPLE_FRAME:
            buf = per_cpu[cpu]
            # Skip frames that aren't a direct continuation (arg must
            # strictly increase by one; a non-monotonic arg means the
            # emitter moved on without a new kind=4, which shouldn't
            # happen today — drop defensively).
            if not buf.frames or arg != buf.last_depth + 1:
                continue
            buf.frames.append(sym)
            buf.last_depth = arg
        else:
            # Not a sample record — terminate any in-flight stack.
            flush(cpu)

    for cpu in list(per_cpu.keys()):
        flush(cpu)

    return done


# ── Fold ─────────────────────────────────────────────────────────────

def fold(stacks: list[list[str]]) -> Counter[tuple[str, ...]]:
    """Each stack is [leaf, caller1, caller2, ...]. We fold on the
    tuple (deepest_caller, ..., caller1, leaf) so the "root" of the
    flame graph is the outermost stack frame — standard orientation
    used by Brendan Gregg's flamegraph.pl."""
    folded: Counter[tuple[str, ...]] = Counter()
    for s in stacks:
        folded[tuple(reversed(s))] += 1
    return folded


# ── Tree ─────────────────────────────────────────────────────────────

@dataclass
class Node:
    name: str
    count: int = 0
    children: dict[str, "Node"] = field(default_factory=dict)


def build_tree(folded: Counter[tuple[str, ...]]) -> Node:
    root = Node(name="<root>")
    for stack, count in folded.items():
        root.count += count
        cur = root
        for name in stack:
            child = cur.children.get(name)
            if child is None:
                child = Node(name=name)
                cur.children[name] = child
            child.count += count
            cur = child
    return root


# ── Render ───────────────────────────────────────────────────────────

# Layout constants. These are deliberately close to flamegraph.pl's
# defaults so the output looks familiar.
SVG_WIDTH = 1800
SVG_PAD_X = 10
SVG_PAD_TOP = 40
FRAME_HEIGHT = 16
FONT_SIZE = 12
MIN_RENDER_PX = 0.2  # frames thinner than this are skipped


def palette(name: str) -> str:
    """Stable pseudo-random warm-palette color keyed by function name.
    Same hash-to-HSL trick flamegraph.pl uses, so equivalent names get
    equivalent colors across re-runs."""
    h = 0
    for ch in name:
        h = (h * 131 + ord(ch)) & 0xFFFFFFFF
    # Warm band: hue 0..60 (reds→yellows), saturation 55-65%, lightness 45-55%.
    hue = h % 60
    sat = 55 + (h >> 8) % 10
    lit = 45 + (h >> 16) % 10
    return f"hsl({hue},{sat}%,{lit}%)"


def escape_xml(s: str) -> str:
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
    )


def render_svg(root: Node) -> str:
    if root.count == 0:
        return "<!-- no samples -->\n"

    plot_w = SVG_WIDTH - 2 * SVG_PAD_X
    total = root.count
    px_per_sample = plot_w / total

    # Figure out depth so we can size the SVG. Depth of the tree is
    # the length of the longest stack.
    def depth_of(n: Node) -> int:
        if not n.children:
            return 1
        return 1 + max(depth_of(c) for c in n.children.values())

    max_depth = depth_of(root) - 1  # exclude synthetic <root>
    svg_h = SVG_PAD_TOP + max_depth * FRAME_HEIGHT + 40

    out: list[str] = []
    out.append(
        f'<svg version="1.1" xmlns="http://www.w3.org/2000/svg" '
        f'width="{SVG_WIDTH}" height="{svg_h}" '
        f'viewBox="0 0 {SVG_WIDTH} {svg_h}" '
        f'font-family="Verdana, sans-serif" font-size="{FONT_SIZE}">'
    )
    out.append(
        f'<rect x="0" y="0" width="{SVG_WIDTH}" height="{svg_h}" fill="#eeeeec"/>'
    )
    out.append(
        f'<text x="{SVG_WIDTH // 2}" y="24" text-anchor="middle" '
        f'font-size="16" font-weight="bold">Kprof flame graph '
        f'({total} samples)</text>'
    )

    # Classic flame graph layout: outermost caller at the bottom,
    # leaves at the top. `depth = 0` corresponds to the direct
    # children of `<root>` (i.e. the outermost caller of any sample).
    def draw(node: Node, x_px: float, depth: int) -> None:
        for name, child in sorted(node.children.items()):
            w = child.count * px_per_sample
            if w >= MIN_RENDER_PX:
                y = SVG_PAD_TOP + (max_depth - 1 - depth) * FRAME_HEIGHT
                fill = palette(name)
                title = escape_xml(f"{name} — {child.count}/{total} samples")
                out.append(
                    f'<g><title>{title}</title>'
                    f'<rect x="{SVG_PAD_X + x_px:.2f}" y="{y}" '
                    f'width="{w:.2f}" height="{FRAME_HEIGHT - 1}" '
                    f'fill="{fill}" stroke="#00000022" stroke-width="0.5"/>'
                )
                # Text fits only when the frame is wide enough.
                if w >= 40:
                    text_x = SVG_PAD_X + x_px + 3
                    text_y = y + FRAME_HEIGHT - 4
                    label = name
                    # rough per-char budget at FONT_SIZE=12
                    max_chars = max(1, int((w - 6) / 6))
                    if len(label) > max_chars:
                        label = label[: max_chars - 1] + "…"
                    out.append(
                        f'<text x="{text_x:.2f}" y="{text_y}" '
                        f'fill="#000">{escape_xml(label)}</text>'
                    )
                out.append('</g>')
            draw(child, x_px, depth + 1)
            x_px += w

    draw(root, 0.0, 0)
    out.append('</svg>\n')
    return "\n".join(out)


# ── CLI ──────────────────────────────────────────────────────────────

def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: flamegraph.py <path|-> > out.svg", file=sys.stderr)
        return 2

    path = argv[1]
    if path == "-":
        stacks = parse_stacks(sys.stdin)
    else:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            stacks = parse_stacks(fh)

    if not stacks:
        print("no sample stacks found in input", file=sys.stderr)
        return 1

    folded = fold(stacks)
    tree = build_tree(folded)
    sys.stdout.write(render_svg(tree))

    # Also emit a short per-run summary on stderr so the pipeline
    # isn't totally opaque.
    print(
        f"flamegraph.py: {len(stacks)} sample stacks, "
        f"{len(folded)} unique, {tree.count} total samples",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
