# gdb_mcp

Persistent gdb session for debugging the Zag kernel under qemu's gdb stub.
Drives a single long-lived `gdb -interpreter=mi3` subprocess via stdio
JSON-RPC, with symbol and struct-field resolution backed by the callgraph
SQLite DB built by `tools/indexer`. The DB is the workaround for gdb's
fussy handling of fully-qualified Zig namespaces — instead of typing
`print sched.scheduler.core_states[0].current_ec` and watching gdb fail
with `No symbol "sched" in current context`, the MCP looks the symbol up
by SQL and feeds gdb a raw address.

## Build

```
cd tools/gdb_mcp
zig build
```

Produces `zig-out/bin/gdb_mcp`. Links the system `libsqlite3` (Arch:
`pacman -S sqlite`).

The DB it queries is the same `tools/callgraph_http/test/dbs/*.db` the
callgraph MCP uses; build it with `zig build index -Demit_index=true` from
the repo root after a kernel build.

## Register with Claude Code

Add to `~/.claude.json` under `mcpServers`:

```json
"gdb": {
  "type": "stdio",
  "command": "/home/alec/Zag/tools/gdb_mcp/zig-out/bin/gdb_mcp",
  "args": [
    "--db-dir", "/home/alec/Zag/tools/callgraph_http/test/dbs"
  ],
  "env": {}
}
```

CLI args:
- `--db <path>` — open one DB file
- `--db-dir <dir>` — pick the newest `*.db` (by mtime) from the dir
- `--gdb <path>` — gdb binary; defaults to `gdb` on PATH

## Workflow

1. **Boot the kernel under qemu with the gdb stub:**
   ```
   qemu-system-x86_64 ... -s -S
   ```
   `-s` opens the stub on `:1234`; `-S` halts the CPU at reset so the agent
   can set breakpoints before any code runs.

2. **Start a session:**
   ```
   gdb_start { elf: "/home/alec/Zag/zig-out/bin/kernel.elf" }
   ```
   Default target is `:1234`. Pass `target: "none"` to spawn gdb without
   connecting (useful for sanity-checking symbol resolution).

3. **If KASLR is in play**, set the offset once the kernel is loaded:
   ```
   gdb_set_kaslr { offset: "0xff..." }     # runtime − link
   ```
   Subsequent name-based ops (`gdb_break`, `gdb_resolve`, `gdb_read_var`)
   apply this offset automatically.

4. **Set a breakpoint by qualified Zig name** — DB resolves the address,
   gdb gets `*0x<addr>`:
   ```
   gdb_break { at: "main.kMain" }
   gdb_break { at: "kernel/sched/scheduler.zig:412" }      # also works
   gdb_break { at: "0xffffffff8002e350" }                  # also works
   ```

5. **Step the L4 fast-path:**
   ```
   gdb_continue                                            # runs to bp
   gdb_step_instruction                                    # `si`
   gdb_pc                                                  # current frame
   gdb_regs                                                # all regs
   ```

6. **Read a struct field without writing C casts:**
   ```
   gdb_read_var {
     name: "sched.scheduler.core_states",
     type: "sched.scheduler.PerCore",
     array_index: 0,
     field: "current_ec"
   }
   ```
   The DB knows `core_states` is at `0xffffffff80317330` (`.bss`),
   `PerCore` is 144 bytes wide, and `current_ec` is at offset 64. The MCP
   does the math and issues `-data-read-memory-bytes`.

7. **Done:**
   ```
   gdb_end
   ```

## Tools

| Tool | Purpose |
| --- | --- |
| `gdb_status` | Session state, target, KASLR offset, loaded DBs |
| `gdb_start` | Spawn gdb, connect to stub. Auto-runs DB↔ELF freshness check |
| `gdb_end` | Tear down the session |
| `gdb_reset` | Force-reset: kill active session + SIGKILL orphan gdb procs from previous gdb_mcp instances. Use after a hang |
| `gdb_verify` | Recheck DB↔ELF freshness on demand |
| `gdb_set_kaslr` | Set runtime − link offset for the current session |
| `gdb_resolve` | Look up qname in `bin_symbol`; report link/runtime addr + size |
| `gdb_resolve_field` | Walk dotted field path through `type_field`; report offset + size |
| `gdb_break` | Set bp at file:line / addr / qname |
| `gdb_break_clear` | Delete bp by id (or `"all"`) |
| `gdb_break_list` | List bps |
| `gdb_continue` / `gdb_step` / `gdb_step_instruction` / `gdb_next` / `gdb_finish` / `gdb_interrupt` | Execution control |
| `gdb_pc` | Current frame. Auto-surfaces `gdb_args` diagnostic when the func is sret-returning |
| `gdb_args` | Sret-aware argument register dump for the current frame (or an explicitly named function) — works around gdb's wrong `args=[...]` for >16-byte-return Zig functions |
| `gdb_regs` | Register dump |
| `gdb_read_mem` | Raw memory read |
| `gdb_read_var` | DB-resolved variable + field read |
| `gdb_backtrace` | Frame list |
| `gdb_disasm` | Disassemble around `$pc` or a given address |
| `gdb_raw` | Pass an arbitrary MI command — escape hatch |

## Gotchas

### Zig sret calling convention

For Zig functions with return values **larger than 16 bytes**, the ABI puts
the hidden sret pointer in `%rdi` and shifts every "real" argument right by
one. So when gdb shows `frame={func="foo",args=[{name="self",value="..."}]}`,
the value it printed for `self` is actually the sret slot — `self` is in
`%rdx`, not `%rdi`. Pattern to recognize: the function returns a struct or
optional bigger than 16 bytes, and gdb's `args=[...]` first value looks like
a stack address rather than a real argument.

The MCP detects this automatically. `gdb_pc` and the stop-event output
from `gdb_continue` / `gdb_step` / `gdb_step_instruction` / `gdb_next`
auto-append a `[zig-sret] …` block when the current function is
sret-returning, with sret-aware labels on `rdi/rsi/rdx/rcx/r8/r9`. You
can also call `gdb_args` directly — with no args for the current frame,
or with `name=<qname>` to ask "is X sret-returning, and if so what would
its regs look like?".

For functions returning ≤16 bytes, gdb's `args=[...]` follows normal SysV
ordering and is reliable.

### DB staleness

`gdb_start` automatically runs the freshness check; if it reports
`WARNING: DB↔ELF deltas inconsistent`, the kernel was rebuilt without
re-indexing. Run `zig build index -Demit_index=true` from the repo root
and reconnect. The `gdb_resolve` / `gdb_break {at: qname}` /
`gdb_read_var` paths all assume the DB matches the loaded ELF — running
on a stale DB returns wrong addresses for symbols the rebuild moved.

## Limitations / future work

- **Single session.** Only one gdb at a time per server. Adequate for the
  intended single-target debugging workflow.
- **No automatic KASLR detection.** Caller passes the offset via
  `gdb_set_kaslr`. Auto-detection by reading runtime `$pc` after a known
  kernel breakpoint hit is left for a follow-up.
- **`gdb_read_var` array/field walk needs explicit `type`.** The
  callgraph DB doesn't yet record a variable→type relationship, so the
  caller passes the element/struct type qname. `gdb_resolve_field` is
  pure DB lookup and works without a session.
- **MI parser is line-oriented and minimal.** It extracts class, console
  stream, and a couple of common attrs verbatim; everything else is
  returned as raw payload. For elaborate parsing, use `gdb_raw` and
  parse the returned text yourself.
