//! Tool dispatch for the gdb MCP daemon. Each `gdb_*` handler drives the
//! persistent gdb subprocess (see gdb_session.zig) and/or queries the
//! callgraph DB for symbol/field resolution.
//!
//! The registry owns:
//!   - one or more open callgraph DBs (read-only, one per arch)
//!   - the gdb binary path
//!   - at most one active gdb session (created by gdb_start, torn down by
//!     gdb_end). The MCP request loop is single-threaded, so callers
//!     serialize gdb commands implicitly.

const std = @import("std");

const gdb_session = @import("gdb_session.zig");
const sqlite = @import("sqlite.zig");

const Session = gdb_session.Session;

pub const DbEntry = struct {
    path: []const u8,
    arch: []const u8,
    commit_sha: []const u8,
    db: sqlite.Db,
};

pub const Registry = struct {
    gpa: std.mem.Allocator,
    dbs: std.ArrayList(DbEntry),
    /// Path to the gdb binary; defaults to "gdb" on PATH.
    gdb_path: []const u8,
    /// At most one live session. Owned by the registry.
    session: ?*Session = null,

    pub fn init(gpa: std.mem.Allocator) Registry {
        return .{ .gpa = gpa, .dbs = .{}, .gdb_path = "gdb" };
    }

    pub fn deinit(self: *Registry) void {
        if (self.session) |s| {
            s.close();
            self.session = null;
        }
        for (self.dbs.items) |*e| {
            self.gpa.free(e.path);
            self.gpa.free(e.arch);
            self.gpa.free(e.commit_sha);
            e.db.close();
        }
        self.dbs.deinit(self.gpa);
    }

    pub fn addDb(self: *Registry, path: []const u8) !void {
        var db = try sqlite.Db.openReadOnly(path, self.gpa);
        errdefer db.close();
        const arch = try metaValue(&db, self.gpa, "arch");
        errdefer self.gpa.free(arch);
        const sha = try metaValue(&db, self.gpa, "commit_sha");
        errdefer self.gpa.free(sha);
        try self.dbs.append(self.gpa, .{
            .path = try self.gpa.dupe(u8, path),
            .arch = arch,
            .commit_sha = sha,
            .db = db,
        });
    }

    pub fn pick(self: *Registry, arch: ?[]const u8) ?*DbEntry {
        if (self.dbs.items.len == 0) return null;
        if (arch) |a| {
            for (self.dbs.items) |*e| {
                if (std.mem.eql(u8, e.arch, a)) return e;
            }
        }
        return &self.dbs.items[0];
    }

    pub fn dispatch(
        self: *Registry,
        al: std.mem.Allocator,
        tool: []const u8,
        args: std.json.Value,
        out: *std.ArrayList(u8),
    ) !bool {
        if (std.mem.eql(u8, tool, "gdb_status")) {
            try self.toolStatus(al, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "gdb_start")) {
            try self.toolStart(al, args, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "gdb_end")) {
            try self.toolEnd(al, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "gdb_raw")) {
            try self.toolRaw(al, args, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "gdb_set_kaslr")) {
            try self.toolSetKaslr(al, args, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "gdb_resolve")) {
            try self.toolResolve(al, args, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "gdb_break")) {
            try self.toolBreak(al, args, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "gdb_break_clear")) {
            try self.toolBreakClear(al, args, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "gdb_break_list")) {
            try self.toolBreakList(al, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "gdb_continue")) {
            try self.toolContinue(al, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "gdb_step")) {
            try self.toolExec(al, "-exec-step", 30_000, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "gdb_step_instruction")) {
            try self.toolExec(al, "-exec-step-instruction", 30_000, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "gdb_next")) {
            try self.toolExec(al, "-exec-next", 30_000, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "gdb_finish")) {
            try self.toolExec(al, "-exec-finish", 30_000, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "gdb_reset")) {
            try self.toolReset(al, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "gdb_verify")) {
            try self.toolVerify(al, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "gdb_interrupt")) {
            try self.toolInterrupt(al, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "gdb_pc")) {
            try self.toolPc(al, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "gdb_args")) {
            try self.toolArgs(al, args, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "gdb_regs")) {
            try self.toolRegs(al, args, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "gdb_read_mem")) {
            try self.toolReadMem(al, args, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "gdb_backtrace")) {
            try self.toolBacktrace(al, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "gdb_disasm")) {
            try self.toolDisasm(al, args, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "gdb_resolve_field")) {
            try self.toolResolveField(al, args, out);
            return true;
        }
        if (std.mem.eql(u8, tool, "gdb_read_var")) {
            try self.toolReadVar(al, args, out);
            return true;
        }
        return false;
    }

    // ---------------------------------------------------------- DB lookups

    /// Look up a Zig qualified name in the callgraph DB and return the
    /// link-time address from bin_symbol. Returns null on miss.
    /// Caller adds Session.kaslr_offset to get runtime addr.
    fn resolveSymbol(self: *Registry, qname: []const u8) ?u64 {
        const entry = self.pick(null) orelse return null;
        var stmt = entry.db.prepare(
            \\SELECT bs.addr, bs.size FROM bin_symbol bs
            \\JOIN entity e ON e.id = bs.entity_id
            \\WHERE e.qualified_name = ?
            \\LIMIT 1
        , self.gpa) catch return null;
        defer stmt.finalize();
        stmt.bindText(1, qname) catch return null;
        const has = stmt.step() catch return null;
        if (!has) return null;
        const addr_signed = stmt.columnInt(0);
        return @bitCast(addr_signed);
    }

    fn resolveSymbolWithSize(self: *Registry, qname: []const u8) ?struct { addr: u64, size: u64 } {
        const entry = self.pick(null) orelse return null;
        var stmt = entry.db.prepare(
            \\SELECT bs.addr, bs.size FROM bin_symbol bs
            \\JOIN entity e ON e.id = bs.entity_id
            \\WHERE e.qualified_name = ?
            \\LIMIT 1
        , self.gpa) catch return null;
        defer stmt.finalize();
        stmt.bindText(1, qname) catch return null;
        const has = stmt.step() catch return null;
        if (!has) return null;
        return .{
            .addr = @bitCast(stmt.columnInt(0)),
            .size = @bitCast(stmt.columnInt(1)),
        };
    }

    /// Check whether the gdb-loaded ELF agrees with the callgraph DB on
    /// link-time symbol addresses. For each sentinel from `entry_point`,
    /// we ask gdb `info address <qname>` and compare to bin_symbol.addr.
    /// Returns a one-paragraph human-readable verdict.
    fn verifyDbFreshness(
        self: *Registry,
        al: std.mem.Allocator,
        session: *Session,
    ) ![]const u8 {
        const entry = self.pick(null) orelse return "[verify] no DB loaded — skipping freshness check\n";

        // Pull up to 3 sentinels: entry-point functions (stable, well-named).
        var stmt = entry.db.prepare(
            \\SELECT e.qualified_name, bs.addr FROM bin_symbol bs
            \\JOIN entity e ON e.id = bs.entity_id
            \\JOIN entry_point ep ON ep.entity_id = e.id
            \\WHERE bs.section = '.text'
            \\ORDER BY bs.addr
            \\LIMIT 3
        , self.gpa) catch |err| {
            return try std.fmt.allocPrint(al, "[verify] sentinel query failed: {s}\n", .{@errorName(err)});
        };
        defer stmt.finalize();

        var w: std.io.Writer.Allocating = .init(al);
        defer w.deinit();

        var checked: usize = 0;
        var matches: usize = 0;
        var first_delta: ?i64 = null;
        var consistent: bool = true;

        while (try stmt.step()) {
            const qname_borrowed = stmt.columnText(0) orelse continue;
            const qname = try al.dupe(u8, qname_borrowed);
            const link_addr_signed = stmt.columnInt(1);
            const link_addr: u64 = @bitCast(link_addr_signed);

            const cmd = try std.fmt.allocPrint(al, "-interpreter-exec console \"info address {s}\"", .{qname});
            const resp = session.run(al, cmd) catch |err| {
                try w.writer.print("[verify]   {s}: gdb run err {s}\n", .{ qname, @errorName(err) });
                continue;
            };
            const gdb_addr = parseInfoAddressLine(resp.console) orelse {
                try w.writer.print("[verify]   {s}: gdb couldn't resolve\n", .{qname});
                continue;
            };
            checked += 1;
            const delta: i64 = @bitCast(gdb_addr -% link_addr);
            if (first_delta) |fd| {
                if (fd != delta) consistent = false;
            } else {
                first_delta = delta;
            }
            if (delta == 0) matches += 1;
            try w.writer.print("[verify]   {s}: db=0x{x} gdb=0x{x} delta=0x{x}\n", .{ qname, link_addr, gdb_addr, @as(u64, @bitCast(delta)) });
        }

        if (checked == 0) {
            try w.writer.writeAll("[verify] no sentinels could be checked — DB freshness unknown\n");
        } else if (consistent and (first_delta orelse 0) == 0) {
            try w.writer.print("[verify] OK — DB matches loaded ELF on {d}/{d} sentinels\n", .{ matches, checked });
        } else if (consistent) {
            try w.writer.print("[verify] DB is fresh but ELF is rebased by 0x{x} (consistent across {d} sentinels — likely KASLR or add-symbol-file). Consider gdb_set_kaslr.\n", .{ @as(u64, @bitCast(first_delta orelse 0)), checked });
        } else {
            try w.writer.print("[verify] WARNING: DB↔ELF deltas inconsistent across {d} sentinels. DB is STALE — re-run `zig build index -Demit_index=true`. Symbol-name resolution will return wrong addresses.\n", .{checked});
        }
        return try al.dupe(u8, w.written());
    }

    /// If `qname` names a function whose return type is > 16 bytes
    /// (sret on x86_64), return the return-type qname + size. Otherwise
    /// null. Used to flag frames where gdb's `args=[...]` mis-identifies
    /// arguments because Zig pushes the sret pointer into %rdi and shifts
    /// real args right.
    fn lookupSretReturn(
        self: *Registry,
        al: std.mem.Allocator,
        qname: []const u8,
    ) !?struct { type_qname: []const u8, size: i64 } {
        const entry = self.pick(null) orelse return null;
        var stmt = entry.db.prepare(
            \\SELECT e2.qualified_name, t.size
            \\FROM entity e
            \\JOIN entity_type_ref ref ON ref.referrer_entity_id = e.id AND ref.role = 'return_type'
            \\JOIN entity e2 ON e2.id = ref.referred_entity_id
            \\JOIN type t ON t.entity_id = e2.id
            \\WHERE e.kind = 'fn' AND e.qualified_name = ?
            \\LIMIT 1
        , self.gpa) catch return null;
        defer stmt.finalize();
        try stmt.bindText(1, qname);
        if (!try stmt.step()) return null;
        const sz = stmt.columnInt(1);
        if (sz <= 16) return null;
        const ty = stmt.columnText(0) orelse return null;
        return .{ .type_qname = try al.dupe(u8, ty), .size = sz };
    }

    /// Append a Zig-sret diagnostic block when `func_qname` is sret-returning.
    /// Reads %rdi/%rsi/%rdx/%rcx/%r8/%r9 and surfaces them with sret-aware
    /// labels. No-op if the func isn't sret or regs can't be read.
    fn augmentSretFrame(
        self: *Registry,
        al: std.mem.Allocator,
        session: *Session,
        func_qname: []const u8,
        out: *std.ArrayList(u8),
    ) !void {
        const sret = (try self.lookupSretReturn(al, func_qname)) orelse return;

        const regs = [_][]const u8{ "$rdi", "$rsi", "$rdx", "$rcx", "$r8", "$r9" };
        var vals: [6]?u64 = .{ null, null, null, null, null, null };
        for (regs, 0..) |r, i| {
            const cmd = try std.fmt.allocPrint(al, "-data-evaluate-expression \"(unsigned long long){s}\"", .{r});
            const resp = session.run(al, cmd) catch continue;
            if (!std.mem.eql(u8, resp.class, "done")) continue;
            // payload like: value="0xff..."
            vals[i] = parseEvalValue(resp.payload);
        }

        try std.fmt.format(out.writer(al), "[zig-sret] {s} returns {s} (size {d}); gdb's args=[...] is unreliable. Reading regs:\n", .{
            func_qname, sret.type_qname, sret.size,
        });
        const rdi_label = "rdi (sret slot)";
        const rsi_label = "rsi";
        const rdx_label = "rdx (arg0?)";
        const rcx_label = "rcx (arg1?)";
        const r8_label = "r8  (arg2?)";
        const r9_label = "r9  (arg3?)";
        const labels = [_][]const u8{ rdi_label, rsi_label, rdx_label, rcx_label, r8_label, r9_label };
        for (vals, labels) |v, l| {
            if (v) |x| {
                try std.fmt.format(out.writer(al), "  {s} = 0x{x}\n", .{ l, x });
            } else {
                try std.fmt.format(out.writer(al), "  {s} = <unread>\n", .{l});
            }
        }
        try out.appendSlice(al, "  Note: Zig's >16-byte-return ABI passes sret in %rdi; the first real arg is observed at %rdx (not %rsi). Verify by signature.\n");
    }

    /// Resolve `type` table row for a type qname → (type_id, size).
    fn resolveType(self: *Registry, type_qname: []const u8) ?struct { id: i64, size: i64 } {
        const entry = self.pick(null) orelse return null;
        var stmt = entry.db.prepare(
            \\SELECT t.id, COALESCE(t.size, 0) FROM type t
            \\JOIN entity e ON e.id = t.entity_id
            \\WHERE e.qualified_name = ?
            \\LIMIT 1
        , self.gpa) catch return null;
        defer stmt.finalize();
        stmt.bindText(1, type_qname) catch return null;
        const has = stmt.step() catch return null;
        if (!has) return null;
        return .{ .id = stmt.columnInt(0), .size = stmt.columnInt(1) };
    }

    /// Walk a dotted field path through type_field, accumulating offsets.
    /// Returns total_offset + leaf_size on success; logs the failure spot
    /// to `out` on miss.
    fn resolveFieldPath(
        self: *Registry,
        al: std.mem.Allocator,
        type_qname: []const u8,
        path_dotted: []const u8,
        out: *std.ArrayList(u8),
    ) !?struct { offset: i64, size: i64 } {
        const entry = self.pick(null) orelse return null;
        const root = self.resolveType(type_qname) orelse {
            try std.fmt.format(out.writer(al), "error: type `{s}` not found in `type` table\n", .{type_qname});
            return null;
        };

        var current_type_id: i64 = root.id;
        var current_size: i64 = root.size;
        var total_offset: i64 = 0;

        var it = std.mem.splitScalar(u8, path_dotted, '.');
        while (it.next()) |raw| {
            const field = std.mem.trim(u8, raw, " \t");
            if (field.len == 0) continue;

            var stmt = entry.db.prepare(
                \\SELECT tf.offset, tf.type_ref, COALESCE(t2.size, 0) FROM type_field tf
                \\LEFT JOIN type t2 ON t2.id = tf.type_ref
                \\WHERE tf.type_id = ? AND tf.name = ?
                \\LIMIT 1
            , self.gpa) catch return null;
            defer stmt.finalize();
            try stmt.bindInt(1, current_type_id);
            try stmt.bindText(2, field);
            const has = try stmt.step();
            if (!has) {
                try std.fmt.format(out.writer(al), "error: field `{s}` not found on type id={d}\n", .{ field, current_type_id });
                return null;
            }
            const off = stmt.columnInt(0);
            const ref = stmt.columnInt(1);
            const ref_size = stmt.columnInt(2);
            total_offset += off;
            if (ref != 0) {
                current_type_id = ref;
                current_size = ref_size;
            } else {
                // No type_ref recorded — leaf with unknown size. Caller can
                // override with `len`.
                current_size = 0;
            }
        }
        return .{ .offset = total_offset, .size = current_size };
    }

    // ------------------------------------------------------------------ tools

    fn toolStatus(self: *Registry, al: std.mem.Allocator, out: *std.ArrayList(u8)) !void {
        var w: std.io.Writer.Allocating = .init(al);
        defer w.deinit();
        if (self.session) |s| {
            try w.writer.writeAll("session: active\n");
            try w.writer.print("elf: {s}\n", .{s.elf_path});
            if (s.target) |t| try w.writer.print("target: {s}\n", .{t});
            if (s.kaslr_offset) |off| {
                try w.writer.print("kaslr_offset: 0x{x}\n", .{@as(u64, @bitCast(off))});
            } else {
                try w.writer.writeAll("kaslr_offset: <not computed>\n");
            }
        } else {
            try w.writer.writeAll("session: none\n");
        }
        try w.writer.print("gdb: {s}\n", .{self.gdb_path});
        try w.writer.print("dbs: {d}\n", .{self.dbs.items.len});
        for (self.dbs.items) |*e| {
            try w.writer.print("  {s} arch={s} commit={s}\n", .{ e.path, e.arch, e.commit_sha });
        }
        try out.appendSlice(al, w.written());
    }

    fn toolStart(
        self: *Registry,
        al: std.mem.Allocator,
        args: std.json.Value,
        out: *std.ArrayList(u8),
    ) !void {
        if (self.session != null) {
            try out.appendSlice(al, "error: session already active; call gdb_end first\n");
            return;
        }
        const elf_v = (args.object.get("elf") orelse {
            try out.appendSlice(al, "error: missing required arg `elf`\n");
            return;
        });
        if (elf_v != .string) {
            try out.appendSlice(al, "error: `elf` must be a string\n");
            return;
        }
        const target = blk: {
            if (args.object.get("target")) |v| {
                if (v == .string) break :blk v.string;
            }
            break :blk ":1234";
        };
        const skip_target = std.mem.eql(u8, target, "none");

        const session = Session.spawn(self.gpa, self.gdb_path, elf_v.string) catch |err| {
            try std.fmt.format(out.writer(al), "error: spawn failed: {s}\n", .{@errorName(err)});
            return;
        };
        errdefer {
            session.close();
        }

        var tgt_console: []const u8 = "";
        if (!skip_target) {
            const target_cmd = try std.fmt.allocPrint(
                al,
                "-target-select remote {s}",
                .{target},
            );
            const tgt_resp = session.run(al, target_cmd) catch |err| {
                try std.fmt.format(out.writer(al), "error: target-select failed: {s}\n", .{@errorName(err)});
                session.close();
                self.session = null;
                return;
            };
            if (!std.mem.eql(u8, tgt_resp.class, "connected") and
                !std.mem.eql(u8, tgt_resp.class, "done"))
            {
                try std.fmt.format(out.writer(al), "error: target-select returned class={s} payload={s}\n", .{
                    tgt_resp.class, tgt_resp.payload,
                });
                session.close();
                return;
            }
            session.target = try self.gpa.dupe(u8, target);
            tgt_console = tgt_resp.console;
        }

        self.session = session;

        var w: std.io.Writer.Allocating = .init(al);
        defer w.deinit();
        try w.writer.print("session started\nelf: {s}\ntarget: {s}\n", .{
            elf_v.string, target,
        });
        if (tgt_console.len > 0) {
            try w.writer.writeAll("--- gdb console ---\n");
            try w.writer.writeAll(tgt_console);
        }
        // DB↔ELF freshness check — quietly cheap (3 short MI calls).
        const verdict = self.verifyDbFreshness(al, session) catch |err| blk: {
            break :blk std.fmt.allocPrint(al, "[verify] check failed: {s}\n", .{@errorName(err)}) catch "[verify] check failed\n";
        };
        try w.writer.writeAll(verdict);
        try out.appendSlice(al, w.written());
    }

    fn toolVerify(self: *Registry, al: std.mem.Allocator, out: *std.ArrayList(u8)) !void {
        const session = self.session orelse {
            try out.appendSlice(al, "error: no active session\n");
            return;
        };
        const verdict = try self.verifyDbFreshness(al, session);
        try out.appendSlice(al, verdict);
    }

    fn toolEnd(self: *Registry, al: std.mem.Allocator, out: *std.ArrayList(u8)) !void {
        if (self.session) |s| {
            s.close();
            self.session = null;
            try out.appendSlice(al, "session ended\n");
        } else {
            try out.appendSlice(al, "no active session\n");
        }
    }

    fn toolSetKaslr(
        self: *Registry,
        al: std.mem.Allocator,
        args: std.json.Value,
        out: *std.ArrayList(u8),
    ) !void {
        const session = self.session orelse {
            try out.appendSlice(al, "error: no active session\n");
            return;
        };
        const off_v = argString(args, "offset") orelse {
            try out.appendSlice(al, "error: missing required string arg `offset` (hex like 0xff... or decimal)\n");
            return;
        };
        const off = parseSignedAddr(off_v) catch {
            try std.fmt.format(out.writer(al), "error: bad offset: {s}\n", .{off_v});
            return;
        };
        session.kaslr_offset = off;
        try std.fmt.format(out.writer(al), "kaslr_offset set to 0x{x}\n", .{@as(u64, @bitCast(off))});
    }

    fn toolResolve(
        self: *Registry,
        al: std.mem.Allocator,
        args: std.json.Value,
        out: *std.ArrayList(u8),
    ) !void {
        const name = argString(args, "name") orelse {
            try out.appendSlice(al, "error: missing required arg `name`\n");
            return;
        };
        const offset: i64 = if (self.session) |s| (s.kaslr_offset orelse 0) else 0;
        const hit = self.resolveSymbolWithSize(name) orelse {
            try std.fmt.format(out.writer(al), "no match for {s} in bin_symbol\n", .{name});
            return;
        };
        const link_addr: i64 = @bitCast(hit.addr);
        const runtime_addr: u64 = @bitCast(link_addr + offset);
        try std.fmt.format(out.writer(al), "name: {s}\nlink_addr: 0x{x}\nsize: {d}\nkaslr_offset: 0x{x}\nruntime_addr: 0x{x}\n", .{
            name, hit.addr, hit.size, @as(u64, @bitCast(offset)), runtime_addr,
        });
    }

    fn toolBreak(
        self: *Registry,
        al: std.mem.Allocator,
        args: std.json.Value,
        out: *std.ArrayList(u8),
    ) !void {
        const session = self.session orelse {
            try out.appendSlice(al, "error: no active session\n");
            return;
        };
        const at = argString(args, "at") orelse {
            try out.appendSlice(al, "error: missing required arg `at` (file:line, addr like 0x..., or qualified Zig name)\n");
            return;
        };
        const hardware = argBool(args, "hardware") orelse false;

        // Build the -break-insert command.
        // - file:line goes through unchanged
        // - 0x... is an explicit address (-> *0x...)
        // - otherwise treat as qname; resolve via DB and use *0x<runtime_addr>
        const target_str = blk: {
            if (std.mem.indexOfScalar(u8, at, ':') != null) break :blk try std.fmt.allocPrint(al, "{s}", .{at});
            if (std.mem.startsWith(u8, at, "0x") or std.mem.startsWith(u8, at, "0X")) {
                break :blk try std.fmt.allocPrint(al, "*{s}", .{at});
            }
            // Treat as qualified Zig name.
            const link_addr_u = self.resolveSymbol(at) orelse {
                try std.fmt.format(out.writer(al), "error: cannot resolve `{s}` via callgraph DB. Try file:line, an explicit 0x... address, or use gdb_raw.\n", .{at});
                return;
            };
            const link_addr: i64 = @bitCast(link_addr_u);
            const runtime: u64 = @bitCast(link_addr + (session.kaslr_offset orelse 0));
            break :blk try std.fmt.allocPrint(al, "*0x{x}", .{runtime});
        };

        const cmd = if (hardware)
            try std.fmt.allocPrint(al, "-break-insert -h {s}", .{target_str})
        else
            try std.fmt.allocPrint(al, "-break-insert {s}", .{target_str});

        const resp = session.run(al, cmd) catch |err| {
            try std.fmt.format(out.writer(al), "error: gdb run failed: {s} — session torn down, call gdb_start to retry\n", .{@errorName(err)});
            self.killSession();
            return;
        };
        try writeResp(al, out, resp);
    }

    fn toolBreakClear(
        self: *Registry,
        al: std.mem.Allocator,
        args: std.json.Value,
        out: *std.ArrayList(u8),
    ) !void {
        const session = self.session orelse {
            try out.appendSlice(al, "error: no active session\n");
            return;
        };
        const id_str = argString(args, "id") orelse {
            try out.appendSlice(al, "error: missing required arg `id` (number, or \"all\")\n");
            return;
        };
        const cmd = if (std.mem.eql(u8, id_str, "all"))
            try std.fmt.allocPrint(al, "-break-delete", .{})
        else
            try std.fmt.allocPrint(al, "-break-delete {s}", .{id_str});
        const resp = session.run(al, cmd) catch |err| {
            try std.fmt.format(out.writer(al), "error: gdb run failed: {s} — session torn down, call gdb_start to retry\n", .{@errorName(err)});
            self.killSession();
            return;
        };
        try writeResp(al, out, resp);
    }

    fn toolBreakList(self: *Registry, al: std.mem.Allocator, out: *std.ArrayList(u8)) !void {
        const session = self.session orelse {
            try out.appendSlice(al, "error: no active session\n");
            return;
        };
        const resp = session.run(al, "-break-list") catch |err| {
            try std.fmt.format(out.writer(al), "error: gdb run failed: {s} — session torn down, call gdb_start to retry\n", .{@errorName(err)});
            self.killSession();
            return;
        };
        try writeResp(al, out, resp);
    }

    fn toolExec(
        self: *Registry,
        al: std.mem.Allocator,
        mi_cmd: []const u8,
        wait_timeout_ms: i32,
        out: *std.ArrayList(u8),
    ) !void {
        const session = self.session orelse {
            try out.appendSlice(al, "error: no active session\n");
            return;
        };
        const resp = session.run(al, mi_cmd) catch |err| {
            try std.fmt.format(out.writer(al), "error: gdb run failed: {s} — session torn down, call gdb_start to retry\n", .{@errorName(err)});
            self.killSession();
            return;
        };
        if (std.mem.eql(u8, resp.class, "running")) {
            const stop = session.waitForStop(al, wait_timeout_ms) catch |err| {
                try std.fmt.format(out.writer(al), "ran but waitForStop failed: {s}\n", .{@errorName(err)});
                if (err == gdb_session.Error.Timeout) {
                    try out.appendSlice(al, "no stop within timeout — session may be stuck. Try gdb_reset.\n");
                } else {
                    self.killSession();
                }
                return;
            };
            try out.appendSlice(al, "stopped: ");
            try out.appendSlice(al, stop.payload);
            try out.append(al, '\n');
            if (stop.extra.len > 0) {
                try out.appendSlice(al, "--- extra ---\n");
                try out.appendSlice(al, stop.extra);
            }
            if (parseFuncName(al, stop.payload)) |func| {
                self.augmentSretFrame(al, session, func, out) catch {};
            }
        } else {
            try writeResp(al, out, resp);
        }
    }

    /// gdb_continue with recovery: if the kernel doesn't stop within 60s
    /// (no breakpoint, free-running), inject -exec-interrupt and report.
    fn toolContinue(self: *Registry, al: std.mem.Allocator, out: *std.ArrayList(u8)) !void {
        const session = self.session orelse {
            try out.appendSlice(al, "error: no active session\n");
            return;
        };
        const resp = session.run(al, "-exec-continue") catch |err| {
            try std.fmt.format(out.writer(al), "error: -exec-continue failed: {s} — session torn down\n", .{@errorName(err)});
            self.killSession();
            return;
        };
        if (!std.mem.eql(u8, resp.class, "running")) {
            try writeResp(al, out, resp);
            return;
        }
        const stop = session.waitForStop(al, 60_000) catch |err| {
            if (err != gdb_session.Error.Timeout) {
                try std.fmt.format(out.writer(al), "waitForStop failed: {s} — session torn down\n", .{@errorName(err)});
                self.killSession();
                return;
            }
            // 60s with no stop. Inject an interrupt and report.
            try out.appendSlice(al, "no stop within 60s; kernel free-running. Sending -exec-interrupt.\n");
            const irq = session.run(al, "-exec-interrupt --all") catch |e| {
                try std.fmt.format(out.writer(al), "interrupt failed: {s} — session torn down\n", .{@errorName(e)});
                self.killSession();
                return;
            };
            _ = irq;
            const stop2 = session.waitForStop(al, 5_000) catch |e| {
                try std.fmt.format(out.writer(al), "interrupt issued but no stop within 5s: {s}. Try gdb_reset.\n", .{@errorName(e)});
                return;
            };
            try out.appendSlice(al, "stopped (after interrupt): ");
            try out.appendSlice(al, stop2.payload);
            try out.append(al, '\n');
            return;
        };
        try out.appendSlice(al, "stopped: ");
        try out.appendSlice(al, stop.payload);
        try out.append(al, '\n');
        if (stop.extra.len > 0) {
            try out.appendSlice(al, "--- extra ---\n");
            try out.appendSlice(al, stop.extra);
        }
        if (parseFuncName(al, stop.payload)) |func| {
            self.augmentSretFrame(al, session, func, out) catch {};
        }
    }

    fn toolReset(self: *Registry, al: std.mem.Allocator, out: *std.ArrayList(u8)) !void {
        if (self.session != null) {
            self.killSession();
            try out.appendSlice(al, "killed active session\n");
        } else {
            try out.appendSlice(al, "no active session\n");
        }
        // Best-effort cleanup of any orphan gdb processes spawned by a
        // previous gdb_mcp instance that died ungracefully (sigkill,
        // crashed Claude Code session, etc.).
        const orphans_killed = pkillOrphanGdbs(al, "/home/alec/Stygia/zig-out/bin/kernel.elf");
        try std.fmt.format(out.writer(al), "orphan gdb processes killed: {d}\n", .{orphans_killed});
    }

    /// Kill the active session and clear the registry slot. Safe to call
    /// when self.session is null.
    fn killSession(self: *Registry) void {
        if (self.session) |s| {
            s.close();
            self.session = null;
        }
    }

    fn toolInterrupt(self: *Registry, al: std.mem.Allocator, out: *std.ArrayList(u8)) !void {
        const session = self.session orelse {
            try out.appendSlice(al, "error: no active session\n");
            return;
        };
        const resp = session.run(al, "-exec-interrupt --all") catch |err| {
            try std.fmt.format(out.writer(al), "error: gdb run failed: {s} — session torn down, call gdb_start to retry\n", .{@errorName(err)});
            self.killSession();
            return;
        };
        // Interrupt is async; gdb returns ^done and we expect a *stopped soon.
        try writeResp(al, out, resp);
        const stop = session.waitForStop(al, 2000) catch |err| {
            try std.fmt.format(out.writer(al), "interrupt sent but no stop within 2s: {s}\n", .{@errorName(err)});
            return;
        };
        try out.appendSlice(al, "stopped: ");
        try out.appendSlice(al, stop.payload);
        try out.append(al, '\n');
    }

    fn toolPc(self: *Registry, al: std.mem.Allocator, out: *std.ArrayList(u8)) !void {
        const session = self.session orelse {
            try out.appendSlice(al, "error: no active session\n");
            return;
        };
        const resp = session.run(al, "-stack-info-frame") catch |err| {
            try std.fmt.format(out.writer(al), "error: gdb run failed: {s} — session torn down, call gdb_start to retry\n", .{@errorName(err)});
            self.killSession();
            return;
        };
        try writeResp(al, out, resp);
        if (parseFuncName(al, resp.payload)) |func| {
            self.augmentSretFrame(al, session, func, out) catch {};
        }
    }

    fn toolArgs(self: *Registry, al: std.mem.Allocator, args: std.json.Value, out: *std.ArrayList(u8)) !void {
        const session = self.session orelse {
            try out.appendSlice(al, "error: no active session\n");
            return;
        };
        // Optional explicit qname override; otherwise grab current frame's func.
        const explicit = argString(args, "name");
        const func: []const u8 = if (explicit) |q| q else blk: {
            const resp = session.run(al, "-stack-info-frame") catch |err| {
                try std.fmt.format(out.writer(al), "error: -stack-info-frame failed: {s}\n", .{@errorName(err)});
                self.killSession();
                return;
            };
            const fn_name = parseFuncName(al, resp.payload) orelse {
                try out.appendSlice(al, "error: couldn't parse func from current frame; pass `name` explicitly\n");
                return;
            };
            break :blk fn_name;
        };
        const sret = (try self.lookupSretReturn(al, func)) orelse {
            try std.fmt.format(out.writer(al), "{s}: not sret (return type ≤ 16 bytes or unknown). gdb's args=[...] should be reliable.\n", .{func});
            return;
        };
        _ = sret;
        try self.augmentSretFrame(al, session, func, out);
    }

    fn toolRegs(
        self: *Registry,
        al: std.mem.Allocator,
        args: std.json.Value,
        out: *std.ArrayList(u8),
    ) !void {
        const session = self.session orelse {
            try out.appendSlice(al, "error: no active session\n");
            return;
        };
        const fmt = argString(args, "format") orelse "x";
        const cmd = try std.fmt.allocPrint(al, "-data-list-register-values {s}", .{fmt});
        const resp = session.run(al, cmd) catch |err| {
            try std.fmt.format(out.writer(al), "error: gdb run failed: {s} — session torn down, call gdb_start to retry\n", .{@errorName(err)});
            self.killSession();
            return;
        };
        try writeResp(al, out, resp);
    }

    fn toolReadMem(
        self: *Registry,
        al: std.mem.Allocator,
        args: std.json.Value,
        out: *std.ArrayList(u8),
    ) !void {
        const session = self.session orelse {
            try out.appendSlice(al, "error: no active session\n");
            return;
        };
        const addr_v = argString(args, "addr") orelse {
            try out.appendSlice(al, "error: missing required arg `addr`\n");
            return;
        };
        const len_v = argInt(args, "len") orelse {
            try out.appendSlice(al, "error: missing required integer arg `len`\n");
            return;
        };
        const cmd = try std.fmt.allocPrint(al, "-data-read-memory-bytes {s} {d}", .{ addr_v, len_v });
        const resp = session.run(al, cmd) catch |err| {
            try std.fmt.format(out.writer(al), "error: gdb run failed: {s} — session torn down, call gdb_start to retry\n", .{@errorName(err)});
            self.killSession();
            return;
        };
        try writeResp(al, out, resp);
    }

    fn toolBacktrace(self: *Registry, al: std.mem.Allocator, out: *std.ArrayList(u8)) !void {
        const session = self.session orelse {
            try out.appendSlice(al, "error: no active session\n");
            return;
        };
        const resp = session.run(al, "-stack-list-frames") catch |err| {
            try std.fmt.format(out.writer(al), "error: gdb run failed: {s} — session torn down, call gdb_start to retry\n", .{@errorName(err)});
            self.killSession();
            return;
        };
        try writeResp(al, out, resp);
    }

    fn toolDisasm(
        self: *Registry,
        al: std.mem.Allocator,
        args: std.json.Value,
        out: *std.ArrayList(u8),
    ) !void {
        const session = self.session orelse {
            try out.appendSlice(al, "error: no active session\n");
            return;
        };
        const at = argString(args, "at"); // optional; if null, disasm at $pc
        const count = argInt(args, "count") orelse 16;
        const cmd = if (at) |a| blk: {
            // Disassemble [a, a+count*8) bytes, mode 0 (raw insns, no source).
            // We approximate "count instructions" by allocating ~8 bytes each.
            const end = try std.fmt.allocPrint(al, "{s}+{d}", .{ a, count * 8 });
            break :blk try std.fmt.allocPrint(al, "-data-disassemble -s {s} -e {s} -- 0", .{ a, end });
        } else try std.fmt.allocPrint(al, "-data-disassemble -s $pc -e $pc+{d} -- 0", .{count * 8});
        const resp = session.run(al, cmd) catch |err| {
            try std.fmt.format(out.writer(al), "error: gdb run failed: {s} — session torn down, call gdb_start to retry\n", .{@errorName(err)});
            self.killSession();
            return;
        };
        try writeResp(al, out, resp);
    }

    fn toolResolveField(
        self: *Registry,
        al: std.mem.Allocator,
        args: std.json.Value,
        out: *std.ArrayList(u8),
    ) !void {
        const ty = argString(args, "type") orelse {
            try out.appendSlice(al, "error: missing required arg `type` (type qualified name)\n");
            return;
        };
        const field = argString(args, "field") orelse {
            try out.appendSlice(al, "error: missing required arg `field` (dotted path like `current_ec` or `run_queue.head`)\n");
            return;
        };
        const result = (try self.resolveFieldPath(al, ty, field, out)) orelse return;
        try std.fmt.format(out.writer(al), "type: {s}\nfield: {s}\noffset: {d} (0x{x})\nleaf_size: {d}\n", .{
            ty, field, result.offset, @as(u64, @bitCast(result.offset)), result.size,
        });
    }

    fn toolReadVar(
        self: *Registry,
        al: std.mem.Allocator,
        args: std.json.Value,
        out: *std.ArrayList(u8),
    ) !void {
        const session = self.session orelse {
            try out.appendSlice(al, "error: no active session\n");
            return;
        };
        const name = argString(args, "name") orelse {
            try out.appendSlice(al, "error: missing required arg `name` (variable qualified name)\n");
            return;
        };
        const ty = argString(args, "type"); // optional: element type for array/struct walks
        const field = argString(args, "field"); // optional: dotted field path
        const array_idx = argInt(args, "array_index"); // optional
        const len_override = argInt(args, "len");

        const sym = self.resolveSymbolWithSize(name) orelse {
            try std.fmt.format(out.writer(al), "error: variable `{s}` not in bin_symbol\n", .{name});
            return;
        };
        var offset: i64 = 0;
        var size: i64 = @bitCast(sym.size);

        if (array_idx) |idx| {
            const t = ty orelse {
                try out.appendSlice(al, "error: `array_index` requires `type` (element type qualified name)\n");
                return;
            };
            const t_row = self.resolveType(t) orelse {
                try std.fmt.format(out.writer(al), "error: element type `{s}` not in `type` table\n", .{t});
                return;
            };
            offset += idx * t_row.size;
            size = t_row.size;
        }

        if (field) |f| {
            const t = ty orelse {
                try out.appendSlice(al, "error: `field` requires `type` (struct type qualified name)\n");
                return;
            };
            const fp = (try self.resolveFieldPath(al, t, f, out)) orelse return;
            offset += fp.offset;
            size = fp.size;
        }

        if (len_override) |l| size = l;
        if (size <= 0) {
            try out.appendSlice(al, "error: resolved size is 0 — pass `len` to override\n");
            return;
        }

        const link_addr: i64 = @bitCast(sym.addr);
        const runtime_addr: u64 = @bitCast(link_addr + offset + (session.kaslr_offset orelse 0));

        const cmd = try std.fmt.allocPrint(al, "-data-read-memory-bytes 0x{x} {d}", .{ runtime_addr, size });
        const resp = session.run(al, cmd) catch |err| {
            try std.fmt.format(out.writer(al), "error: gdb run failed: {s} — session torn down, call gdb_start to retry\n", .{@errorName(err)});
            self.killSession();
            return;
        };
        try std.fmt.format(out.writer(al), "name: {s}\n", .{name});
        if (ty) |t| try std.fmt.format(out.writer(al), "type: {s}\n", .{t});
        if (array_idx) |idx| try std.fmt.format(out.writer(al), "array_index: {d}\n", .{idx});
        if (field) |f| try std.fmt.format(out.writer(al), "field: {s}\n", .{f});
        try std.fmt.format(out.writer(al), "addr: 0x{x}\nsize: {d}\n", .{ runtime_addr, size });
        try writeResp(al, out, resp);
    }

    fn toolRaw(
        self: *Registry,
        al: std.mem.Allocator,
        args: std.json.Value,
        out: *std.ArrayList(u8),
    ) !void {
        const session = self.session orelse {
            try out.appendSlice(al, "error: no active session; call gdb_start first\n");
            return;
        };
        const cmd_v = args.object.get("cmd") orelse {
            try out.appendSlice(al, "error: missing required arg `cmd`\n");
            return;
        };
        if (cmd_v != .string) {
            try out.appendSlice(al, "error: `cmd` must be a string\n");
            return;
        }
        const resp = session.run(al, cmd_v.string) catch |err| {
            try std.fmt.format(out.writer(al), "error: gdb run failed: {s} — session torn down, call gdb_start to retry\n", .{@errorName(err)});
            self.killSession();
            return;
        };
        var w: std.io.Writer.Allocating = .init(al);
        defer w.deinit();
        try w.writer.print("class: {s}\n", .{resp.class});
        if (resp.payload.len > 0) try w.writer.print("payload: {s}\n", .{resp.payload});
        if (resp.console.len > 0) {
            try w.writer.writeAll("--- console ---\n");
            try w.writer.writeAll(resp.console);
        }
        if (resp.log.len > 0) {
            try w.writer.writeAll("--- log ---\n");
            try w.writer.writeAll(resp.log);
        }
        if (resp.async_records.len > 0) {
            try w.writer.writeAll("--- async ---\n");
            try w.writer.writeAll(resp.async_records);
        }
        try out.appendSlice(al, w.written());
    }
};

fn metaValue(db: *sqlite.Db, gpa: std.mem.Allocator, key: []const u8) ![]u8 {
    var stmt = try db.prepare("SELECT value FROM meta WHERE key=?", gpa);
    defer stmt.finalize();
    try stmt.bindText(1, key);
    if (!try stmt.step()) return gpa.dupe(u8, "");
    const v = stmt.columnText(0) orelse return gpa.dupe(u8, "");
    return gpa.dupe(u8, v);
}

// ---------------------------------------------------------- arg helpers

fn argString(args: std.json.Value, key: []const u8) ?[]const u8 {
    if (args != .object) return null;
    const v = args.object.get(key) orelse return null;
    if (v != .string) return null;
    return v.string;
}

fn argInt(args: std.json.Value, key: []const u8) ?i64 {
    if (args != .object) return null;
    const v = args.object.get(key) orelse return null;
    return switch (v) {
        .integer => |i| i,
        .string => |s| std.fmt.parseInt(i64, s, 0) catch null,
        else => null,
    };
}

fn argBool(args: std.json.Value, key: []const u8) ?bool {
    if (args != .object) return null;
    const v = args.object.get(key) orelse return null;
    return switch (v) {
        .bool => |b| b,
        else => null,
    };
}

/// Parse `0xff..` / `-0x..` / decimal as a signed 64-bit value (KASLR
/// offsets can be either positive or negative depending on link-time vs
/// runtime base ordering).
fn parseSignedAddr(s: []const u8) !i64 {
    if (std.mem.startsWith(u8, s, "-")) {
        const u = try std.fmt.parseInt(u64, s[1..], 0);
        return -@as(i64, @bitCast(u));
    }
    const u = try std.fmt.parseInt(u64, s, 0);
    return @bitCast(u);
}

/// Parse `value="..."` from a gdb -data-evaluate-expression payload.
/// Returns the integer if it looks like a hex / decimal literal.
fn parseEvalValue(payload: []const u8) ?u64 {
    const needle = "value=\"";
    const i = std.mem.indexOf(u8, payload, needle) orelse return null;
    const start = i + needle.len;
    const end_q = std.mem.indexOfScalarPos(u8, payload, start, '"') orelse return null;
    const slice = payload[start..end_q];
    if (std.mem.startsWith(u8, slice, "0x") or std.mem.startsWith(u8, slice, "0X")) {
        return std.fmt.parseInt(u64, slice[2..], 16) catch null;
    }
    return std.fmt.parseInt(u64, slice, 0) catch null;
}

/// Extract the `func="<name>"` value from a frame payload. Returns null on
/// missing/unparseable. Caller arena owns the returned slice.
fn parseFuncName(al: std.mem.Allocator, payload: []const u8) ?[]const u8 {
    const needle = "func=\"";
    const i = std.mem.indexOf(u8, payload, needle) orelse return null;
    const start = i + needle.len;
    const end_q = std.mem.indexOfScalarPos(u8, payload, start, '"') orelse return null;
    return al.dupe(u8, payload[start..end_q]) catch null;
}

/// Parse one line of gdb's `info address X` console output, e.g.:
///   `Symbol "X" is a function at address 0xffffffff8002e350.`
///   `Symbol "X" is static storage at address 0x...`
/// Returns null if no address is parseable.
fn parseInfoAddressLine(console: []const u8) ?u64 {
    const needle = "address 0x";
    const i = std.mem.indexOf(u8, console, needle) orelse return null;
    const j = i + needle.len;
    var end = j;
    while (end < console.len) : (end += 1) {
        const c = console[end];
        if (!((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F'))) break;
    }
    if (end == j) return null;
    return std.fmt.parseInt(u64, console[j..end], 16) catch null;
}

/// Walk /proc looking for gdb processes whose cmdline includes
/// `--interpreter=mi3` and the supplied ELF path; SIGKILL them. Skips
/// our own session's gdb (already torn down by killSession before this
/// runs). Returns the count of processes killed.
fn pkillOrphanGdbs(al: std.mem.Allocator, elf_path: []const u8) usize {
    var dir = std.fs.openDirAbsolute("/proc", .{ .iterate = true }) catch return 0;
    defer dir.close();
    var it = dir.iterate();
    var killed: usize = 0;
    const my_pid = std.os.linux.getpid();
    while (it.next() catch null) |entry| {
        if (entry.kind != .directory) continue;
        const pid = std.fmt.parseInt(i32, entry.name, 10) catch continue;
        if (pid == my_pid) continue;

        const cmdline_path = std.fmt.allocPrint(al, "/proc/{s}/cmdline", .{entry.name}) catch continue;
        defer al.free(cmdline_path);
        const file = std.fs.openFileAbsolute(cmdline_path, .{}) catch continue;
        defer file.close();
        var buf: [4096]u8 = undefined;
        const n = file.read(&buf) catch continue;
        const cmdline = buf[0..n];
        // /proc/PID/cmdline is NUL-separated; check substring presence.
        if (std.mem.indexOf(u8, cmdline, "--interpreter=mi3") == null) continue;
        if (std.mem.indexOf(u8, cmdline, elf_path) == null) continue;
        _ = std.posix.kill(pid, std.posix.SIG.KILL) catch continue;
        killed += 1;
    }
    return killed;
}

fn writeResp(
    al: std.mem.Allocator,
    out: *std.ArrayList(u8),
    resp: gdb_session.Response,
) !void {
    try std.fmt.format(out.writer(al), "class: {s}\n", .{resp.class});
    if (resp.payload.len > 0) try std.fmt.format(out.writer(al), "payload: {s}\n", .{resp.payload});
    if (resp.console.len > 0) {
        try out.appendSlice(al, "--- console ---\n");
        try out.appendSlice(al, resp.console);
    }
    if (resp.log.len > 0) {
        try out.appendSlice(al, "--- log ---\n");
        try out.appendSlice(al, resp.log);
    }
    if (resp.async_records.len > 0) {
        try out.appendSlice(al, "--- async ---\n");
        try out.appendSlice(al, resp.async_records);
    }
}
