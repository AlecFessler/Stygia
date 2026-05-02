const std = @import("std");
const sqlite = @import("sqlite.zig");
const types = @import("types.zig");

const FileRecord = types.FileRecord;
const ModuleRecord = types.ModuleRecord;
const TokenRow = types.TokenRow;
const ProvisionalEntity = types.ProvisionalEntity;

/// Batched write commands shipped over the channel from producers to the writer thread.
pub const Job = union(enum) {
    modules: []const ModuleRecord,
    files: []const FileRecord,
    file_line_index: struct { file_id: u32, byte_starts: []const u32 },
    tokens: struct { file_id: u32, rows: []const TokenRow },
    ast_nodes: []const types.AstNodeRow,
    ast_edges: []const types.AstEdgeRow,
    /// Final entity rows after stage 2.5 has assigned IDs.
    entities: []const FinalEntity,
    /// Update ast_node entity_id back-references after stage 2.5.
    ast_entity_backfill: []const AstEntityRef,
    ir_fns: []const types.IrFnRow,
    ir_calls: []const types.IrCallRow,
    bin_symbols: []const types.BinSymbolRow,
    bin_insts: []const types.BinInstRow,
    dwarf_lines: []const types.DwarfLineRow,
    dwarf_types: []const types.TypeRow,
    dwarf_type_fields: []const types.TypeFieldRow,
    dwarf_dies: []const types.DwarfDieRow,
    /// const_alias rows; pre-resolved (alias_id, target_id) pairs.
    const_aliases: []const ConstAliasRow,
    /// entity_type_ref rows; pre-resolved.
    type_refs: []const TypeRefRow,
    /// One-shot SQL string the writer executes verbatim. Caller must provide
    /// a null-terminated slice (use `palloc.dupeZ`). Used for UPDATE / INSERT
    /// passes (e.g. setting is_ast_only on the complement of ir_fn).
    raw_sql: [:0]const u8,
    /// Set a meta key.
    meta: struct { key: []const u8, value: []const u8 },
    /// Rebuild an FTS5 index after content tables are populated.
    fts_rebuild: []const u8, // virtual table name
    /// Owner is done writing; flush and exit.
    shutdown: void,
};

pub const ConstAliasRow = struct {
    entity_id: u32,
    target_entity_id: u32,
};

pub const TypeRefRow = struct {
    referrer_entity_id: u32,
    referred_entity_id: u32,
    role: []const u8,
};

pub const FinalEntity = struct {
    id: u32,
    kind: []const u8,
    qualified_name: []const u8,
    module_id: u32,
    def_file_id: u32,
    def_byte_start: u32,
    def_byte_end: u32,
    def_line: u32,
    def_col: u32,
    is_slab_backed: bool,
    is_pub: bool,
};

pub const AstEntityRef = struct {
    ast_node_id: u64,
    entity_id: u32,
};

/// Bounded MPMC channel with mutex+condvar. One consumer, many producers.
/// Owns an internal allocator; capacity is fixed at init.
pub const Channel = struct {
    mutex: std.Thread.Mutex = .{},
    not_empty: std.Thread.Condition = .{},
    not_full: std.Thread.Condition = .{},
    allocator: std.mem.Allocator,
    queue: std.ArrayList(Job),
    capacity: usize,
    closed: bool = false,

    pub fn init(allocator: std.mem.Allocator, capacity: usize) !Channel {
        return .{
            .allocator = allocator,
            .queue = try std.ArrayList(Job).initCapacity(allocator, capacity),
            .capacity = capacity,
        };
    }

    pub fn deinit(self: *Channel) void {
        self.queue.deinit(self.allocator);
    }

    pub fn send(self: *Channel, job: Job) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        while (self.queue.items.len >= self.capacity and !self.closed) {
            self.not_full.wait(&self.mutex);
        }
        if (self.closed) return error.ChannelClosed;
        try self.queue.append(self.allocator, job);
        self.not_empty.signal();
    }

    /// Returns null when the channel is closed AND drained.
    pub fn recv(self: *Channel) ?Job {
        self.mutex.lock();
        defer self.mutex.unlock();
        while (self.queue.items.len == 0 and !self.closed) {
            self.not_empty.wait(&self.mutex);
        }
        if (self.queue.items.len == 0) return null;
        const job = self.queue.orderedRemove(0);
        self.not_full.signal();
        return job;
    }

    pub fn close(self: *Channel) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.closed = true;
        self.not_empty.broadcast();
        self.not_full.broadcast();
    }
};

pub const Writer = struct {
    db: *sqlite.Db,
    channel: *Channel,
    err: ?anyerror = null,

    /// Thread entry. Blocks on channel until shutdown received.
    pub fn run(self: *Writer) void {
        self.runInner() catch |e| {
            self.err = e;
            std.log.err("writer thread failed: {s}", .{@errorName(e)});
        };
    }

    fn runInner(self: *Writer) !void {
        // Prepared statements live for the writer's lifetime.
        var stmts = try Statements.prepare(self.db);
        defer stmts.finalize();

        try self.db.exec("BEGIN");
        var rows_in_txn: usize = 0;
        const TXN_FLUSH = 50_000;

        while (self.channel.recv()) |job| {
            switch (job) {
                .shutdown => break,
                .modules => |records| {
                    for (records) |m| {
                        stmts.insert_module.reset();
                        try stmts.insert_module.bindInt(1, m.id);
                        try stmts.insert_module.bindText(2, m.qualified_name);
                        try stmts.insert_module.bindInt(3, m.root_file_id);
                        try stmts.insert_module.execOnce();
                    }
                    rows_in_txn += records.len;
                },
                .files => |records| {
                    for (records) |f| {
                        stmts.insert_file.reset();
                        try stmts.insert_file.bindInt(1, f.id);
                        try stmts.insert_file.bindText(2, f.path);
                        try stmts.insert_file.bindBlob(3, &f.sha256);
                        try stmts.insert_file.bindInt(4, @intCast(f.size));
                        try stmts.insert_file.bindBlob(5, f.source);
                        try stmts.insert_file.execOnce();
                    }
                    rows_in_txn += records.len;
                },
                .file_line_index => |fli| {
                    for (fli.byte_starts, 1..) |bs, line| {
                        stmts.insert_file_line.reset();
                        try stmts.insert_file_line.bindInt(1, fli.file_id);
                        try stmts.insert_file_line.bindInt(2, @intCast(line));
                        try stmts.insert_file_line.bindInt(3, bs);
                        try stmts.insert_file_line.execOnce();
                    }
                    rows_in_txn += fli.byte_starts.len;
                },
                .tokens => |tk| {
                    for (tk.rows) |t| {
                        stmts.insert_token.reset();
                        try stmts.insert_token.bindInt(1, tk.file_id);
                        try stmts.insert_token.bindInt(2, t.idx);
                        try stmts.insert_token.bindText(3, t.kind);
                        try stmts.insert_token.bindInt(4, t.byte_start);
                        try stmts.insert_token.bindInt(5, t.byte_len);
                        try stmts.insert_token.bindText(6, t.text);
                        try stmts.insert_token.bindInt(7, t.paren_depth);
                        try stmts.insert_token.bindInt(8, t.brace_depth);
                        try stmts.insert_token.execOnce();
                    }
                    rows_in_txn += tk.rows.len;
                },
                .ast_nodes => |rows| {
                    for (rows) |n| {
                        stmts.insert_ast_node.reset();
                        try stmts.insert_ast_node.bindInt(1, @intCast(n.id));
                        try stmts.insert_ast_node.bindInt(2, n.file_id);
                        if (n.parent_id) |pid| {
                            try stmts.insert_ast_node.bindInt(3, @intCast(pid));
                        } else {
                            try stmts.insert_ast_node.bindNull(3);
                        }
                        try stmts.insert_ast_node.bindText(4, n.kind);
                        try stmts.insert_ast_node.bindInt(5, n.byte_start);
                        try stmts.insert_ast_node.bindInt(6, n.byte_end);
                        try stmts.insert_ast_node.execOnce();
                    }
                    rows_in_txn += rows.len;
                },
                .ast_edges => |rows| {
                    for (rows) |e| {
                        stmts.insert_ast_edge.reset();
                        try stmts.insert_ast_edge.bindInt(1, @intCast(e.parent_id));
                        try stmts.insert_ast_edge.bindInt(2, @intCast(e.child_id));
                        if (e.role) |r| {
                            try stmts.insert_ast_edge.bindText(3, r);
                        } else {
                            try stmts.insert_ast_edge.bindNull(3);
                        }
                        try stmts.insert_ast_edge.execOnce();
                    }
                    rows_in_txn += rows.len;
                },
                .entities => |records| {
                    for (records) |e| {
                        stmts.insert_entity.reset();
                        try stmts.insert_entity.bindInt(1, e.id);
                        try stmts.insert_entity.bindText(2, e.kind);
                        try stmts.insert_entity.bindText(3, e.qualified_name);
                        try stmts.insert_entity.bindInt(4, e.module_id);
                        try stmts.insert_entity.bindInt(5, e.def_file_id);
                        try stmts.insert_entity.bindInt(6, e.def_byte_start);
                        try stmts.insert_entity.bindInt(7, e.def_byte_end);
                        try stmts.insert_entity.bindInt(8, e.def_line);
                        try stmts.insert_entity.bindInt(9, e.def_col);
                        try stmts.insert_entity.bindInt(10, if (e.is_slab_backed) 1 else 0);
                        try stmts.insert_entity.bindInt(11, if (e.is_pub) 1 else 0);
                        try stmts.insert_entity.execOnce();
                    }
                    rows_in_txn += records.len;
                },
                .const_aliases => |rows| {
                    for (rows) |r| {
                        stmts.insert_const_alias.reset();
                        try stmts.insert_const_alias.bindInt(1, r.entity_id);
                        try stmts.insert_const_alias.bindInt(2, r.target_entity_id);
                        try stmts.insert_const_alias.execOnce();
                    }
                    rows_in_txn += rows.len;
                },
                .type_refs => |rows| {
                    for (rows) |r| {
                        stmts.insert_type_ref.reset();
                        try stmts.insert_type_ref.bindInt(1, r.referrer_entity_id);
                        try stmts.insert_type_ref.bindInt(2, r.referred_entity_id);
                        try stmts.insert_type_ref.bindText(3, r.role);
                        try stmts.insert_type_ref.execOnce();
                    }
                    rows_in_txn += rows.len;
                },
                .ir_fns => |rows| {
                    for (rows) |r| {
                        stmts.insert_ir_fn.reset();
                        try stmts.insert_ir_fn.bindInt(1, r.entity_id);
                        try stmts.insert_ir_fn.bindText(2, r.ir_name);
                        if (r.attrs) |a| {
                            try stmts.insert_ir_fn.bindText(3, a);
                        } else {
                            try stmts.insert_ir_fn.bindNull(3);
                        }
                        try stmts.insert_ir_fn.execOnce();
                    }
                    rows_in_txn += rows.len;
                },
                .ir_calls => |rows| {
                    for (rows) |r| {
                        stmts.insert_ir_call.reset();
                        try stmts.insert_ir_call.bindInt(1, r.caller_entity_id);
                        if (r.callee_entity_id) |c| {
                            try stmts.insert_ir_call.bindInt(2, c);
                        } else {
                            try stmts.insert_ir_call.bindNull(2);
                        }
                        try stmts.insert_ir_call.bindText(3, r.call_kind);
                        if (r.resolved_via) |v| {
                            try stmts.insert_ir_call.bindText(4, v);
                        } else {
                            try stmts.insert_ir_call.bindNull(4);
                        }
                        if (r.confidence) |c| {
                            try stmts.insert_ir_call.bindInt(5, c);
                        } else {
                            try stmts.insert_ir_call.bindNull(5);
                        }
                        if (r.ast_node_id) |a| {
                            try stmts.insert_ir_call.bindInt(6, @intCast(a));
                        } else {
                            try stmts.insert_ir_call.bindNull(6);
                        }
                        try stmts.insert_ir_call.bindInt(7, r.site_line);
                        try stmts.insert_ir_call.execOnce();
                    }
                    rows_in_txn += rows.len;
                },
                .bin_symbols => |rows| {
                    for (rows) |r| {
                        stmts.insert_bin_symbol.reset();
                        // Kernel addresses are in the 0xffffffff80…… range,
                        // beyond i64 max as positive values. SQLite stores all
                        // INTEGERs as 64-bit signed; use bitCast so high addrs
                        // round-trip cleanly.
                        try stmts.insert_bin_symbol.bindInt(1, @bitCast(r.addr));
                        try stmts.insert_bin_symbol.bindInt(2, r.entity_id);
                        try stmts.insert_bin_symbol.bindInt(3, @bitCast(r.size));
                        try stmts.insert_bin_symbol.bindText(4, r.section);
                        try stmts.insert_bin_symbol.execOnce();
                    }
                    rows_in_txn += rows.len;
                },
                .bin_insts => |rows| {
                    for (rows) |r| {
                        stmts.insert_bin_inst.reset();
                        try stmts.insert_bin_inst.bindInt(1, @bitCast(r.addr));
                        try stmts.insert_bin_inst.bindBlob(2, r.bytes);
                        try stmts.insert_bin_inst.bindText(3, r.mnemonic);
                        try stmts.insert_bin_inst.bindText(4, r.operands);
                        try stmts.insert_bin_inst.execOnce();
                    }
                    rows_in_txn += rows.len;
                },
                .dwarf_lines => |rows| {
                    for (rows) |r| {
                        stmts.insert_dwarf_line.reset();
                        try stmts.insert_dwarf_line.bindInt(1, @bitCast(r.addr_lo));
                        try stmts.insert_dwarf_line.bindInt(2, @bitCast(r.addr_hi));
                        try stmts.insert_dwarf_line.bindInt(3, r.file_id);
                        try stmts.insert_dwarf_line.bindInt(4, r.line);
                        if (r.col) |c| {
                            try stmts.insert_dwarf_line.bindInt(5, c);
                        } else {
                            try stmts.insert_dwarf_line.bindNull(5);
                        }
                        try stmts.insert_dwarf_line.execOnce();
                    }
                    rows_in_txn += rows.len;
                },
                .dwarf_types => |rows| {
                    for (rows) |r| {
                        stmts.insert_type.reset();
                        try stmts.insert_type.bindInt(1, r.id);
                        if (r.entity_id) |eid| {
                            try stmts.insert_type.bindInt(2, eid);
                        } else {
                            try stmts.insert_type.bindNull(2);
                        }
                        try stmts.insert_type.bindText(3, r.kind);
                        if (r.size) |s| {
                            try stmts.insert_type.bindInt(4, @bitCast(s));
                        } else {
                            try stmts.insert_type.bindNull(4);
                        }
                        if (r.alignment) |a| {
                            try stmts.insert_type.bindInt(5, a);
                        } else {
                            try stmts.insert_type.bindNull(5);
                        }
                        try stmts.insert_type.execOnce();
                    }
                    rows_in_txn += rows.len;
                },
                .dwarf_type_fields => |rows| {
                    for (rows) |r| {
                        stmts.insert_type_field.reset();
                        try stmts.insert_type_field.bindInt(1, r.type_id);
                        try stmts.insert_type_field.bindInt(2, r.idx);
                        try stmts.insert_type_field.bindText(3, r.name);
                        if (r.offset) |o| {
                            try stmts.insert_type_field.bindInt(4, @bitCast(o));
                        } else {
                            try stmts.insert_type_field.bindNull(4);
                        }
                        if (r.type_ref) |t| {
                            try stmts.insert_type_field.bindInt(5, t);
                        } else {
                            try stmts.insert_type_field.bindNull(5);
                        }
                        try stmts.insert_type_field.execOnce();
                    }
                    rows_in_txn += rows.len;
                },
                .dwarf_dies => |rows| {
                    for (rows) |r| {
                        stmts.insert_dwarf_die.reset();
                        try stmts.insert_dwarf_die.bindInt(1, @bitCast(r.offset));
                        try stmts.insert_dwarf_die.bindInt(2, r.entity_id);
                        try stmts.insert_dwarf_die.bindText(3, r.tag);
                        if (r.parent_offset) |po| {
                            try stmts.insert_dwarf_die.bindInt(4, @bitCast(po));
                        } else {
                            try stmts.insert_dwarf_die.bindNull(4);
                        }
                        try stmts.insert_dwarf_die.execOnce();
                    }
                    rows_in_txn += rows.len;
                },
                .raw_sql => |sql| {
                    try self.db.exec("COMMIT");
                    try self.db.exec(sql);
                    try self.db.exec("BEGIN");
                    rows_in_txn = 0;
                },
                .ast_entity_backfill => |refs| {
                    for (refs) |r| {
                        stmts.update_ast_entity.reset();
                        try stmts.update_ast_entity.bindInt(1, r.entity_id);
                        try stmts.update_ast_entity.bindInt(2, @intCast(r.ast_node_id));
                        try stmts.update_ast_entity.execOnce();
                    }
                    rows_in_txn += refs.len;
                },
                .meta => |kv| {
                    stmts.insert_meta.reset();
                    try stmts.insert_meta.bindText(1, kv.key);
                    try stmts.insert_meta.bindText(2, kv.value);
                    try stmts.insert_meta.execOnce();
                    rows_in_txn += 1;
                },
                .fts_rebuild => |table| {
                    // Commit pending writes before rebuilding.
                    try self.db.exec("COMMIT");
                    var buf: [128]u8 = undefined;
                    const sql = try std.fmt.bufPrintZ(&buf, "INSERT INTO {s}({s}) VALUES('rebuild')", .{ table, table });
                    try self.db.exec(sql);
                    try self.db.exec("BEGIN");
                    rows_in_txn = 0;
                },
            }

            if (rows_in_txn >= TXN_FLUSH) {
                try self.db.exec("COMMIT");
                try self.db.exec("BEGIN");
                rows_in_txn = 0;
            }
        }

        try self.db.exec("COMMIT");
    }
};

const Statements = struct {
    insert_module: sqlite.Stmt,
    insert_file: sqlite.Stmt,
    insert_file_line: sqlite.Stmt,
    insert_token: sqlite.Stmt,
    insert_ast_node: sqlite.Stmt,
    insert_ast_edge: sqlite.Stmt,
    insert_entity: sqlite.Stmt,
    update_ast_entity: sqlite.Stmt,
    insert_ir_fn: sqlite.Stmt,
    insert_ir_call: sqlite.Stmt,
    insert_bin_symbol: sqlite.Stmt,
    insert_bin_inst: sqlite.Stmt,
    insert_dwarf_line: sqlite.Stmt,
    insert_meta: sqlite.Stmt,
    insert_const_alias: sqlite.Stmt,
    insert_type_ref: sqlite.Stmt,
    insert_type: sqlite.Stmt,
    insert_type_field: sqlite.Stmt,
    insert_dwarf_die: sqlite.Stmt,

    fn prepare(db: *sqlite.Db) !Statements {
        return .{
            .insert_module = try db.prepare("INSERT INTO module (id, qualified_name, root_file_id) VALUES (?, ?, ?)"),
            .insert_file = try db.prepare("INSERT INTO file (id, path, sha256, size, source) VALUES (?, ?, ?, ?, ?)"),
            .insert_file_line = try db.prepare("INSERT INTO file_line_index (file_id, line, byte_start) VALUES (?, ?, ?)"),
            .insert_token = try db.prepare("INSERT INTO token (file_id, idx, kind, byte_start, byte_len, text, paren_depth, brace_depth) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"),
            .insert_ast_node = try db.prepare("INSERT INTO ast_node (id, file_id, parent_id, kind, byte_start, byte_end) VALUES (?, ?, ?, ?, ?, ?)"),
            .insert_ast_edge = try db.prepare("INSERT OR IGNORE INTO ast_edge (parent_id, child_id, role) VALUES (?, ?, ?)"),
            .insert_entity = try db.prepare("INSERT INTO entity (id, kind, qualified_name, module_id, def_file_id, def_byte_start, def_byte_end, def_line, def_col, is_slab_backed, is_pub) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"),
            .update_ast_entity = try db.prepare("UPDATE ast_node SET entity_id = ? WHERE id = ?"),
            .insert_ir_fn = try db.prepare("INSERT OR IGNORE INTO ir_fn (entity_id, ir_name, attrs) VALUES (?, ?, ?)"),
            .insert_ir_call = try db.prepare("INSERT INTO ir_call (caller_entity_id, callee_entity_id, call_kind, resolved_via, confidence, ast_node_id, site_line) VALUES (?, ?, ?, ?, ?, ?, ?)"),
            .insert_bin_symbol = try db.prepare("INSERT OR IGNORE INTO bin_symbol (addr, entity_id, size, section) VALUES (?, ?, ?, ?)"),
            .insert_bin_inst = try db.prepare("INSERT OR IGNORE INTO bin_inst (addr, bytes, mnemonic, operands) VALUES (?, ?, ?, ?)"),
            .insert_dwarf_line = try db.prepare("INSERT OR IGNORE INTO dwarf_line (addr_lo, addr_hi, file_id, line, col) VALUES (?, ?, ?, ?, ?)"),
            .insert_meta = try db.prepare("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)"),
            .insert_const_alias = try db.prepare("INSERT OR IGNORE INTO const_alias (entity_id, target_entity_id) VALUES (?, ?)"),
            .insert_type_ref = try db.prepare("INSERT OR IGNORE INTO entity_type_ref (referrer_entity_id, referred_entity_id, role) VALUES (?, ?, ?)"),
            .insert_type = try db.prepare("INSERT INTO type (id, entity_id, kind, size, align) VALUES (?, ?, ?, ?, ?)"),
            .insert_type_field = try db.prepare("INSERT INTO type_field (type_id, idx, name, offset, type_ref) VALUES (?, ?, ?, ?, ?)"),
            .insert_dwarf_die = try db.prepare("INSERT OR IGNORE INTO dwarf_die (offset, entity_id, tag, parent_offset) VALUES (?, ?, ?, ?)"),
        };
    }

    fn finalize(self: *Statements) void {
        self.insert_module.finalize();
        self.insert_file.finalize();
        self.insert_file_line.finalize();
        self.insert_token.finalize();
        self.insert_ast_node.finalize();
        self.insert_ast_edge.finalize();
        self.insert_entity.finalize();
        self.update_ast_entity.finalize();
        self.insert_ir_fn.finalize();
        self.insert_ir_call.finalize();
        self.insert_bin_symbol.finalize();
        self.insert_bin_inst.finalize();
        self.insert_dwarf_line.finalize();
        self.insert_meta.finalize();
        self.insert_const_alias.finalize();
        self.insert_type_ref.finalize();
        self.insert_type.finalize();
        self.insert_type_field.finalize();
        self.insert_dwarf_die.finalize();
    }
};
