const std = @import("std");

/// Hard kinds for entity.kind. Strings are what land in SQL.
pub const EntityKind = enum {
    fn_,
    type_,
    const_,
    var_,
    field,
    variant,
    namespace,

    pub fn toString(self: EntityKind) []const u8 {
        return switch (self) {
            .fn_ => "fn",
            .type_ => "type",
            .const_ => "const",
            .var_ => "var",
            .field => "field",
            .variant => "variant",
            .namespace => "namespace",
        };
    }
};

pub const FileRecord = struct {
    id: u32,
    path: []const u8, // relative to kernel root
    source: [:0]const u8, // borrowed, lives in arena; sentinel for parsers
    sha256: [32]u8,
    size: u64,
    module_id: u32,
};

pub const ModuleRecord = struct {
    id: u32,
    qualified_name: []const u8,
    root_file_id: u32,
};

pub const TokenRow = struct {
    idx: u32,
    kind: []const u8, // string label, lives in static or arena
    byte_start: u32,
    byte_len: u32,
    text: []const u8, // borrowed
    paren_depth: u16,
    brace_depth: u16,
};

/// Provisional entity emitted by the AST pass; final entity_id is assigned in stage 2.5.
pub const ProvisionalEntity = struct {
    kind: EntityKind,
    qualified_name: []const u8,
    module_id: u32,
    def_file_id: u32,
    def_byte_start: u32,
    def_byte_end: u32,
    def_line: u32,
    def_col: u32,
    is_slab_backed: bool,
    is_pub: bool,
    /// Global id of the ast_node this decl was emitted from. Stage 2.5
    /// back-fills `ast_node.entity_id = entity.id` for this node.
    def_ast_node_id: u64,
};

/// Provisional alias emitted by the AST pass. Stage 2.5 resolves
/// `target_chain` against the alias's module's import graph and emits
/// a `const_alias` row when the chain terminates in a known entity.
pub const ProvisionalAlias = struct {
    alias_qname: []const u8,
    alias_module_id: u32,
    target_chain: []const []const u8,
};

/// Provisional type reference emitted by the AST pass for chain-shaped
/// type expressions. Stage 2.5 resolves `target_chain` and emits
/// `entity_type_ref` rows.
pub const ProvisionalTypeRef = struct {
    referrer_qname: []const u8,
    referrer_module_id: u32,
    target_chain: []const []const u8,
    /// 'field_type' | 'param_type' | 'return_type'
    role: []const u8,
};

pub const AstNodeRow = struct {
    id: u64,
    file_id: u32,
    parent_id: ?u64,
    kind: []const u8, // static or arena-owned
    byte_start: u32,
    byte_end: u32,
};

pub const AstEdgeRow = struct {
    parent_id: u64,
    child_id: u64,
    role: ?[]const u8,
};

pub const IrFnRow = struct {
    entity_id: u32,
    ir_name: []const u8,
    attrs: ?[]const u8,
};

pub const IrCallRow = struct {
    caller_entity_id: u32,
    callee_entity_id: ?u32,
    call_kind: []const u8,
    resolved_via: ?[]const u8,
    confidence: ?u8,
    ast_node_id: ?u64,
    site_line: u32,
};

pub const BinSymbolRow = struct {
    addr: u64,
    entity_id: u32,
    size: u64,
    section: []const u8,
};

pub const BinInstRow = struct {
    addr: u64,
    bytes: []const u8,
    mnemonic: []const u8,
    operands: []const u8,
};

pub const DwarfLineRow = struct {
    addr_lo: u64,
    addr_hi: u64,
    file_id: u32,
    line: u32,
    col: ?u32,
};

/// One row per ingested type DIE (struct / union / enum / array / pointer /
/// primitive). `entity_id` is NULL for anonymous / unmatched types so the
/// row still exists as a target for `type_field.type_ref`.
pub const TypeRow = struct {
    id: u32,
    entity_id: ?u32,
    kind: []const u8,
    size: ?u64,
    alignment: ?u32,
};

/// One row per struct/union member. `offset` is NULL when the member's
/// `DW_AT_data_member_location` is a non-trivial DWARF expression we don't
/// evaluate. `type_ref` is NULL when the member's type DIE wasn't ingested.
pub const TypeFieldRow = struct {
    type_id: u32,
    idx: u32,
    name: []const u8,
    offset: ?u64,
    type_ref: ?u32,
};

/// Maps DWARF DIE byte offset (in `.debug_info`) to entity_id. One row per
/// DIE we ingest that we managed to match against the entity table.
pub const DwarfDieRow = struct {
    offset: u64,
    entity_id: u32,
    tag: []const u8,
    parent_offset: ?u64,
};
