// Spec §[capabilities] handle layout, type tags, and per-type cap bit
// definitions. The handle table is mapped read-only into the holding
// domain — code constructing handle ids for syscall args wraps a u12;
// reading caps from the table reads the full Cap struct verbatim.

pub const HANDLE_ID_BITS: u6 = 12;
pub const HANDLE_TABLE_MAX: u32 = 1 << HANDLE_ID_BITS;

pub const HandleId = u12;

pub const HandleType = enum(u4) {
    capability_domain_self = 0,
    capability_domain = 1,
    execution_context = 2,
    page_frame = 3,
    virtual_address_range = 4,
    device_region = 5,
    port = 6,
    reply = 7,
    virtual_machine = 8,
    timer = 9,
    _,
};

pub const Cap = extern struct {
    word0: u64,
    field0: u64,
    field1: u64,

    pub fn id(self: Cap) HandleId {
        return @truncate(self.word0 & 0xFFF);
    }

    pub fn handleType(self: Cap) HandleType {
        return @enumFromInt(@as(u4, @truncate((self.word0 >> 12) & 0xF)));
    }

    pub fn caps(self: Cap) u16 {
        return @truncate(self.word0 >> 48);
    }
};

pub const HANDLE_BYTES: usize = @sizeOf(Cap);

// §[capabilities]: "Some handles carry kernel-mutable snapshots in their
// field0/field1." Reads here are non-atomic snapshots; the holding
// domain accepts that the kernel may have mutated the slot mid-read.
// Use `sync` to force a fresh kernel-authoritative snapshot when that
// matters.
pub fn readCap(cap_table_base: u64, slot: u32) Cap {
    const tbl: [*]const Cap = @ptrFromInt(cap_table_base);
    return tbl[slot];
}

// §[device_region] field0 layout. dev_type at bits 0-3 distinguishes
// mmio (0) vs port_io (1). For port_io, base_port at bits 4-19 and
// port_count at bits 20-35 carry the x86-64 I/O port range.
pub const DevType = enum(u4) {
    mmio = 0,
    port_io = 1,
    _,
};

pub const DeviceRegionFields = struct {
    dev_type: DevType,
    base_port: u16,
    port_count: u16,
};

pub fn deviceRegionFields(c: Cap) DeviceRegionFields {
    return .{
        .dev_type = @enumFromInt(@as(u4, @truncate(c.field0 & 0xF))),
        .base_port = @truncate((c.field0 >> 4) & 0xFFFF),
        .port_count = @truncate((c.field0 >> 20) & 0xFFFF),
    };
}

// The 12-bit handle id is the only field a syscall ever takes. Upper
// bits of the syscall word slot are _reserved.
pub fn handleArg(slot: HandleId) u64 {
    return @as(u64, slot);
}

// §[capability_domain] self-handle cap bits.
pub const SelfCap = packed struct(u16) {
    crcd: bool = false,
    crec: bool = false,
    crvr: bool = false,
    crpf: bool = false,
    crvm: bool = false,
    crpt: bool = false,
    pmu: bool = false,
    setwall: bool = false,
    power: bool = false,
    restart: bool = false,
    reply_policy: bool = false,
    fut_wake: bool = false,
    timer: bool = false,
    _reserved: u1 = 0,
    pri: u2 = 0,

    pub fn toU16(self: SelfCap) u16 {
        return @bitCast(self);
    }
};

// §[capability_domain] IDC handle cap bits.
pub const IdcCap = packed struct(u16) {
    move: bool = false,
    copy: bool = false,
    crec: bool = false,
    aqec: bool = false,
    aqvr: bool = false,
    restart_policy: bool = false,
    _reserved: u10 = 0,

    pub fn toU16(self: IdcCap) u16 {
        return @bitCast(self);
    }
};

// §[execution_context] EC handle cap bits.
pub const EcCap = packed struct(u16) {
    move: bool = false,
    copy: bool = false,
    saff: bool = false,
    spri: bool = false,
    term: bool = false,
    susp: bool = false,
    read: bool = false,
    write: bool = false,
    restart_policy: u2 = 0,
    bind: bool = false,
    rebind: bool = false,
    unbind: bool = false,
    _reserved: u3 = 0,

    pub fn toU16(self: EcCap) u16 {
        return @bitCast(self);
    }
};

// §[var] VAR handle cap bits.
pub const VarCap = packed struct(u16) {
    move: bool = false,
    copy: bool = false,
    r: bool = false,
    w: bool = false,
    x: bool = false,
    mmio: bool = false,
    max_sz: u2 = 0,
    dma: bool = false,
    restart_policy: u2 = 0,
    _reserved: u5 = 0,

    pub fn toU16(self: VarCap) u16 {
        return @bitCast(self);
    }
};

// §[page_frame] page-frame handle cap bits.
pub const PfCap = packed struct(u16) {
    move: bool = false,
    copy: bool = false,
    r: bool = false,
    w: bool = false,
    x: bool = false,
    max_sz: u2 = 0,
    restart_policy: bool = false,
    _reserved: u8 = 0,

    pub fn toU16(self: PfCap) u16 {
        return @bitCast(self);
    }
};

// §[device_region] device-region handle cap bits.
pub const DeviceCap = packed struct(u16) {
    move: bool = false,
    copy: bool = false,
    dma: bool = false,
    irq: bool = false,
    restart_policy: bool = false,
    _reserved: u11 = 0,

    pub fn toU16(self: DeviceCap) u16 {
        return @bitCast(self);
    }
};

// §[port] port handle cap bits.
pub const PortCap = packed struct(u16) {
    move: bool = false,
    copy: bool = false,
    xfer: bool = false,
    recv: bool = false,
    bind: bool = false,
    restart_policy: bool = false,
    _reserved: u10 = 0,

    pub fn toU16(self: PortCap) u16 {
        return @bitCast(self);
    }
};

// §[reply] reply handle cap bits.
pub const ReplyCap = packed struct(u16) {
    move: bool = false,
    copy: bool = false,
    xfer: bool = false,
    _reserved: u13 = 0,

    pub fn toU16(self: ReplyCap) u16 {
        return @bitCast(self);
    }
};

// §[virtual_machine] VM handle cap bits.
pub const VmCap = packed struct(u16) {
    policy: bool = false,
    restart_policy: bool = false,
    _reserved: u14 = 0,

    pub fn toU16(self: VmCap) u16 {
        return @bitCast(self);
    }
};

// §[timer] timer handle cap bits.
pub const TimerCap = packed struct(u16) {
    move: bool = false,
    copy: bool = false,
    arm: bool = false,
    cancel: bool = false,
    restart_policy: bool = false,
    _reserved: u11 = 0,

    pub fn toU16(self: TimerCap) u16 {
        return @bitCast(self);
    }
};

// §[create_capability_domain] passed-handle entry encoding.
pub const PassedHandle = packed struct(u64) {
    id: u12,
    _reserved_lo: u4 = 0,
    caps: u16,
    move: bool,
    _reserved_hi: u31 = 0,

    pub fn toU64(self: PassedHandle) u64 {
        return @bitCast(self);
    }
};

// §[handle_attachments] entry encoding for suspend/reply_transfer.
pub const PairEntry = packed struct(u64) {
    id: u12,
    _reserved_lo: u4 = 0,
    caps: u16,
    move: bool,
    _reserved_hi: u31 = 0,

    pub fn toU64(self: PairEntry) u64 {
        return @bitCast(self);
    }
};

// Conventional slot ids for a freshly-created capability domain
// (§[capability_domain] / §[create_capability_domain]).
pub const SLOT_SELF: HandleId = 0;
pub const SLOT_INITIAL_EC: HandleId = 1;
pub const SLOT_SELF_IDC: HandleId = 2;
pub const SLOT_FIRST_PASSED: HandleId = 3;
