// USB input port protocol — wire format between the USB driver
// (server) and any input consumer (Doom, compositor, …; client).
//
// L4-style synchronous rendezvous over a Zag port. The client is the
// sender — it issues a fast-suspend on the port asking the driver to
// dequeue one event from the driver's internal SPSC ring; the driver
// is the receiver and replies with either an event or "queue empty".
// The driver itself spin-polls the xHCI event ring on a short-timeout
// recv loop so HID transfer completions are still drained while no
// client is waiting.
//
// Wire shape (v3 vreg ABI):
//
//   Request (client → port via suspend, payload_count = 1):
//     v1 = SLOT_INITIAL_EC   // boilerplate suspend target
//     v2 = port              // input port handle
//     v3 = op                // see Op below
//
//   Reply (driver → client via reply):
//     v1 = count             // 0 = no event ready, 1 = one event in v2..v5
//     v2 = tag               // see Tag below (only if count == 1)
//     v3 = a                 // tag-specific
//     v4 = b                 // tag-specific
//     v5 = c                 // tag-specific
//
// Per-tag payload layout for count == 1:
//
//   Tag.keyboard:
//     v3 = keycode  (u8 USB HID usage; e.g. 0xE0..0xE7 for modifiers)
//     v4 = state    (0 = release, 1 = press)
//     v5 = modifiers (u8 — full bitmask snapshot at event time)
//
//   Tag.mouse:
//     v3 = buttons  (u8 button mask)
//     v4 = dx       (u64 = i16 sign-extended into u64; cast back via @bitCast(@as(i64, …)))
//     v5 = dy       (same encoding as dx)

pub const Op = enum(u64) {
    // Pop one event from the driver's internal queue. Drives the entire
    // wire today; if the driver has no events ready, replies count = 0.
    poll = 0,
    _,
};

pub const Tag = enum(u64) {
    keyboard = 1,
    mouse = 2,
    _,
};

pub const KeyState = enum(u64) {
    released = 0,
    pressed = 1,
    _,
};

// Helper for clients: re-derive an i16 from the v4/v5 mouse dx/dy
// payload, which the driver writes as a 64-bit zero-extended view of
// an i16 (range -32768..32767).
pub fn unpackI16(v: u64) i16 {
    return @bitCast(@as(u16, @truncate(v)));
}

pub fn packI16(v: i16) u64 {
    return @as(u64, @as(u16, @bitCast(v)));
}
