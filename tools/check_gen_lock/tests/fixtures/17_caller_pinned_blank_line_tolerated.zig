// EXPECT: clean
// `// caller-pinned` must survive a blank line between the annotation
// and the site it justifies.
//
// The pre-hardening walker stopped dead at the first blank line, so
// inserting one — or leaving one behind after deleting a temporary
// probe line — silently revoked the exemption and turned the field into
// an error with no edit to the annotation itself. That bit a live
// debugging session.

const slab = @import("../slab.zig");

const Foo = slab.Foo;

pub const HolderBlank = struct {
    // caller-pinned: the owner pins this Foo for the holder's lifetime,
    // so a bare pointer is intentional here.

    inner: *Foo,
};

pub const HolderTwoBlanks = struct {
    // caller-pinned: same justification, with an intervening comment
    // and two blank lines between the annotation and the field.

    // (an unrelated note that is still just a comment)

    inner: *Foo,
};

pub fn sysTouchHolder(caller: *anyopaque) u64 {
    _ = caller;
    return 0;
}
