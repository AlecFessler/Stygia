// EXPECT: errors=2
// The other half of the annotation-tolerance contract: tolerating blank
// lines must NOT let an annotation drift onto an unrelated site.
//
// Two independent bounds are pinned here:
//
//   HolderCrossesCode — the annotation sits above `other`, and `other`
//   is real code. A comment block justifies the statement directly
//   below it and nothing past that statement, so `inner` is still a
//   violation.
//
//   HolderTooFar — the annotation is further above `inner` than
//   ANNOTATION_LOOKBACK_LINES (32), so the walker gives up before
//   reaching it. Without a bound, a distant file banner could exempt
//   arbitrary code below it.

const slab = @import("../slab.zig");

const Foo = slab.Foo;

pub const HolderCrossesCode = struct {
    // caller-pinned: this justification is for `other`, not for `inner`.
    other: u64 = 0,
    inner: *Foo,
};

pub const HolderTooFar = struct {
    // caller-pinned: too far above to cover the field below.
    //
    // filler 1
    // filler 2
    // filler 3
    // filler 4
    // filler 5
    // filler 6
    // filler 7
    // filler 8
    // filler 9
    // filler 10
    // filler 11
    // filler 12
    // filler 13
    // filler 14
    // filler 15
    // filler 16
    // filler 17
    // filler 18
    // filler 19
    // filler 20
    // filler 21
    // filler 22
    // filler 23
    // filler 24
    // filler 25
    // filler 26
    // filler 27
    // filler 28
    // filler 29
    // filler 30
    // filler 31
    // filler 32
    // filler 33
    inner: *Foo,
};

pub fn sysTouchBounded(caller: *anyopaque) u64 {
    _ = caller;
    return 0;
}
