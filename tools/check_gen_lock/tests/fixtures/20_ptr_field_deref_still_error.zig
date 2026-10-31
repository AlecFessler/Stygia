// EXPECT: errors=1
const slab = @import("../slab.zig");

fn SlabRef(comptime T: type) type {
    return struct { ptr: *T };
}

const Holder = struct {
    process: SlabRef(slab.Foo),
};

pub fn readField(holder: *Holder) u64 {
    return holder.process.ptr.value;
}
