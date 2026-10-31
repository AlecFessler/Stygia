// EXPECT: clean
const slab = @import("../slab.zig");

fn SlabRef(comptime T: type) type {
    return struct { ptr: *T };
}

const Holder = struct {
    process: SlabRef(slab.Foo),
};

pub fn addressOnly(holder: *Holder) usize {
    return @intFromPtr(holder.process.ptr);
}
