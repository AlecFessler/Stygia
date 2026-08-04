// `mod.append` is a plain module-level function. It must NOT be wired up as
// the callee of `std`'s `array_list.Aligned(T,null).append` just because the
// erased name would collide: generic-instantiation erasure only fires when
// the instantiated head is itself a known entity in that namespace.
pub fn append(x: u64) u64 {
    return x + 1;
}

// A non-generic function carrying a `__anon_NNNN` discriminator resolves by
// suffix stripping and is tagged as such.
pub fn logf(x: u64) u64 {
    return append(x);
}

pub fn caller() u64 {
    return logf(1);
}
