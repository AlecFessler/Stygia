// Constants shared between the libz_image builder (runner-side) and the
// libz_loader runtime hook (child-side).
//
// The runner stages libz_c.elf into a single page_frame at startup,
// applies its R_*_RELATIVE relocations against `LIBZ_SLIDE`, then hands
// that pf out to every spawned test domain. Each child mapPfs the pf
// at exactly `LIBZ_SLIDE` so the prelinked addresses inside the libz
// image (its own GOT, its data.rel.ro pointers, etc.) are valid at
// runtime without re-relocating per-child.
//
// The slot constant pins where the runner stages the libz pf in the
// child's installed cap-table view. The runner already passes:
//   slot 3 = result port handle    (SLOT_FIRST_PASSED + 0)
//   slot 4 = test ELF page_frame   (SLOT_FIRST_PASSED + 1, for tests
//                                    that need to re-spawn themselves)
// Add libz at slot 5 so existing tests that never look at slot 5 don't
// notice. The runner passes 3 handles in its passed_handles array; the
// child's _start reaches into slot 5 via a self-handle issuance to
// resolve the libz pf id.
pub const LIBZ_SLIDE: u64 = 0x4000_0000_0000;
pub const LIBZ_PF_SLOT: u8 = 5;
