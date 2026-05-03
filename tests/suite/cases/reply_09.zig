// Spec §[reply] reply — test 09.
//
// "[test 09] returns E_PERM when `pair_count > 0` and the reply handle
//  does not have the `xfer` cap."
//
// Strategy
//   Per §[reply]: "The kernel mints the reply handle at recv time with
//   `move = 1`, `copy = 0`, and `xfer = 1` if and only if the recv'ing
//   port had the `xfer` cap; otherwise `xfer = 0`." So the cleanest
//   way to land an xfer=0 reply handle in the caller's table is to
//   create the port without the `xfer` cap and then drive a recv.
//
//   Pipeline (test EC owns both ends):
//     1. mint port with caps = {bind, recv}    — note: NO xfer
//     2. mint EC W with caps = {susp}          — restart_policy = 0
//        keeps W inside the runner-granted ceiling
//     3. suspend(W, port)                      — queues W as a
//        suspended sender; non-blocking on the test EC since
//        [1] != self per §[suspend]
//     4. recv(port)                            — returns immediately
//        and yields a reply handle id in syscall word bits 32-43.
//        Since the port lacked xfer, the minted reply handle has
//        xfer = 0.
//     5. reply(reply_handle, pair_count = 1)   — must return E_PERM.
//
//   N = 1 is the smallest legal pair_count > 0 (§[reply] test 10
//   rejects pair_count > 63 with E_INVAL), so the call passes the
//   pair_count range check trivially. The cap check on the reply
//   handle (test 09) fires before pair entry validation (tests 11-16),
//   so the kernel rejects on the missing xfer cap before reading any
//   pair-entry vreg. That means we don't need to populate the high-vreg
//   pair entries; libz's typed `reply` wrapper handles only the bare
//   case, so we dispatch directly via `issueReg` with
//   `extraCount(1) | extraTstart(reply_handle_id)` placing pair_count
//   in syscall word bits 12-19 and the reply handle id in bits 20-31
//   per §[reply].
//
// Action
//   1. create_port(caps = {bind, recv})        — must succeed
//   2. create_execution_context(target = self,
//        caps = {susp, restart_policy = 0})    — must succeed
//   3. suspend(W, port)                        — must return OK
//   4. recv(port)                              — must return OK
//   5. reply(reply_handle, pair_count = 1)     — must return E_PERM
//
// Assertions
//   1: setup port creation failed
//   2: setup EC creation failed
//   3: suspend itself did not return OK
//   4: recv did not return OK
//   5: reply returned something other than E_PERM

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: mint port without xfer. bind is required for suspend
    // (§[suspend] [2] cap) and recv works because the test EC holds the
    // port handle (no E_CLOSED). Restricting to {bind, recv} guarantees
    // the kernel mints the reply handle at recv time with xfer = 0.
    const port_caps = caps.PortCap{ .bind = true, .recv = true };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // Step 2: mint W. susp lets the test queue W onto the port via
    // suspend. restart_policy = 0 (kill) keeps the call inside the
    // runner-granted ceiling.
    const w_caps = caps.EcCap{
        .susp = true,
        .restart_policy = 0,
    };
    const ec_caps_word: u64 = @as(u64, w_caps.toU16());
    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const cec = syscall.createExecutionContext(
        ec_caps_word,
        entry,
        1,
        0,
        0,
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(2);
        return;
    }
    const w_handle: u12 = @truncate(cec.v1 & 0xFFF);

    // Step 3: queue W as a suspended sender on the port. Since
    // [1] = W != self, the call returns immediately without blocking
    // the test EC (§[suspend]).
    const sus = syscall.issueReg(.@"suspend", 0, .{
        .v1 = w_handle,
        .v2 = port_handle,
    });
    if (sus.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // Step 4: recv. The port has the test EC as a live bind-cap holder
    // and W queued as a suspension event, so recv returns immediately
    // with the reply handle id encoded in the syscall word per §[recv].
    const got = syscall.recv(port_handle, 0);
    if (got.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }
    // §[recv] syscall word return layout: reply_handle_id in bits
    // 32-43 (12 bits).
    const reply_handle_id: u12 = @truncate((got.word >> 32) & 0xFFF);

    // Step 5: probe the reply handle (xfer = 0) with reply, pair_count = 1.
    // libz's typed `reply` wrapper handles only the bare-reply path, so
    // dispatch directly via issueReg with pair_count = 1 in syscall word
    // bits 12-19 and reply_handle_id in bits 20-31 per §[reply]. The
    // kernel checks the xfer cap on the reply handle before reading any
    // pair entry, so the high-vreg pair-entry slot can be left
    // unpopulated.
    const extra: u64 = syscall.extraCount(1) | syscall.extraTstart(reply_handle_id);
    const r = syscall.issueReg(.reply, extra, .{});
    if (r.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(5);
        return;
    }

    testing.pass();
}
