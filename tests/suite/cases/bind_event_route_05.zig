// Spec §[bind_event_route] bind_event_route — test 05.
//
// "[test 05] returns E_PERM if [3] does not have the `bind` cap."
//
// Strategy
//   The E_PERM gate on [3] checks for the port's `bind` cap (§[port]
//   bit 4). To exercise it in isolation every other argument must be
//   well-formed so the kernel cannot reject earlier:
//     - [1] must be a valid EC handle (sidesteps test 01 / E_BADCAP).
//     - [2] must be a registerable event type (sidesteps test 03).
//     - [1], [2], [3] must have no reserved bits set (sidesteps test 04).
//     - [3] must be a valid port handle (sidesteps test 02).
//
//   For [3] specifically we need a port handle that is structurally
//   valid (so test 02's BADCAP gate doesn't fire) but lacks the `bind`
//   cap. The cleanest construction is to mint a fresh port via
//   `create_port` with `bind` set, then `restrict` away the `bind`
//   cap. The handle id stays the same; only the caps field on the
//   slot is narrowed. This mirrors restrict_07's pattern for the
//   parallel E_PERM gate on `recv`.
//
//   For [1] we use SLOT_INITIAL_EC, the test domain's initial EC.
//   The runner mints it with the new domain's `ec_inner_ceiling`,
//   which by primary.zig's `ceilings_inner` (var_inner_ceiling field
//   = 0x01FF, ec_inner_ceiling field = 0xFF — bits 0-7 set) includes
//   `bind` (EcCap bit 10). Whether or not [1] has `bind` doesn't
//   matter for this assertion: the spec orders the cap checks per
//   argument independently, and we only need the [3]-side check to
//   surface E_PERM. Using a valid EC handle prevents test 01's gate.
//
//   The spec does not pin the relative order of cap checks across
//   [1] vs [3] for bind_event_route. With both [1] and [3] passing
//   their type/structural validations, only the absent `bind` cap on
//   [3] remains as a spec-mandated reason for E_PERM, so the kernel
//   must return E_PERM regardless of check ordering.
//
// Action
//   1. create_port(caps = {bind, recv})           — must succeed
//   2. restrict(port, caps = {recv})              — must succeed (drops bind)
//   3. bindEventRoute(SLOT_INITIAL_EC, 1, port)   — must return E_PERM
//
// Assertions
//   1: create_port returned an error word (setup failure).
//   2: restrict returned a non-zero error word (failed to drop bind).
//   3: bindEventRoute returned something other than E_PERM.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: mint a port with `bind` so the handle starts well-formed.
    // `recv` is included as a non-bind cap to retain after the restrict
    // — restrict's contract is bitwise subset, so we need at least one
    // cap to remain set (a zero caps word may collide with delete-style
    // handling depending on impl, and we only care about the bind bit
    // being cleared here).
    const initial = caps.PortCap{ .bind = true, .recv = true };
    const cp = syscall.createPort(@as(u64, initial.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // Step 2: restrict the port to clear the `bind` cap. We retain
    // `recv` so the port remains a valid, structurally well-formed
    // handle in the test domain — only the bind bit is dropped, which
    // is the precise condition the test 05 spec line probes.
    const reduced = caps.PortCap{ .recv = true };
    const restrict_result = syscall.restrict(port_handle, @as(u64, reduced.toU16()));
    if (restrict_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    // Step 3: invoke bind_event_route with the bind-stripped port.
    // event_type = 1 (memory_fault) is registerable per §[event_type],
    // sidestepping test 03's E_INVAL gate. SLOT_INITIAL_EC is a valid
    // EC handle in this domain, sidestepping test 01's E_BADCAP gate.
    // The only spec violation is the missing `bind` cap on [3], which
    // the kernel must surface as E_PERM.
    const result = syscall.bindEventRoute(caps.SLOT_INITIAL_EC, 1, port_handle);
    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
