# Stygia-o4a.7: first x86 shootdown IPI during AP bringup

## Root cause

`userspace_init.init` queues the root thread before `smpInit`. The first AP
that reaches `sched.run` can dispatch that thread while the BSP is still
starting the remaining APs. The root thread's first synchronous TLB
shootdown (generation 1) then sends IPIs to all **discovered** LAPIC IDs,
including APs that have not yet completed initialization or received a
SIPI. Those IPIs do not reach the eventual handler. The initiating core
waits for acknowledgements until the bounded retry sends new IPIs after
the targets have started.

This is separate from Stygia-o4a.27's false 4-second hang report during
the intentional 5-second timed receive probe. The original first-IPI
log showed core 1 waiting for generation 1 while core 2's scheduler
entries continued, and the later retry marker appeared during startup.

## Direct trace

Temporary instrumentation recorded each target's AP phase and scheduler
entry count at the first send, then printed them at the first retry.
Phase 0 means the AP had not reached the readiness signal in `coreInit`;
phase 3 means it had finished `perCoreInit` and printed its scheduler
entry banner. The instrumentation was removed from the fix.

Representative x2APIC trace (the original line is in
[`traces/o4a-7-baseline-x2apic.log`](traces/o4a-7-baseline-x2apic.log.gz)):

```text
[IPI-PHASE] src=1 dst=2 apic=2 mode=1 send_phase=0 now_phase=3 send_entries=0 now_entries=10 cycles=124338228
[IPI-PHASE] src=1 dst=3 apic=3 mode=1 send_phase=0 now_phase=3 send_entries=0 now_entries=12 cycles=181942740
```

Representative forced xAPIC trace (the original line is in
[`traces/o4a-7-baseline-xapic.log`](traces/o4a-7-baseline-xapic.log.gz)):

```text
[IPI-PHASE] src=1 dst=2 apic=2 mode=0 send_phase=0 now_phase=3 send_entries=0 now_entries=10 cycles=112984494
[IPI-PHASE] src=1 dst=3 apic=3 mode=0 send_phase=0 now_phase=3 send_entries=0 now_entries=11 cycles=167404608
```

The initial send to APs 2 and 3 happened before either reached the AP
readiness signal. The BSP starts APs serially and waits for AP 2's
signal before sending AP 3's SIPI, so AP 3 had not yet been started
when core 1 sent its first IPI. At retry, both targets had entered the
scheduler and taken 10–12 scheduler interrupts. An IPI addressed to
an AP before its SIPI cannot be recovered merely by waiting for that
AP to enable interrupts.

## Controlled comparison

Both configurations used the same focused `recv_01` runner with
`-Drepeat=20`, QEMU/KVM with four cores, and the same trace build. Forced
xAPIC replaced the generated `-cpu host,+invtsc` with
`-cpu host,+invtsc,-x2apic`. The baseline let APs schedule immediately
after their individual initialization. The barrier held every AP out of
`sched.run` until all APs had finished per-core setup and the BSP had
armed remote shootdown. Each cell represents ten separate QEMU boots.

| APIC mode | Baseline boots with two generation-1 retries | Barrier boots with a generation-1 retry |
| --- | ---: | ---: |
| x2APIC | 10/10 | 0/10 |
| xAPIC | 10/10 | 0/10 |

All 40 boots exited successfully; no `[HANG]` appeared. One aggregate
line in each barrier mode was byte-interleaved by concurrent kernel and
runner COM1 output; individual test results remained successful. Exact compressed raw
representative barrier logs are
[`x2APIC`](traces/o4a-7-barrier-x2apic.log.gz) and
[`xAPIC`](traces/o4a-7-barrier-xapic.log.gz). The bounded shootdown retry
remains in place as a defense against future delayed delivery.

With the final barrier and no trace instrumentation, a complete
346-test suite repeated ten times passed 3460/3460 in x2APIC and
3460/3460 in forced xAPIC, with no `[HANG]` report. A QEMU TCG focused
boot passed `recv_01` three times. Full-suite captures are
`/tmp/stygia-bead7-firstipi-final-x2-full10.log` and
`/tmp/stygia-bead7-firstipi-final-xapic-full10.log` on the development
host; the representative startup traces above are committed here.

## Startup invariant

Each AP publishes readiness only after its APIC/IDT and per-core
scheduler setup, then waits on an acquire load of `aps_may_schedule`.
The BSP verifies the ready count equals the discovered core count,
arms remote shootdown, then release-stores the gate. An AP asserts the
ready count before entering `sched.run`. The BSP never waits for an AP
to dispatch while holding the gate, so this ordering cannot deadlock
normal AP startup.
