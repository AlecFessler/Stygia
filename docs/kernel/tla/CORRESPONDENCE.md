# ThreadLifecycle action-to-kernel correspondence

Status: **in progress**, reviewed against `main` at `6ad8bf71` (2026-10-31).
This is implementation evidence for the active `Next` relation, not a refinement
proof. The parity table in `README.md` maps the model to `systems.md`; this
ledger maps actions to kernel code and distinguishes code review, an automated
source check, and runtime evidence. A row marked *reviewed* does not assert
that every interleaving or architecture has a passing kernel test.

## Milestone 1: scheduler, retirement, and guest cancellation

| Active action | Kernel correspondence | Evidence and limit |
|---|---|---|
| `ParkDecision` | `scheduler.dequeueOrIdle` / `dequeueOrIdleLocked` set `idle_parked` under the core lock after the empty-queue decision. | G14 source-order gate and mutation fixture; focused `g14` TLC row. Model fuses the decision and park flag into one action. |
| `WakeIpi` | `scheduler.finishEnqueuePublish` observes `idle_parked` under the destination core lock and sends `arch.smp.sendWakeIpi` after unlock; `parkAndAwaitIRQ` returns to `run`. | G14 gate and lost-wake mutation fixture; `g14_missing` falsifier. The pre-IPI instruction window is below model atomicity. |
| `DispatchThread` | `scheduler.dequeueLocalReadyLocked` removes a ready thread and `lifecycle.prepareDispatchLocked` commits `ready -> running`; `setCurrentThread` records ownership. | Source review; model queue is a set, whereas kernel run queue is priority/FIFO. `processRefAlive` supplies the restart/dead-process filter. |
| `DispatchAbort` | `scheduler.dispatchTailBody` rechecks `lifecycle.load(current) != .running` after teardown drain, then discharges and reselects. | Source review; model combines loss-of-state and loss-of-process cases. |
| `DispatchLoad` | `scheduler.dispatchTailBody` calls `arch.cpu.loadThreadContextAndReturn`; dispatch shim selects x64/aarch64. | Source review; arch register and stack restoration is outside lifecycle state. |
| `S7Claim`, `S7Retire` | `dequeueLocalReadyLocked` rejects unpublishable process refs and `thread.destroyThreadRefLocked` / `routeRetiredFinalize` handle dead threads. | Source review; model expresses a distinct S7 claim step while source can reject before claiming. Do not treat this as a one-to-one source transition. |
| `StealClaim` | `scheduler.stealCandidateFromVictimLocked` checks affinity, process liveness, queue cache, and `ready`, then pins/claims and removes under victim lock. | Source review; set queue omits per-priority selection and cache incoherence (G13). |
| `StealDispatch` | `scheduler.commitStolenDispatchLocked` commits claimed thread on thief core and releases holder pin. | Source review. |
| `StealAbandon`, `StealDropDead` | `scheduler.abandonStolenReadyUnlocked` republishes via `enqueuePinnedClaimed` or calls `thread.dischargeClaimedHolderDead`. | Source review. Model action separation captures claim-to-discharge race, but not actual lock-acquisition steps. |
| `UserPark` | `lifecycle.prepareRunningPark` publishes parking; syscall/fault wait paths use it before their eventual scheduler hop. | Source review of primitive and `thread.suspendOnPortInner`; wait-container linkage is a separate instruction sequence under a reaching lock, fused in model. Full path audit remains pending. |
| `HopRelease` | `scheduler.hopParkYield` / `hopParkRun` use `arch.cpu.hopToStackAndCall` to leave the outgoing kstack; `scheduler_hop_*` land on park stack. | Source review of scheduler path. Model treats release as an atomic step; arch-specific hop assembly and release-store parity remain to review. |
| `HopCommitWait` | `scheduler.dischargeOwnedParking` calls `lifecycle.commitParkingWaiting` and clears current. | Source review. |
| `HopCommitRequeue` | `scheduler.dischargeOwnedParking` chooses a fresh affinity core and calls `enqueueOnCore`; `drainDeferredRequeuesLocked` is the local deferred path. | Source review; model chooses nondeterministic destination, omitting priority and affinity algorithm. |
| `HopCommitPended` | `scheduler.dischargeOwnedParking` waits for payload, clears current, then enqueues. | Source review; `waitForPendedPayload` is a spin outside model atomicity. |
| `HopCommitRetired` | `scheduler.dischargeOwnedParking` clears current and finalizes on safe stack after dead-gen check. | Source review; model coalesces on-CPU and stack-safety checks. |
| `HopCommitClaimed` | `scheduler.dischargeOwnedParking` handles parking/pended/retired, while claimed ownership is discharged by the external claimant. | **Needs closer parity review**: no literal `claimed` arm here. The model has a rev-3 compatibility action under `PENDED = FALSE`; confirm no active production config relies on it. |
| `TickPreempt` | `scheduler.preempt` calls `yieldTo`; `yieldToTarget` uses `prepareRunningPark(.requeue)` under core lock. | Source review; `PIN_GATE` is in lifecycle primitive and IRQ entry discipline. No stand-alone kernel race test established here. |
| `BoundaryRetired` | `scheduler.dispatchTailBody` checks lifecycle before context load; syscall/IRQ exits enter scheduler paths that discharge retired current. | Source review; x64 and aarch64 boundary entry points still need direct path audit. |
| `VcpuGuestExit` | `scheduler.switchTo` calls `arch.vm.enterGuest`, then `port.fireVmExit` on an ordinary exit. | Source review; guest instructions are outside model. |
| `VcpuCancelExit` | Both `arch/{x64,aarch64}/vm_runloop.enterGuest` check `retired` at the top of their guest loop and return `cancelled`; `scheduler.switchTo` skips `fireVmExit`, then `dischargeOwnedParking`. | **Automated** model/source order check with x64, arm, and scheduler mutation fixtures; focused TLC `vcpu_cancel` pass and `vcpu_nocancel` falsifier. This checks the acknowledgement path, **not arch-state lifetime**. |
| `RetireEnabled`, `RetireThreadsAfter`, `RetireCoresAfter`, `RetireThread` | `thread.retireAndBumpDeadGen` marks retiring, waits pins, removes ready queue, calls `lifecycle.retire`, then flips dead gen; `lifecycle.retire` waits for pended payload before CAS. | Source review and lifecycle model `small`/`vcpu_cancel` rows. Retire source is a multi-instruction protocol; model uses one atomic action. Owner-core cancellation is represented as `vm=cancel` but source relies on wake IPI and guest-loop check. |
| `RetireUnwind` | Legacy/falsifier action, enabled only by the defective switch; current retire cleanup runs after state CAS in `terminate` and `destroyThreadRefLockedMode`. | No production correspondence claim; see model `N4` falsifier and README G4. |
| `ClearFreedDirective` | `thread.finalizeDestroyMarkedDead` calls `lifecycle.markDirectiveDead` before `slab_instance.destroyAlreadyMarked` zeroes/recycles the slot. | G11-focused model proof and code review; physical slab gen flips earlier at `retireAndBumpDeadGen` (README G11). |

### Open kernel mismatch exposed by this review

`Stygia-o4a.4.2.2.1` records a remote vCPU lifetime race. Both
`thread.terminate` and `destroyThreadRefLockedMode` call
`arch.vm.freeVcpuArchState` **before** `routeRetiredFinalize` wakes or waits
for the remote owner. Both arch `enterGuest` loops cache the state pointer
and use it after guest exits. The model's `VcpuCancelExit` establishes an
eventual owner acknowledgement, but has no state-page lifetime variable and
cannot rule out this use-after-free. The new source gate intentionally does
not certify this failed obligation.

### Still to review

Wake/IRQ/relwait, suspend/directive, rendezvous/one-shot, termination spin,
pin, creation, recv/reply fast paths, affinity, G16/restart details, and all
remaining arch boundary paths. These actions are listed in `ThreadLifecycle.tla`
and are **not** accepted by this milestone.
