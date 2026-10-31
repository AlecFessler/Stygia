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
| `S7Claim`, `S7Retire` | **Mismatch:** `dequeueLocalReadyLocked` pops and skips a thread on `!canPublishReady`, with no claim or retire. Independent process teardown may later retire it. | `Stygia-o4a.4.2.2.2`; the model's claim-then-retire route and the design's §3.2 text cannot currently be cited as source correspondence. A guarantee covering every skip is still needed. |
| `StealClaim` | `scheduler.stealCandidateFromVictimLocked` checks affinity, process liveness, queue cache, and `ready`, then pins/claims and removes under victim lock. | Source review; set queue omits per-priority selection and cache incoherence (G13). |
| `StealDispatch` | `scheduler.commitStolenDispatchLocked` commits claimed thread on thief core and releases holder pin. | Source review. |
| `StealAbandon`, `StealDropDead` | `scheduler.abandonStolenReadyUnlocked` republishes via `enqueuePinnedClaimed` or calls `thread.dischargeClaimedHolderDead`. | Source review. Model action separation captures claim-to-discharge race, but not actual lock-acquisition steps. |
| `UserPark` | `lifecycle.prepareRunningPark` publishes parking; syscall/fault wait paths use it before their eventual scheduler hop. | Source review of primitive and `thread.suspendOnPortInner`; wait-container linkage is a separate instruction sequence under a reaching lock, fused in model. Full path audit remains pending. |
| `HopRelease` | `scheduler.hopParkYield` / `hopParkRun` use `arch.cpu.hopToStackAndCall` to leave the outgoing kstack; `scheduler_hop_*` land on park stack. | Source review of scheduler path. Model treats release as an atomic step; arch-specific hop assembly and release-store parity remain to review. |
| `HopCommitWait` | `scheduler.dischargeOwnedParking` calls `lifecycle.commitParkingWaiting` and clears current. | Source review. |
| `HopCommitRequeue` | `scheduler.dischargeOwnedParking` chooses a fresh affinity core and calls `enqueueOnCore`; `drainDeferredRequeuesLocked` is the local deferred path. | Source review; model chooses nondeterministic destination, omitting priority and affinity algorithm. |
| `HopCommitPended` | `scheduler.dischargeOwnedParking` waits for payload, clears current, then enqueues. | Source review; `waitForPendedPayload` is a spin outside model atomicity. |
| `HopCommitRetired` | `scheduler.dischargeOwnedParking` clears current and finalizes on safe stack after dead-gen check. | Source review; model coalesces on-CPU and stack-safety checks. |
| `HopCommitClaimed` | No literal `claimed` arm in `scheduler.dischargeOwnedParking`; claimant-side `PENDED = FALSE` is a historical rev-3 machine. | Model-only falsifier/compatibility action; current kernel uses `pended` for parking-origin claims. |
| `TickPreempt` | `scheduler.preempt` calls `yieldTo`; `yieldToTarget` uses `prepareRunningPark(.requeue)` under core lock. | Source review; `PIN_GATE` is in lifecycle primitive and IRQ entry discipline. No stand-alone kernel race test established here. |
| `BoundaryRetired` | `scheduler.dispatchTailBody` checks lifecycle before context load; syscall/IRQ exits enter scheduler paths that discharge retired current. | Source review; x64 and aarch64 boundary entry points still need direct path audit. |
| `VcpuGuestExit` | `scheduler.switchTo` calls `arch.vm.enterGuest`, then `port.fireVmExit` on an ordinary exit. | Source review; guest instructions are outside model. |
| `VcpuCancelExit` | Both `arch/{x64,aarch64}/vm_runloop.enterGuest` check `retired` at the top of their guest loop and return `cancelled`; `scheduler.switchTo` skips `fireVmExit`, then `dischargeOwnedParking`. | **Automated** model/source order check with x64, arm, and scheduler mutation fixtures; focused TLC `vcpu_cancel` pass and `vcpu_nocancel` falsifier. This checks the acknowledgement path, **not arch-state lifetime**. |
| `RetireEnabled`, `RetireThreadsAfter`, `RetireCoresAfter`, `RetireThread` | `thread.retireAndBumpDeadGen` marks retiring, waits pins, removes ready queue, calls `lifecycle.retire`, then flips dead gen; `lifecycle.retire` waits for pended payload before CAS. | Source review and lifecycle model `small`/`vcpu_cancel` rows. Retire source is a multi-instruction protocol; model uses one atomic action. Owner-core cancellation is represented as `vm=cancel` but source relies on wake IPI and guest-loop check. |
| `RetireUnwind` | Legacy/falsifier action, enabled only by the defective switch; current retire cleanup runs after state CAS in `terminate` and `destroyThreadRefLockedMode`. | No production correspondence claim; see model `N4` falsifier and README G4. |
| `ClearFreedDirective` | `thread.finalizeDestroyMarkedDead` calls `lifecycle.markDirectiveDead` before `slab_instance.destroyAlreadyMarked` zeroes/recycles the slot. | G11-focused model proof and code review; physical slab gen flips earlier at `retireAndBumpDeadGen` (README G11). |

## Milestone 2: wait, wake, rendezvous, and directives

The corresponding kernel suites are `futex_wait_*`, `futex_wake_*`,
`recv_*`, `reply_*`, and `suspend_*` in `tests/suite/build.zig`. The
required precommit ran all listed cases on x86 and Pi5 bare metal for
milestone 1. Those are interface tests; none is claimed to force every
model interleaving. The TLC rows named below exercise the abstract
transition relation, not the Zig source.

| Active action | Kernel correspondence | Evidence and limit |
|---|---|---|
| `WakeStart` | `futex.wake`, `port.propagateClosedToReceivers`/`finalizeClosedSenders`, and `thread.resumeFromReply` use `beginWaitingClaimPinned`/`beginWaitingClaim` to win waiting or parking episodes. | Code review; `futex_wake_*`, `recv_*`, `reply_*` kernel suites and model `small`. Pop, gen validation, CAS, and unlink take more instructions than the model action; the reaching lock and pin supply their intended exclusion. The separate recv queued-sender pop is a mismatch below. |
| `WakePlace` | `futex.wake` and `port.publishReceiverAndUnpin` place a claimed target through `scheduler.enqueue`; `lifecycle.finishClaimedReady` publishes it. | Code review and same suites; actual priority and affinity selection are below set-queue model granularity. |
| `WakePendDone` | `futex.wake`, `port.publishReceiverAndUnpin`, and timer expiry call `lifecycle.publishPendedPayload`, then release their target pin. | Code review and `small`/`pinord` TLC safety rows. Payload writes occur before the release store in source; the model makes completion one step. |
| `WakeTgtRetired` | `scheduler.enqueuePinnedClaimed` can fail publication after a retire; `thread.dischargeClaimedHolderDead` and retire/finalize routing discharge holder obligations. | Code review; model immediately enters `finalizing`, whereas source may return from enqueue and leave finalization to the retirer or owner core. No dedicated kernel race test identified; equivalence of all such outcomes remains open. |
| `RelwaitPlace` | Rev-3 `PENDED = FALSE` falsifier path, not a production wait algorithm. | `rev3_x2`/`rev3_x3` TLC expected violations; no production correspondence. |
| `SuspendStart` | `port.suspendThread` selects a ready target; `thread.suspendOnPortInner` calls `scheduler.claimReadyFromQueue`, which pins, CASes, and removes under the run-queue lock. | Code review; `suspend_*` kernel suite and model `small`. The model omits handle resolution, gen locks, and port-lock acquisition. |
| `SuspendPlace` | `thread.suspendOnPortInner` installs event/wait fields and calls `lifecycle.commitClaimedWaiting`, then links the port sender queue or rendezvouses. | Code review; `suspend_*` and `recv_*` suites. Model fuses descriptor writes and port linkage at a coarser granularity. |
| `SuspendTgtRetired` | `commitClaimedWaiting` can lose to retirement; `suspendOnPortInner` releases the claim pin and returns an error, with finalization routed through retire owner. | Code review; no focused race fixture shown. Model immediately enters `finalizing`; source may defer it. |
| `RvStart` | `thread.suspendOnPortInner` publishes sender parking before `port.rendezvousWithReceiver` claims a waiting receiver under Port lock. | Code review; `recv_*`/`suspend_*` suites and TLC `small`. The model combines both publishes in one action; source uses multiple instructions under Port lock. |
| `RvDeliver` | `port.rendezvousWithReceiver` drops Port lock, mints/transfers in `deliverEvent`, then `publishReceiverAndUnpin` handles success/failure or pended payload. | Code review; `recv_*`/`reply_*` suites. The model's mint success/failure alternatives are broad abstractions of process-lock and attachment work. |
| `DirSelfMark` | `lifecycle.selfMarkSuspending` is called by `port.suspendThread`. | **Mismatch:** source marks before target state selection, including ready and idle-wait paths. Model restricts it to the remote-running directive path. `Stygia-o4a.4.2.2.3`; `suspend_*` does not establish the overlapping-call E_BUSY scope. |
| `DirSelfAbort` | `port.suspendThread` has a deferred `clearSelfDirective`; a failed `claimRemoteSuspend` returns E_BUSY. | Code review; clear is a CAS on the caller word. The source's earlier mark makes this broader than the model abort. |
| `DirClaim` | `port.suspendThread` pins a remote running target under its gen lock and uses `lifecycle.claimRemoteSuspend` (`none -> claiming` with owner slot). | Code review; `suspend_*` suite and `diraba`/`dirf6fix` TLC rows. The model's target generation and owner are separate fields; source packs owner slot into one atomic word. |
| `DirArm` | `port.suspendThread` installs port/owner/caps and calls `lifecycle.armRemoteSuspend` (`claiming -> armed` CAS); then interrupts owner core. | Code review; same suites/rows. Source uses held gen lock and target pin across the arm; model collapses lock steps. |
| `DirLoop` | `port.waitForSuspendDirective` spins on exact arm word, rechecks target gen and port liveness, handles `failed`, and identity-gated disarm. | Code review; `suspend_*` and `dirf6fix`. The model stutters during pure spin; source has periodic scheduler kicks and retry branches. |
| `DirDrop`, `DirFail` | `thread.consumeSuspendDirective` and `failSuspendDirective` publish `directive_result`, then CAS the arm to `failed`; waiter reads and acks via `waitForSuspendDirectiveFailure`. | Code review; `dirf6fix` model gate. Stale-port and other failures share the same source helper; model splits them for bounded falsifiers. |
| `DirConsume` | `thread.consumeSuspendDirective` calls `suspendOnPortInner`; success disarms the exact word after parking/rendezvous publication. | Code review; `suspend_*`, `recv_*`. The model makes park publish plus directive reset atomic; source performs separate operations under Port lock and target pin. |
| `FireAt` | `port.expireTimedRecvWaiters` and `futex.expireTimedWaiters` snapshot deadlines, revalidate generation/episode, remove wait nodes, then claim; device IRQ-specific wake sources remain to audit. | Code review; `recv_*` and `futex_wait_*` suites. A timer scan is split into two lock phases, not one atomic pop+claim; model treats successful episode claim as one action and omits stale-snapshot branches. |
| `IrqWakePlace`, `IrqPendDone` | Timer expiry uses `scheduler.enqueue` for claimed and `lifecycle.publishPendedPayload` for pended; pins are released afterward. | Code review; same suites. Model represents an interrupt frame as explicit state, while source handler execution/IRQ masking supplies the ordering. |
| `IrqRelwait` | Rev-3 `PENDED = FALSE` falsifier path only. | `rev3_x2` TLC deadlock; no production correspondence. |
| `RecvPop` | **Mismatch:** `port.recvInner` pops a queued sender under Port lock, then unlocks before `deliverEvent`/`mintReply`; no claim or pin spans the unlocked interval. | `Stygia-o4a.4.2.2.5` (P1). The model has `waiting -> claimed` and a holder pin; source can race remote terminate/finalize/reuse. Existing `recv_*` suite does not force that window. |
| `FastPath`, `ReplyFP` | x64 `arch/x64/interrupts.zig` inline asm classifier implements fused suspend/reply paths with slow-path fallback; aarch64 uses generic Zig paths. | Code review of entry/classifier only; **full asm state-write audit remains open** (README assigns `stygia-qde`). `recv_*`/`reply_*` interface suites cannot alone prove the fused intermediate-state compression. |
| `AffMove` | `thread.repairAffinityPlacement` claims a ready target then calls `scheduler.enqueue` using current affinity. | Code review and `affinity_*` kernel suite. Model only enables moves when old queue is excluded; source may claim/requeue any ready target. Priority repair also uses this shape despite its model identity abstraction: `Stygia-o4a.4.2.2.4`. |

### Open kernel mismatch exposed by this review

`Stygia-o4a.4.2.2.1` records a remote vCPU lifetime race. Both
`thread.terminate` and `destroyThreadRefLockedMode` call
`arch.vm.freeVcpuArchState` **before** `routeRetiredFinalize` wakes or waits
for the remote owner. Both arch `enterGuest` loops cache the state pointer
and use it after guest exits. The model's `VcpuCancelExit` establishes an
eventual owner acknowledgement, but has no state-page lifetime variable and
cannot rule out this use-after-free. The new source gate intentionally does
not certify this failed obligation.

Other reviewed mismatches are filed as `Stygia-o4a.4.2.2.2` (S7 failed
dispatch routing), `.3` (self-mark scope), `.4` (ready priority move), and
`.5` (queued-sender recv lifetime). They are implementation/design parity
questions, not model-only atomicity gaps.

### Still to review

Termination spin, pin, creation, G16/restart details, full x64 fast-path
assembly, device IRQ wake sources, and remaining arch boundary paths still
need direct review. The rows above are code correspondences or explicit
mismatches; they do not yet satisfy the full-bead acceptance criterion.
