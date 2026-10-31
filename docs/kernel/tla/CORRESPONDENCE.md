# ThreadLifecycle action-to-kernel correspondence

Status: **in progress**, reviewed against `main` at `cf760313` (2026-10-31).
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
| `VcpuCancelExit` | Both `arch/{x64,aarch64}/vm_runloop.enterGuest` check `retired` at the top of their guest loop and return `cancelled`; `scheduler.switchTo` skips `fireVmExit`, then `dischargeOwnedParking`. `thread.finalizeDestroyMarkedDead` frees vCPU arch state only after owner-side eviction/finalization. | Automated model/source order check with x64, arm, and scheduler mutation fixtures; focused TLC `vcpu_cancel` pass and `vcpu_nocancel` falsifier. Kernel lifetime fix `6bcee799` and `vcpu_retire_remote` cover retirement and state-page reuse, but that test does not enter a real guest with a cached state pointer (`Stygia-s0p`). |
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

## Milestone 3: creation, termination, process lifecycle, and model-only steps

`create_thread_*`, `create_vcpu_*`, `terminate_*`, `delete_*`,
`process_restart_*`, `handle_restart_*`, `reply_restart_*`, and the VMAR
restart cases are the available kernel interface suites. The first two
milestone gates ran them as part of 380/380 cases on each x86 boot and
1140/1140 aggregate cases on Pi5 bare metal. These broad results show
interface regressions did not appear in those runs. The specific races
listed below need focused tests. The existing G16/restart source-order
checker and its four earlier mutation fixtures are narrower than a
process teardown/refcount proof.

| Active action | Kernel correspondence | Evidence and limit |
|---|---|---|
| `Init` | Boot initializes per-core scheduler state; initial user threads are created through `thread.allocThread`/`process.createProcess`. | Model seed, not a runtime kernel transition. No code-level one-to-one state mapping exists for TLC's bounded initial thread set. |
| `ProcessDie` | `process.claimExitLocked` claims an exit decision; `destroyPhase1` dead-marks the process gen so `scheduler.processRefAlive` rejects future dispatch. | Model environment surrogate: one `dd` bit can flip at a time, while source has a process-wide gen gate. `S7Claim`/`S7Retire` remains a separate mismatch (`.2`). |
| `QueueTeardown` | `derivation.delete(SLOT_SELF)` and `port.queueFaultProcessTeardown` call `scheduler.queueCurrentTeardown`; it writes one typed request under the core lock. | G16 source-order gate; focused G16 TLC pass/falsifier rows; `delete_*`/fault cases. The model makes process phase `queued` visible with the request; source has a separate `claimExitLocked` before queue publication. |
| `SelfRetireForTeardown` | Both exit paths call `thread.parkSelfFaulted` after queuing; it marks retiring and retires, then scheduler hops off the caller kstack. | Source review and G16 model external-retire probe. The model handles an already-retired caller; source `lifecycle.retire` returns immediately in that case. |
| `ConsumeTeardown` | `scheduler.scheduler_hop_run`/`scheduler_run_after_park` drain the pending request on a safe stack; `drainTeardown` clears the core slot before `runProcessTeardown`. | G16 source-order gate and mutation fixtures; G16 TLC rows. `active` is an abstract ownership state, not a literal second core slot in source; the request is held by the park-stack frame. |
| `TeardownRetire` | `process.destroyPhase2` calls `thread.destroyThreadsInProcess`, which retires each matching live thread. | Source review and broad `delete_*`/process suites. The model compresses slab walk, gen validation, per-thread cleanup, and deferred finalize. |
| `FinishTeardown` | `process.destroyPhase2` waits at `scheduler.awaitProcessQuiesced`, releases VMAR/handle/root resources, and destroys the process slab after the thread walk. | Source review; G16 TLC completion probe and broad suites. Model waits for every abstract thread to be `freed`; source uses on-core/root barriers and zombie finalization. Refcount arithmetic and byte releases are outside model. |
| `RestartQuiesced` | `scheduler.awaitProcessQuiesced` checks active roots and committed/current threads before `process.restartProcess` walks old threads or VMARs. | Restart source-order gate and `process_restart_*` suite. Model predicate quantifies current thread only and omits active translation-root state. |
| `RestartRetire` | `process.restartProcess` invokes `thread.destroyThreadForRestart` for non-persist old threads, preserving stale reply-handle behavior. | Restart gate and `process_restart_term_*`/`thread_restart_policy` suites. Model `rp` is a bounded policy abstraction. |
| `RestartApply` | `restartProcess` evicts cores, retires/recreates old threads, applies VMAR policy and handle/reply policy, clears `restarting`, then enqueues survivors. | Restart source-order gate with gate-clear mutation; restart model configs and kernel suites. One model action compresses many source steps. Intermediate states and byte/refcount effects are not checked by TLC. |
| `RestartFallback` | `scheduler.runProcessTeardown` tries `restartProcess`; on false it clears caller-thread ownership and enters `runProcessTeardownWithoutRestart`. | Source-order gate and fallback mutation; restart fallback TLC configs. Model makes fallback one state update; source can fail at several policy points. |
| `TermStart` | `thread.terminate` resolves the target handle and enters retirement path, including self target. | Source review; `terminate_*` suite and `mterm`/`mtermfix` TLC pair. The model omits capability resolution errors and gen-lock acquisition. |
| `TermRetire` | `thread.retireAndBumpDeadGen` marks retiring, waits pins, removes ready queue membership, retires state, flips dead gen. | Source review; `terminate_*` suite. The model's one retire step hides pre-CAS wait and cleanup ordering. The `mark_state` protocol differs (`.7`). |
| `TermStale` | `thread.terminate` returns E_TERM when the target gen lock rejects a stale handle; if `retireAndBumpDeadGen` sees an already retired target, it returns OK. | The model has no return-code variable, so this action covers both terminal outcomes (`retired`, `finalizing`, `freed`). It excludes live pinned, directive-pinned, and pended targets: those remain in `termR` until `TermRetire` is enabled. The `termstale_reach`/`termstale_safe` TLC pair checks a reachable blocked-live state and excludes a stale return there. The pre-CAS pin/payload wait is still represented by a guard, not individual kernel instructions. |
| `TermWait` | `thread.routeRetiredFinalize` sends a remote IPI and waits for the target to leave `current_thread` unless the target is self or the caller becomes retired. The retired-caller check uses `lifecycle.load` in the wait loop. | **Repaired `.6`:** `terminate_mutual_remote` synchronizes two pinned callers, requires both to attempt termination, and probes both owner cores after the calls. The original loop fails the probe on aarch64 TCG; the repaired loop passes repeated x64 KVM and aarch64 TCG runs. This race test cannot prove every interleaving or replace the `mtermfix` model check. W4 owed-mark wait still has no source counterpart (`.7`). |
| `PinAcq`, `PinRel` | Representative model episode for any lock class with a preemptible thread-context hold. Current tree's effective-mask analysis says the production pin-class set is empty. | **Model-only over-approximation**, retained for F3/C1 falsifiers (`pinord`). There is no production `PinAcq` call to map; real claim pins are represented in wake/suspend/steal actions and implemented by `lifecycle.tryPinLive`/`releasePin`. |
| `PinBump`, `PinUnlock` | `PIN_BUMP_FIRST = FALSE` defective-machine half-states only. | `pinord` TLC falsifier; no production correspondence. |
| `CreateThread` | `thread.allocThread` initializes a private slot then publishes it live; `syscall.createThread` mints handle(s) and later calls `scheduler.enqueueOnCore`. vCPU creation uses `publishMintedVcpuAndEnqueue` under an exit-port lock and lifecycle pin. | Source review; `create_thread_*`/`create_vcpu_*` suites. **Atomicity gap:** model fuses slab publication and ready queue insertion. Ordinary source creation has a live `.ready` slab before its queue link; whether this can produce an observable failed dispatch under concurrent teardown requires a dedicated test/proof. |
| `DirectiveDispatchThread` | `scheduler.dequeueLocalReadyLocked` is the corresponding normal dispatch. | This action belongs only to the reduced `DirectiveNext` checking relation; it fuses `DispatchThread` and `DispatchLoad`, so no separate production path exists. |
| `Quiescent`, `Terminating` | TLC's terminal-state predicate and stuttering self-loop. | **Model-only harness actions**, with no kernel operation to map. |

The architecture entry path reviewed for `TickPreempt`, `DirConsume`, and
`BoundaryRetired` is x64 `arch/x64/interrupts.zig:dispatchInterrupt`
and aarch64 `arch/aarch64/exceptions.zig:handleIrqLowerEl` / the SVC
entry. Both async user IRQ handlers check a pending directive before
their scheduler handler and guard the return on current-thread identity;
the scheduler tail rechecks lifecycle before loading the saved context.
The x64 inline IPC assembly and the arch stack-switch instructions have
not had a complete instruction-by-instruction correspondence audit. The
kernel suites passing on both architectures are functional evidence,
not a proof of every interrupt/return interleaving.

### Abstraction classes and unresolved obligations

- **Model-only/historical:** `Init` seed, `Terminating`, `Quiescent`,
  `DirectiveDispatchThread`, `PinAcq`/`PinRel` with today's empty class,
  `PinBump`/`PinUnlock`, `RelwaitPlace`, `IrqRelwait`, `HopCommitClaimed`,
  and `RetireUnwind` under the current feature switches.
- **Source steps fused by model:** park publish and linkage, scheduler
  commit and dispatch load, one-shot pop and claim, directive park and
  disarm, normal creation publish and enqueue, phase-2 teardown, and
  restart policy application. The named locks/pins above justify some
  fusion, but the source's split intervals remain subject to review.
- **Mismatches under active switches:** `.2` S7 routing, `.3` self-mark scope,
  `.4` ready priority move, `.5` recv queued-sender ownership, and `.7`
  marking protocol. `.1` and `.6` are repaired in the kernel and covered by
  focused runtime tests. The `.8` model guard is repaired and checked by the
  `termstale_reach`/`termstale_safe` pair. These results do not resolve the
  remaining mismatches.

### Repaired vCPU state lifetime mismatch

`Stygia-o4a.4.2.2.1` identified a remote vCPU lifetime race. Fix `6bcee799`
moved `arch.vm.freeVcpuArchState` into `thread.finalizeDestroyMarkedDead`,
after owner eviction or owner-side finalization. The model's
`VcpuCancelExit` establishes eventual owner acknowledgement but has no
state-page lifetime variable. `vcpu_retire_remote` covers remote retirement
and state-page reuse; a real guest `VMRESUME` witness remains `Stygia-s0p`.

Additional reviewed mismatches are filed as `Stygia-o4a.4.2.2.2` (S7 failed
dispatch routing), `.3` (self-mark scope), `.4` (ready priority move), and
`.5` (queued-sender recv lifetime). They are implementation/design parity
questions, not model-only atomicity gaps. The final table names repaired `.6`,
open `.7`, and repaired model guard `.8`.

### Review boundary

The tables cover the active model actions through the creation and
process-lifecycle families below. Full x64 fast-path assembly, device
IRQ wake sources, arch stack-switch instructions, and the unresolved
race/atomicity obligations still need focused review or tests. The
parent bead remains open until the active mismatches are resolved.
