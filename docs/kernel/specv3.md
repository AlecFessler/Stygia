# Zag Microkernel Specification v3.0

## §[scope] Scope

## §[syscall_abi] Syscall ABI

Syscalls transfer payload via 128 **virtual registers** (vregs). The low-numbered vregs are backed by architecture GPRs; the rest spill to the user stack.

### vreg mapping (x86-64)

| vreg | location |
|---|---|
| 0 | `[rsp + 0]` — syscall word |
| 1 | rax |
| 2 | rbx |
| 3 | rdx |
| 4 | rbp |
| 5 | rsi |
| 6 | rdi |
| 7 | r8 |
| 8 | r9 |
| 9 | r10 |
| 10 | r12 |
| 11 | r13 |
| 12 | r14 |
| 13 | r15 |
| 14..127 | `[rsp + (N - 13) * 8]` — stack |

rsp, rcx, and r11 are not GPR-backed: rsp is the stack pointer anchor, and rcx/r11 are clobbered by `sysret` for return address and RFLAGS.

### vreg mapping (aarch64)

| vreg | location |
|---|---|
| 0 | `[sp + 0]` — syscall word |
| 1..31 | x0..x30 |
| 32..127 | `[sp + (N - 31) * 8]` — stack |

### syscall word

Bits 0-11 of vreg 0 carry the syscall_op (0..4095). The op range is partitioned to let the kernel classify a syscall in two instructions on the IPC fast path:

- `0..13` — fast suspend. The op value IS `payload_count` (and `pair_count` is implicitly 0). The entire syscall word must equal exactly the op value: bits 4-63 must be zero on entry. No other syscall — current or future — may take a value in this range.
- `14` — suspend (general variant). Carries `pair_count` and `payload_count` as syscall-word fields per §[port].suspend.
- `15..4095` — every other syscall.

Higher bits are reserved unless a syscall claims them — when claimed, each syscall's spec calls out the layout (e.g., `pair_count` in bits 12-19, `tstart` in bits 20-31, `reply_handle_id` in bits 32-43 on `recv` return / bits 20-31 on `reply` entry, `recv_port_handle_id` in bits 32-43 on `reply` entry, `event_type` in bits 44-48, `payload_count` in bits 49-55 on `recv` return). Bits not assigned by the invoked syscall must be zero on entry; the kernel returns E_INVAL if a reserved bit is set.

## §[error_codes] Error Codes

Error codes are returned in vreg 1 by syscalls that fail. Zero indicates success.

| Value | Name | Meaning |
|---|---|---|
| 1 | E_ABANDONED | the peer that would resolve a pending suspension was destroyed before it could do so |
| 2 | E_BADADDR | a user address argument is not a valid mapped address in the caller's domain |
| 3 | E_BADCAP | handle id is not a valid handle of the expected type in the caller's table |
| 4 | E_BUSY | target object is in a state that disallows the operation (e.g., target EC is running and not suspended) |
| 5 | E_CLOSED | port has no remaining endpoints to make progress against the call |
| 6 | E_FULL | a fixed-capacity table cannot accommodate the requested allocation (caller's handle table or target's handle table) |
| 7 | E_INVAL | argument violates a structural constraint (reserved bits set, value out of range, alignment, size, etc.) |
| 8 | E_NODEV | required hardware feature is not present on this platform |
| 9 | E_NOENT | named entry does not exist in the targeted structure |
| 10 | E_NOMEM | insufficient kernel memory to complete the operation |
| 11 | E_NOSPC | insufficient address space for the requested range |
| 12 | E_PERM | required cap is missing on the handle (or self-handle), or argument exceeds a ceiling |
| 13 | E_REFUSED | a pending IDC call was rejected by policy before a reply could be produced |
| 14 | E_TERM | handle references an execution context that was terminated; the stale handle is removed from the caller's table on the same call |
| 15 | E_TIMEOUT | a wait expired before its wakeup condition was met |

## §[capabilities] Capabilities

An unforgeable reference to a kernel object, paired with bits that gate operations on that object.

Capability layout:

```
word 0:
 63            48 47                          16 15   12 11         0
┌────────────────┬──────────────────────────────┬───────┬────────────┐
│   cap (16)     │       _reserved (32)         │type(4)│   id(12)   │
└────────────────┴──────────────────────────────┴───────┴────────────┘

word 1 (field0):
 63                                                                  0
┌─────────────────────────────────────────────────────────────────────┐
│                     type-dependent metadata                         │
└─────────────────────────────────────────────────────────────────────┘

word 2 (field1):
 63                                                                  0
┌─────────────────────────────────────────────────────────────────────┐
│                     type-dependent metadata                         │
└─────────────────────────────────────────────────────────────────────┘
```

| Field | Bits | Purpose |
|---|---|---|
| id | 12 | handle id (table index, 0..4095) |
| type | 4 | kernel object type tag |
| _reserved | 32 | reserved |
| capabilities | 16 | type-dependent capabilities bitfield |
| field0 | 64 | type-dependent metadata |
| field1 | 64 | type-dependent metadata |

Syscall arguments that take a handle carry only the 12-bit handle id — the caller's handle-table index. Such arguments may be named `handle` directly or after the role they play (e.g. `target`, `exit_port`). The kernel resolves the id against the caller's table and reads the full capability for cap checks and dispatch.

A capability domain's handle table contains at most one handle referencing any given kernel object. Operations that would mint a duplicate handle into a table already containing one referencing the same object instead coalesce: the existing handle's caps are upgraded to the union of its prior caps and the incoming caps (bounded by any receive-time filters such as `idc_rx`), and its slot id is unchanged.

Some handles carry kernel-mutable snapshots in their field0/field1 (e.g., an EC handle's priority and affinity, a VMAR handle's `cur_rwx`/`map`/`device`). The kernel cannot keep these snapshots atomically synchronized across all handle copies at once. Any syscall that takes such a handle implicitly refreshes that handle's snapshot from the authoritative kernel state as a side effect; an explicit `sync` syscall is also provided when the caller wants a fresh snapshot without performing any other operation.

Handle types a capability domain can hold:

| Type | How obtained |
|---|---|
| capability_domain_self | inherent (slot 0 at capability domain creation) |
| capability_domain (IDC handle) | `create_capability_domain`; received via suspend/reply transfer |
| execution_context | `create_execution_context`; received via suspend/reply transfer |
| page_frame | `create_page_frame`; received via suspend/reply transfer |
| virtual_memory_address_region | `create_vmar`; received via suspend/reply transfer |
| device_region | kernel-issued at boot to root service; received via suspend/reply transfer |
| port | `create_port`; received via suspend/reply transfer |
| reply | created by recv |
| virtual_machine | `create_virtual_machine` |
| timer | `timer_arm`; received via suspend/reply transfer |

### Lifetimes

Kernel objects are grouped by the **ceiling** of their lifetime — the longest they could possibly persist. An object may die sooner (via delete, revoke, kill, etc.) but cannot outlive its ceiling.

- **System lifetime** — Device Region, Capability Domain. Could persist as long as the kernel runs.
- **Refcount lifetime** — Port, Page Frame, Timer. Bounded by the distributed set of handles referencing them.
- **Capability domain lifetime** — Execution Context, Virtual Memory Address Region, Virtual Machine. Cannot outlive the capability domain they are bound to.
- **Execution context lifetime** — Event Route, Reply. Event routes are kernel-held bindings (not handles) that are swept when the execution context they route from is destroyed. Replies cannot outlive the execution context they are bound to.

### restrict

#### Summary

Reduces the caps on a handle in place. The new caps must be a subset of the current caps.

#### Declaration

```
restrict([1] handle, [2] caps) -> void
  syscall_num = 15

  [1] handle: handle in the caller's table (bits 0-11; upper bits _reserved)
  [2] caps: u64 packed as
    bits  0-15: new caps
    bits 16-63: _reserved
```

#### Description

Most cap fields use bitwise subset semantics: a bit set in `[2].caps` must also be set in the handle's current caps. The `restart_policy` field on EC handles (bits 8-9) and VMAR handles (bits 9-10) is a 2-bit enum ordered by privilege (lowest privilege = numeric 0); for these fields "reducing" means the new numeric value is less than or equal to the current value, not bitwise subset.

#### Capabilities

None — reducing authority never requires authority.

#### Errors

**E_BADCAP** — `[1]` is not a valid handle.

**E_PERM** — `[2].caps` is not a subset of the handle's current caps (bitwise for most fields; numeric ≤ for `restart_policy` on EC/VMAR handles).

**E_INVAL** — reserved bits set in `[1]` or `[2]`.

#### Tests

[test 01] returns E_BADCAP if [1] is not a valid handle.
[test 02] returns E_PERM if any cap field in [2].caps using bitwise semantics has a bit set that is not set in the handle's current caps.
[test 03] returns E_PERM if the handle is an EC handle and [2].caps' `restart_policy` (bits 8-9) numeric value exceeds the handle's current `restart_policy`.
[test 04] returns E_PERM if the handle is a VMAR handle and [2].caps' `restart_policy` (bits 9-10) numeric value exceeds the handle's current `restart_policy`.
[test 05] returns E_INVAL if any reserved bits are set in [1] or [2].
[test 06] on success, the handle's caps field equals [2].caps.
[test 07] on success, syscalls gated by caps cleared by restrict return E_PERM when invoked via this handle.

### delete

#### Summary

Releases a handle from the calling domain's handle table. Type-specific side effects apply.

#### Declaration

```
delete([1] handle) -> void
  syscall_num = 16

  [1] handle: handle in the caller's table (bits 0-11; upper bits _reserved)
```

#### Description

Per-type observable behavior:

| Handle type | Observable delete behavior |
|---|---|
| `capability_domain_self` | The calling domain is cleaned up; each handle in its table is released with its type-specific delete behavior applied |
| `capability_domain` (IDC) | Release handle. Domain has system lifetime; it does not terminate when IDC handles drop |
| `execution_context` | Release handle. ECs have capability-domain lifetime; they are not destroyed by handle drops |
| `page_frame` | Release handle. When the last handle to a page frame is released, the physical memory returns to the free pool |
| `virtual_memory_address_region` | Non-transferable; exactly one handle exists. Delete unmaps everything installed, frees the address range, releases the handle |
| `device_region` | Release handle. When the last handle to a device region is released, the region returns to the root service |
| `port` | Decrement the send refcount if this handle has `bind`; decrement the recv refcount if this handle has `recv`. When the recv refcount hits zero, suspended senders resume with `E_CLOSED`. When the send refcount hits zero and no event routes target the port, receivers suspended on the port resume with `E_CLOSED`. Release handle |
| `reply` | If the suspended sender is still waiting, resume them with `E_ABANDONED`. Release handle |
| `virtual_machine` | Non-transferable; exactly one handle exists. Destroy the VM: all vCPU ECs terminate, guest memory is freed, kernel-emulated LAPIC/IOAPIC/timer state is torn down. Release handle |
| `timer` | Release handle. When the last handle to the timer is released, the kernel cancels the timer if armed and reclaims its kernel state |

#### Capabilities

None.

#### Errors

**E_BADCAP** — `[1]` is not a valid handle.

**E_INVAL** — reserved bits set in `[1]`.

#### Tests

[test 01] returns E_BADCAP if [1] is not a valid handle.
[test 02] returns E_INVAL if any reserved bits are set in [1].
[test 03] on success, the handle is released and subsequent operations on it return E_BADCAP.

### revoke

#### Summary

Releases every handle transitively derived from the target via `copy`, across all capability domains. The target handle itself is not released — use `delete` for that.

#### Declaration

```
revoke([1] handle) -> void
  syscall_num = 17

  [1] handle: handle in the caller's table (bits 0-11; upper bits _reserved)
```

#### Description

A handle that was copied from the target and then subsequently moved is still a derivation of the target — moving a handle keeps it on the copy ancestry chain rather than orphaning it. A domain that has moved a handle elsewhere no longer holds it and cannot revoke it; whoever holds the copy ancestor still can, and the revoke will reach the moved descendant through the preserved chain.

Each released descendant is processed with the type-specific behavior defined for `delete`.

#### Capabilities

None.

#### Errors

**E_BADCAP** — `[1]` is not a valid handle.

**E_INVAL** — reserved bits set in `[1]`.

#### Tests

[test 01] returns E_BADCAP if [1] is not a valid handle.
[test 02] returns E_INVAL if any reserved bits are set in [1].
[test 03] on success, every handle transitively derived via copy from [1] is released from its holder with the type-specific delete behavior applied.
[test 04] a handle that was copied from [1] and then subsequently moved is released by revoke([1]).
[test 05] revoke([1]) does not release [1] itself.
[test 06] revoke([1]) does not release any handle on the copy ancestor side of [1].

### sync

#### Summary

Refreshes a handle's kernel-mutable field0/field1 snapshot. No-op for handles whose state does not drift.

#### Declaration

```
sync([1] handle) -> void
  syscall_num = 18

  [1] handle: handle in the caller's table
```

#### Capabilities

None.

#### Errors

**E_BADCAP** — `[1]` is not a valid handle.

**E_INVAL** — reserved bits set in `[1]`.

#### Tests

[test 01] returns E_BADCAP if [1] is not a valid handle.
[test 02] returns E_INVAL if any reserved bits are set in [1].
[test 03] on success, [1]'s field0 and field1 reflect the authoritative kernel state at the moment of the call.

## §[capability_domain] Capability Domain

A capability domain is a set of capabilities usable by execution contexts bound to the domain.

### Self handle

Handle ABI:

```
word 0:
 63            48 47                          16 15   12 11         0
┌────────────────┬──────────────────────────────┬───────┬────────────┐
│   cap (16)     │       _reserved (32)         │type(4)│   id(12)   │
└────────────────┴──────────────────────────────┴───────┴────────────┘

word 1 (field0):
 63    56 55     48 47     40 39     32 31     24 23                  8 7         0
┌────────┬─────────┬─────────┬─────────┬─────────┬──────────────────────┬───────────┐
│port_clg│vm_clg   │ pf_clg  │ idc_rx  │cridc_clg│   vmar_inner_clg     │ec_inner_clg│
│  (8)   │  (8)    │   (8)   │   (8)   │   (8)   │       (16)           │    (8)    │
└────────┴─────────┴─────────┴─────────┴─────────┴──────────────────────┴───────────┘

word 2 (field1):
 63              38 37        32 31              16 15         8 7         0
┌──────────────────┬────────────┬──────────────────┬──────────────┬───────────┐
│ _reserved (26)   │fut_wait_max│restart_policy_clg│vmar_outer_clg│ec_outer_clg│
│                  │    (6)     │      (16)        │     (8)      │    (8)    │
└──────────────────┴────────────┴──────────────────┴──────────────┴───────────┘
```

cap (word 0, bits 48-63):

```
 15  14 13 12   11      10     9      8      7      6     5     4     3     2     1     0
┌──────┬────┬─────┬──────┬──────┬──────┬──────┬──────┬───────┬──────┬──────┬──────┬──────┬──────┬──────┐
│pri(2)│_rsv│timer│fut_wk│reply │restrt│power │setwal│  pmu  │ crpt │ crvm │ crpf │ crvr │ crec │ crcd │
│      │    │     │      │_plcy │      │      │      │       │      │      │      │      │      │      │
└──────┴────┴─────┴──────┴──────┴──────┴──────┴──────┴───────┴──────┴──────┴──────┴──────┴──────┴──────┘
```

| Bit(s) | Name | Gates |
|---|---|---|
| 0 | `crcd` — create capability domain | `create_capability_domain` syscall |
| 1 | `crec` — create execution context | `create_execution_context` syscall (target = self) |
| 2 | `crvr` — create virtual memory address region | `create_vmar` syscall |
| 3 | `crpf` — create page frame | `create_page_frame` syscall |
| 4 | `crvm` — create virtual machine | `create_virtual_machine` syscall |
| 5 | `crpt` — create port | `create_port` syscall |
| 6 | `pmu` — performance monitoring | `perfmon_*` syscalls |
| 7 | `setwall` — set wall-clock time | `time_setwall` syscall |
| 8 | `power` — power management | `power_*` syscalls |
| 9 | `restart` — domain restart on EC exit/fault | the kernel restarts the domain rather than tearing it down (see §[restart_semantics]) |
| 10 | `reply_policy` — reply caps survive restart | on restart, reply handles in the domain are kept (1) rather than dropped (0) |
| 11 | `fut_wake` — futex wake | `futex_wake` syscall |
| 12 | `timer` — mint timer | `timer_arm` syscall |
| 14-15 | `pri` — priority ceiling (0-3) | max priority any EC in this domain may be created with or raised to |

field0:

| field | bits | meaning |
|---|---|---|
| ec_inner_ceiling | 0-7 | max caps on EC handles held by this domain itself referencing its own ECs |
| vmar_inner_ceiling | 8-23 | max caps on VMAR handles held by this domain itself referencing its own VMARs (16 bits to fit all VMAR caps) |
| cridc_ceiling | 24-31 | see §[cridc_ceiling] |
| idc_rx | 32-39 | mask intersected with sent caps when this domain receives an IDC handle |
| pf_ceiling | 40-47 | max caps `create_page_frame` may mint when called from this domain (`max_rwx` bits 40-42, `max_sz` bits 43-44) |
| vm_ceiling | 48-55 | max caps `create_virtual_machine` may mint when called from this domain (`policy` bit 48) |
| port_ceiling | 56-63 | max caps `create_port` may mint when called from this domain (`xfer` bit 58, `recv` bit 59, `bind` bit 60) |

field1:

| field | bits | meaning |
|---|---|---|
| ec_outer_ceiling | 0-7 | max caps on EC handles held by other domains referencing ECs in this domain |
| vmar_outer_ceiling | 8-15 | max caps on VMAR handles held by other domains referencing VMARs in this domain |
| restart_policy_ceiling | 16-31 | max `restart_policy` value per handle type allowed at create time in this domain (see §[restart_semantics]); semantically inner, lives in field1 because field0 is full |
| fut_wait_max | 32-37 | max number of addresses the domain may pass to `futex_wait_val` or `futex_wait_change` per call (0..63); 0 disables futex wait entirely |

#### §[cridc_ceiling] cridc_ceiling

At `create_capability_domain`:

- The IDC handle the caller receives to the new domain has caps = the caller's `cridc_ceiling`.
- The IDC handle placed in the new domain's slot 2 has caps = the `cridc_ceiling` passed in the ceilings word.

All subsequent IDC handles to the new domain derive from these two originals by copy or move, subject to cap-subset rules.

#### §[idc_rx] idc_rx

When a domain receives an IDC handle over IDC:

- The installed handle has caps = the intersection of the caps attempted to be granted and the receiving domain's `idc_rx`.

[test 01] when a domain receives an IDC handle over IDC, the installed handle's caps = intersection of the granted caps and the receiver's `idc_rx`.

### IDC handle

Handle ABI:

```
word 0:
 63            48 47                          16 15   12 11         0
┌────────────────┬──────────────────────────────┬───────┬────────────┐
│   cap (16)     │       _reserved (32)         │type(4)│   id(12)   │
└────────────────┴──────────────────────────────┴───────┴────────────┘

word 1 (field0):
 63                                          24 23        16 15           0
┌─────────────────────────────────────────────┬─────────────┬───────────────┐
│              _reserved (40)                 │vmar_cap_clg │ec_cap_ceiling │
│                                             │    (8)      │     (16)      │
└─────────────────────────────────────────────┴─────────────┴───────────────┘

word 2 (field1):
 63                                                                  0
┌─────────────────────────────────────────────────────────────────────┐
│                         _reserved (64)                              │
└─────────────────────────────────────────────────────────────────────┘
```

Field layout:

| field | location | meaning |
|---|---|---|
| ec_cap_ceiling | field0 bits 0-15 | per-IDC ceiling on caps of EC handles minted via `acquire_ecs` through this IDC |
| vmar_cap_ceiling | field0 bits 16-23 | per-IDC ceiling on caps of VMAR handles minted via `acquire_vmars` through this IDC |

cap (word 0, bits 48-63):

```
 15                          6    5    4    3    2    1    0
┌─────────────────────────────┬──────┬──────┬──────┬──────┬────┬────┐
│      _reserved (10)         │rstrt │ aqvr │ aqec │ crec │copy│move│
│                             │_plcy │      │      │      │    │    │
└─────────────────────────────┴──────┴──────┴──────┴──────┴────┴────┘
```

| Bit | Name | Gates |
|---|---|---|
| 0 | `move` | transferring this handle via move to another capability domain |
| 1 | `copy` | transferring this handle via copy to another capability domain |
| 2 | `crec` — create execution context in referenced domain | `create_execution_context` with this handle as `target` |
| 3 | `aqec` — acquire ECs | `acquire_ecs` syscall on this IDC |
| 4 | `aqvr` — acquire VMARs | `acquire_vmars` syscall on this IDC |
| 5 | `restart_policy` | IDC handle behavior on domain restart: 0=drop, 1=keep (see §[restart_semantics]) |

### create_capability_domain

#### Summary

Creates a new capability domain from an ELF image carried in a page frame. The caller receives back an IDC handle to the new domain.

#### Declaration

```
create_capability_domain([1] caps, [2] ceilings_inner, [3] ceilings_outer, [4] elf_page_frame, [5] initial_ec_affinity, [6+] passed_handles)
  -> [1] idc_handle
  syscall_num = 19

  [1] caps: u64 packed as
    bits  0-15: self_caps          — caps on the new domain's slot-0 self-handle
    bits 16-23: idc_rx             — new domain's idc_rx (see §[capability_domain] Self handle)
    bits 24-63: _reserved

  [2] ceilings_inner: u64 packed as (matches self-handle field0)
    bits  0-7:  ec_inner_ceiling
    bits  8-23: vmar_inner_ceiling:
                   bit  8:     move
                   bit  9:     copy
                   bits 10-12: r/w/x
                   bit 13:     mmio
                   bits 14-15: max_sz (enum)
                   bit 16:     dma
                   bits 17-23: _reserved
    bits 24-31: cridc_ceiling      — new domain's cridc_ceiling (see §[capability_domain] Self handle)
    bits 32-39: pf_ceiling:
                   bits 32-34: max_rwx (r/w/x)
                   bits 35-36: max_sz (enum)
                   bits 37-39: _reserved
    bits 40-47: vm_ceiling:
                   bit 40:     policy
                   bits 41-47: _reserved
    bits 48-55: port_ceiling:
                   bit 50:     xfer
                   bit 51:     recv
                   bit 52:     bind
                   bits 48-49, 53-55: _reserved
    bits 56-63: _reserved

  [3] ceilings_outer: u64 packed as (matches self-handle field1)
    bits  0-7: ec_outer_ceiling
    bits  8-15: vmar_outer_ceiling
    bits 16-31: restart_policy_ceiling:
                   bits 16-17: ec_restart_max     (kill / restart_at_entry / persist / _reserved)
                   bits 18-19: vmar_restart_max    (free / decommit / preserve / snapshot)
                   bit 20:     pf_restart_max     (drop / keep)
                   bit 21:     dr_restart_max     (drop / keep)
                   bit 22:     port_restart_max   (drop / keep)
                   bit 23:     vm_restart_max     (drop / keep)
                   bit 24:     idc_restart_max    (drop / keep)
                   bit 25:     tm_restart_max     (drop / keep)
                   bits 26-31: _reserved
    bits 32-37: fut_wait_max         — max addresses per `futex_wait_*` call (0..63); 0 disables futex wait
    bits 38-63: _reserved

  [4] elf_page_frame: page frame handle containing the ELF image from offset 0

  [5] initial_ec_affinity: u64 core mask applied to the new domain's
      initial EC. Bit N = 1 allows the EC to run on core N. 0 = any
      core (kernel chooses). Same encoding as `create_execution_context`'s
      `[6] affinity`.

  [6+] passed_handles: each entry is a u64 packed as
    bits  0-11: handle id (12-bit handle in the caller's table)
    bits 12-15: _reserved
    bits 16-31: caps to install on the handle inserted into the new domain
    bit     32: move (1 = remove from caller; 0 = copy, both retain)
    bits 33-63: _reserved
```

#### Description

The ELF image is read from `elf_page_frame` starting at byte 0. The image must be position-independent; the kernel loads its segments at a randomized base in the ASLR zone (see §[address_space]). The pointer to the new domain's read-only view of its capability table is passed as the first argument to the initial EC's entry point.

The caller receives an IDC handle to the new domain with caps = the caller's own `cridc_ceiling`. The new domain's slot-2 self-IDC handle is minted with caps = the `cridc_ceiling` passed in [2]. The new domain's slot-1 initial-EC handle is minted with caps = the new domain's `ec_inner_ceiling` from [2].

#### Capabilities

- Self-handle: `crcd`
- `[1].self_caps` ⊆ caller's self-handle caps
- `[2].ec_inner_ceiling` ⊆ caller's `ec_inner_ceiling`
- `[2].vmar_inner_ceiling` ⊆ caller's `vmar_inner_ceiling`
- `[2].cridc_ceiling` ⊆ caller's `cridc_ceiling`
- `[2].pf_ceiling` ⊆ caller's `pf_ceiling`
- `[2].vm_ceiling` ⊆ caller's `vm_ceiling`
- `[2].port_ceiling` ⊆ caller's `port_ceiling`
- `[3].ec_outer_ceiling` ⊆ caller's `ec_outer_ceiling`
- `[3].vmar_outer_ceiling` ⊆ caller's `vmar_outer_ceiling`
- `[3].restart_policy_ceiling.*` ≤ caller's corresponding fields
- `[3].fut_wait_max` ≤ caller's `fut_wait_max`

#### Return value

`[1]`: IDC handle to the new domain with caps = caller's `cridc_ceiling`.

#### Errors

**E_PERM** — caller's self-handle lacks `crcd`, or any cap/ceiling argument exceeds the corresponding ceiling on the caller.

**E_BADCAP** — `[4]` is not a valid page frame handle, or any passed handle id in `[6+]` is not a valid handle in the caller's table.

**E_INVAL** — ELF header malformed; ELF image not position-independent (no `PT_DYNAMIC`, or `e_type != ET_DYN`); `[4]` smaller than the declared ELF image size; reserved bits set in `[1]`, `[2]`, or any passed handle entry; two passed handles reference the same source; `[5]` has bits set outside the system's core count.

**E_NOMEM** — insufficient kernel memory.

**E_FULL** — caller's handle table has no free slot for the returned IDC handle.

#### Tests

[test 01] returns E_PERM if the caller's self-handle lacks `crcd`.
[test 02] returns E_PERM if `self_caps` is not a subset of the caller's self-handle caps.
[test 03] returns E_PERM if `ec_inner_ceiling` is not a subset of the caller's `ec_inner_ceiling`.
[test 04] returns E_PERM if `ec_outer_ceiling` is not a subset of the caller's `ec_outer_ceiling`.
[test 05] returns E_PERM if `vmar_inner_ceiling` is not a subset of the caller's `vmar_inner_ceiling`.
[test 06] returns E_PERM if `vmar_outer_ceiling` is not a subset of the caller's `vmar_outer_ceiling`.
[test 07] returns E_PERM if any field in `restart_policy_ceiling` exceeds the caller's corresponding field.
[test 08] returns E_PERM if `fut_wait_max` exceeds the caller's `fut_wait_max`.
[test 09] returns E_PERM if `cridc_ceiling` is not a subset of the caller's `cridc_ceiling`.
[test 10] returns E_PERM if `pf_ceiling` is not a subset of the caller's `pf_ceiling`.
[test 11] returns E_PERM if `vm_ceiling` is not a subset of the caller's `vm_ceiling`.
[test 12] returns E_PERM if `port_ceiling` is not a subset of the caller's `port_ceiling`.
[test 13] returns E_BADCAP if `elf_page_frame` is not a valid page frame handle.
[test 14] returns E_BADCAP if any passed handle id is not a valid handle in the caller's table.
[test 15] returns E_INVAL if the ELF header is malformed.
[test 16] returns E_INVAL if `elf_page_frame` is smaller than the declared ELF image size.
[test 16a] returns E_INVAL if the ELF image is not position-independent (no PT_DYNAMIC, or e_type != ET_DYN).
[test 17] returns E_INVAL if any reserved bits are set in [1], [2], or a passed handle entry.
[test 18] returns E_INVAL if any two entries in [6+] reference the same source handle.
[test 19] on success, the caller receives an IDC handle to the new domain with caps = the caller's `cridc_ceiling`.
[test 20] on success, the new domain's handle table contains the self-handle at slot 0 with caps = `self_caps`.
[test 21] on success, the new domain's handle table contains the initial EC at slot 1 with caps = the `ec_inner_ceiling` supplied in [2].
[test 22] on success, the new domain's handle table contains an IDC handle to itself at slot 2 with caps = the passed `cridc_ceiling`.
[test 23] on success, passed handles occupy slots 3+ of the new domain's handle table in the order supplied, each with the caps specified in its entry.
[test 24] a passed handle entry with `move = 1` is removed from the caller's handle table after the call.
[test 25] a passed handle entry with `move = 0` remains in the caller's handle table after the call.
[test 26] on success, the new domain's `ec_inner_ceiling`, `vmar_inner_ceiling`, `cridc_ceiling`, `idc_rx`, `pf_ceiling`, `vm_ceiling`, and `port_ceiling` in field0 are set to the values supplied in [2] and [1].
[test 27] on success, the new domain's `ec_outer_ceiling` and `vmar_outer_ceiling` in field1 are set to the values supplied in [3].
[test 28] on success, the new domain's `idc_rx` in field0 is set to the value supplied in [1].
[test 29] the initial EC begins executing at the entry point declared in the ELF header (after the kernel-applied randomized ASLR offset).
[test 30] on success, two successive `create_capability_domain` calls with the same ELF image place the image at different randomized base addresses with high probability (ASLR jitter test — see §[address_space]).
[test 31] on success, the new domain's initial EC has affinity equal to `[5]` (any-core when 0).
[test 32] returns E_INVAL if `[5]` has bits set outside the system's core count.

### acquire_ecs

#### Summary

Returns handles to all non-vCPU execution contexts bound to the target domain referenced by an IDC handle.

#### Declaration

```
acquire_ecs([1] target) -> [1..N] handles
  syscall_num = 20

  syscall word bits 12-19: count (set by the kernel on return; 0 on entry)

  [1] target: IDC handle
```

#### Description

The kernel sets the syscall word's count field to N, the number of handles returned, and writes them to vregs `[1..N]`.

#### Capabilities

- IDC handle `[1]`: `aqec`

#### Return value

`[1..N]`: EC handles, each with caps = `target.ec_outer_ceiling` ∩ `[1].ec_cap_ceiling`. The syscall word's count field is set to N.

#### Errors

**E_BADCAP** — `[1]` is not a valid IDC handle.

**E_PERM** — `[1]` does not have the `aqec` cap.

**E_INVAL** — reserved bits set in `[1]`.

**E_FULL** — caller's handle table cannot accommodate all returned handles.

#### Tests

[test 01] returns E_BADCAP if [1] is not a valid IDC handle.
[test 02] returns E_PERM if [1] does not have the `aqec` cap.
[test 03] returns E_INVAL if any reserved bits are set in [1].
[test 04] returns E_FULL if the caller's handle table cannot accommodate all returned handles.
[test 05] on success, the syscall word's count field equals the number of non-vCPU ECs bound to the target domain.
[test 06] on success, vregs `[1..N]` contain handles in the caller's table referencing those ECs, each with caps = target's `ec_outer_ceiling` intersected with the IDC's `ec_cap_ceiling`.
[test 07] vCPUs in the target domain are not included in the returned handles.

### acquire_vmars

#### Summary

Returns handles to all `map=1` (pf) and `map=3` (demand) VMARs bound to the target domain referenced by an IDC handle. MMIO and DMA VMARs are excluded.

#### Declaration

```
acquire_vmars([1] target) -> [1..N] handles
  syscall_num = 21

  syscall word bits 12-19: count (set by the kernel on return; 0 on entry)

  [1] target: IDC handle
```

#### Description

While in flight, all ECs in the target domain are paused — `acquire_vmars` and the resulting `idc_read`/`idc_write` traffic is intended as a debugger primitive, not a performance path.

#### Capabilities

- IDC handle `[1]`: `aqvr`

#### Return value

`[1..N]`: VMAR handles, each with caps = `target.vmar_outer_ceiling` ∩ `[1].vmar_cap_ceiling`. The syscall word's count field is set to N.

#### Errors

**E_BADCAP** — `[1]` is not a valid IDC handle.

**E_PERM** — `[1]` does not have the `aqvr` cap.

**E_INVAL** — reserved bits set in `[1]`.

**E_FULL** — caller's handle table cannot accommodate all returned handles.

#### Tests

[test 01] returns E_BADCAP if [1] is not a valid IDC handle.
[test 02] returns E_PERM if [1] does not have the `aqvr` cap.
[test 03] returns E_INVAL if any reserved bits are set in [1].
[test 04] returns E_FULL if the caller's handle table cannot accommodate all returned handles.
[test 05] on success, the syscall word's count field equals the number of `map=1` and `map=3` VMARs bound to the target domain.
[test 06] on success, vregs `[1..N]` contain handles in the caller's table referencing those VMARs, each with caps = target's `vmar_outer_ceiling` intersected with the IDC's `vmar_cap_ceiling`.
[test 07] MMIO and DMA VMARs in the target domain are not included in the returned handles.

### §[restart_semantics] Restart Semantics

When a capability domain holding the `restart` cap on its self-handle exits — voluntary, fault, or kill — the kernel restarts the domain rather than tearing it down. ECs re-enter at their original entry points (or `persist` through the restart, see below); the handle table survives; each handle is processed per its `restart_policy` bits. Reply handles held by the restarting domain are governed by the domain-wide `reply_policy` bit on the self-handle.

Per-handle policies are ordered least-to-most privileged. The `restart_policy` cap field is monotonic-reducing along this ordering: a holder may reduce its handle's policy to any value at or below the current setting. (For 2-bit policies, "reducing" is numeric reduction along the privilege ordering, not bitwise subset.)

| Handle type | Policies (low → high privilege) | Notes |
|---|---|---|
| `capability_domain_self` | always preserved | the restart target itself |
| `execution_context` | 0=kill / 1=restart_at_entry / 2=persist | `persist` keeps the EC running through the restart, including its stack pages; otherwise the EC re-enters at its original entry point (1) or is killed (0) |
| `virtual_memory_address_region` | 0=free / 1=decommit / 2=preserve / 3=snapshot | `snapshot` requires a bound source VMAR via the `snapshot` syscall; `preserve` keeps contents; `decommit` keeps the reservation but releases pages; `free` releases everything. A VMAR lives in exactly one domain's address space; the owning domain's handle's `restart_policy` determines what happens to the VMAR. Cross-domain handles to the same VMAR carry their own `restart_policy` for whether the foreign handle survives the foreign domain's restart |
| `page_frame` | 0=drop / 1=keep | refcount semantics apply on `drop` |
| `device_region` | 0=drop / 1=keep | |
| `port` | 0=drop / 1=keep | refcount semantics apply on `drop` |
| `virtual_machine` | 0=drop / 1=keep | |
| `capability_domain` (IDC) | 0=drop / 1=keep | |
| `timer` | 0=drop / 1=keep | refcount semantics apply on `drop` |
| `reply` | governed by domain `reply_policy` | drop: pending callers resume with `E_REFUSED`; keep: reply remains valid, caller stays suspended |

Each handle's `restart_policy` value is bounded at create time (and at copy time) by the domain's `restart_policy_ceiling` corresponding field on its self-handle.

[test 01] returns E_PERM if `create_execution_context` is called with `caps.restart_policy` exceeding the calling domain's `restart_policy_ceiling.ec_restart_max`.
[test 02] returns E_PERM if `create_vmar` is called with `caps.restart_policy` exceeding the calling domain's `restart_policy_ceiling.vmar_restart_max`.
[test 03] returns E_PERM if `create_page_frame` is called with `caps.restart_policy = 1` and the calling domain's `restart_policy_ceiling.pf_restart_max = 0`.
[test 04] returns E_PERM if `create_virtual_machine` is called with `caps.restart_policy = 1` and the calling domain's `restart_policy_ceiling.vm_restart_max = 0`.
[test 05] returns E_PERM if `create_port` is called with `caps.restart_policy = 1` and the calling domain's `restart_policy_ceiling.port_restart_max = 0`.
[test 06] returns E_PERM if any IDC handle minted by `create_capability_domain` (the caller's own returned handle, the new domain's slot-2 self-IDC, or any `passed_handles` IDC entry) has `caps.restart_policy = 1` and the calling domain's `restart_policy_ceiling.idc_restart_max = 0`.
[test 07] returns E_PERM if any device_region handle minted by transfer (e.g., copy/move via xfer) has `caps.restart_policy = 1` and the calling domain's `restart_policy_ceiling.dr_restart_max = 0`.
[test 08] returns E_PERM if `timer_arm` is called with `caps.restart_policy = 1` and the calling domain's `restart_policy_ceiling.tm_restart_max = 0`.

## §[execution_context] Execution Context

An execution context is a schedulable unit of executable state bound to a capability domain.

Handle ABI:

```
word 0:
 63            48 47                          16 15   12 11         0
┌────────────────┬──────────────────────────────┬───────┬────────────┐
│   cap (16)     │       _reserved (32)         │type(4)│   id(12)   │
└────────────────┴──────────────────────────────┴───────┴────────────┘

word 1 (field0):
 63                                              2 1   0
┌─────────────────────────────────────────────────┬─────┐
│              _reserved (62)                     │pri  │
│                                                 │ (2) │
└─────────────────────────────────────────────────┴─────┘

word 2 (field1):
 63                                                                  0
┌─────────────────────────────────────────────────────────────────────┐
│                       affinity (64)                                 │
└─────────────────────────────────────────────────────────────────────┘
```

Field layout:

| field | location | meaning |
|---|---|---|
| pri | field0 bits 0-1 | current scheduling priority (0-3); reflects the EC's runtime state |
| affinity | field1 bits 0-63 | current 64-bit core affinity mask; bit N = 1 means the EC may run on core N |

Both fields are kernel-mutable: `priority` and `affinity` syscalls update them, and the snapshot in any caller's handle is refreshed by the implicit-sync side effect of any syscall that takes the handle (or by an explicit `sync` call).

cap (word 0, bits 48-63):

```
 15      13 12    11    10   9     8 7      6    5    4    3    2    1    0
┌──────────┬──────┬──────┬──────┬───────┬───────┬──────┬──────┬──────┬──────┬──────┬────┬────┐
│_rsvd (3) │unbind│rebind│ bind │ rstrt │ write │ read │ susp │ term │ spri │ saff │copy│move│
│          │      │      │      │ _plcy │       │      │      │      │      │      │    │    │
└──────────┴──────┴──────┴──────┴───────┴───────┴──────┴──────┴──────┴──────┴──────┴────┴────┘
```

| Bit | Name | Gates |
|---|---|---|
| 0 | `move` | transferring this handle via move to another capability domain |
| 1 | `copy` | transferring this handle via copy to another capability domain |
| 2 | `saff` — set affinity | `affinity` syscall on this EC |
| 3 | `spri` — set priority | `priority` syscall on this EC |
| 4 | `term` — terminate | `terminate` syscall on this EC |
| 5 | `susp` — suspend | `suspend` syscall on this EC |
| 6 | `read` | exposing this EC's state in event payloads during event delivery (§[event_state]); when absent, state in the payload is zeroed |
| 7 | `write` | applying modifications written to the event payload back to this EC's state on reply; when absent, modifications are discarded |
| 8-9 | `restart_policy` | EC behavior on domain restart: 0=kill, 1=restart_at_entry, 2=persist, 3=_reserved (see §[restart_semantics]) |
| 10 | `bind` | `bind_event_route` on this EC when no prior route exists for the given event type |
| 11 | `rebind` | `bind_event_route` on this EC when a prior route exists for the given event type (atomic overwrite) |
| 12 | `unbind` | `clear_event_route` on this EC |

### create_execution_context

#### Summary

Creates a new execution context either in the caller's own domain or in a target domain referenced by an IDC handle.

#### Declaration

```
create_execution_context([1] caps, [2] entry, [3] stack_pages, [4] target, [5] vm_handle, [6] affinity)
  -> [1] handle
  syscall_num = 22

  [1] caps: u64 packed as
    bits  0-15: caps          — caps on the EC handle returned to the caller
    bits 16-31: target_caps   — caps on the EC handle inserted into target's table
                                (ignored when target = self)
    bits 32-33: priority      — scheduling priority, 0-3, bounded by caller's priority ceiling
    bits 34-63: _reserved

  [2] entry:        instruction pointer where the EC begins execution
  [3] stack_pages:  number of stack pages the kernel allocates in the target's address space;
                    kernel installs unmapped guard pages above and below the stack
  [4] target:       0 = self, else IDC handle with crec cap to the target domain
  [5] affinity:     64-bit core mask; bit N = 1 allows the EC to run on core N.
                    0 = any core (kernel chooses)
```

#### Description

The kernel allocates `[3]` pages of stack in the target's address space at a kernel-chosen randomized base in the ASLR zone (see §[address_space]), with unmapped guard pages above and below to catch overflow and underflow. The EC begins executing at `[2] entry` with the stack pointer set to the top of the allocated stack.

#### Capabilities

- Self-handle: `crec`
- IDC handle `[4]` (when nonzero): `crec`
- `[1].caps` ⊆ self's `ec_inner_ceiling` (when `[4] = 0`) or target domain's `ec_outer_ceiling` (when `[4] != 0`)
- `[1].target_caps` ⊆ target domain's `ec_inner_ceiling` (when `[4] != 0`)
- `[1].priority` ≤ caller's priority ceiling

#### Return value

`[1]`: EC handle with caps = `[1].caps`.

#### Errors

**E_PERM** — self-handle lacks `crec`; `[4]` lacks `crec` (when nonzero); any cap/priority argument exceeds the corresponding ceiling.

**E_BADCAP** — `[4]` is nonzero and not a valid IDC handle.

**E_INVAL** — `[3] stack_pages` is 0; `[5] affinity` has bits set outside the system's core count; reserved bits set in `[1]`.

**E_NOMEM** — insufficient kernel memory.

**E_NOSPC** — target's address space has insufficient contiguous space for the stack.

**E_FULL** — caller's handle table has no free slot, or the target domain's handle table is full when `[4]` is nonzero.

#### Tests

[test 01] returns E_PERM if the caller's self-handle lacks `crec`.
[test 02] returns E_PERM if [4] is nonzero and [4] lacks `crec`.
[test 03] returns E_PERM if [4] is 0 (target = self) and caps is not a subset of self's `ec_inner_ceiling`.
[test 04] returns E_PERM if [4] is nonzero and caps is not a subset of the target domain's `ec_outer_ceiling`.
[test 05] returns E_PERM if [4] is nonzero and target_caps is not a subset of the target domain's `ec_inner_ceiling`.
[test 06] returns E_PERM if priority exceeds the caller's priority ceiling.
[test 07] returns E_BADCAP if [4] is nonzero and not a valid IDC handle.
[test 08] returns E_INVAL if [3] stack_pages is 0.
[test 09] returns E_INVAL if [5] affinity has bits set outside the system's core count.
[test 10] returns E_INVAL if any reserved bits are set in [1].
[test 11] on success, the caller receives an EC handle with caps = `[1].caps`.
[test 12] on success, when [4] is nonzero, the target domain also receives a handle with caps = `[1].target_caps`.
[test 13] on success, the EC's priority is set to `[1].priority`.
[test 14] on success, the EC's affinity is set to `[5]`.
[test 15] on success, the EC's stack base lies within the ASLR zone (see §[address_space]).

### self

#### Summary

Returns the handle in the caller's table that references the calling execution context. Pure lookup — no handle is inserted, minted, or modified, and no authority is granted. By the at-most-one invariant, there is at most one such handle.

#### Declaration

```
self() -> [1] handle
  syscall_num = 23
```

#### Capabilities

None.

#### Return value

`[1]`: handle in the caller's table whose resolved capability references the calling EC.

#### Errors

**E_NOENT** — no handle in the caller's table references the calling EC.

#### Tests

[test 01] returns E_NOENT if no handle in the caller's table references the calling execution context.
[test 02] on success, [1] is a handle in the caller's table whose resolved capability references the calling execution context.

### terminate

#### Summary

Terminates the target execution context.

#### Declaration

```
terminate([1] target) -> void
  syscall_num = 24

  [1] target: EC handle
```

#### Description

Termination atomically destroys the EC. Handles referencing it in any capability domain become stale; a syscall invoked with a stale handle returns `E_TERM` and the stale handle is removed from the caller's table on the same call.

Termination also clears the kernel-held event routes bound to the EC (§[event_route]) and marks any reply handles whose suspended sender was the terminated EC such that subsequent operations on those reply handles return `E_ABANDONED`.

#### Capabilities

- EC handle `[1]`: `term`

#### Errors

**E_BADCAP** — `[1]` is not a valid EC handle.

**E_PERM** — `[1]` does not have the `term` cap.

**E_INVAL** — reserved bits set in `[1]`.

#### Tests

[test 01] returns E_BADCAP if [1] is not a valid EC handle.
[test 02] returns E_PERM if [1] does not have the `term` cap.
[test 03] returns E_INVAL if any reserved bits are set in [1].
[test 04] on success, the target EC stops executing.
[test 05] on success, syscalls invoked with any handle to the terminated EC return E_TERM and remove that handle from the caller's table on the same call.
[test 06] on success, no further events generated by the terminated EC are delivered to any port previously bound by an event_route from that EC.
[test 07] on success, reply handles whose suspended sender was the terminated EC return E_ABANDONED on subsequent operations.
[test 08] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

### yield

#### Summary

Yields the calling EC's timeslice. With `[1] = 0`, the scheduler selects the next EC to run. With `[1]` a valid handle to a runnable EC, that EC is scheduled next; if it is not runnable, the scheduler selects.

#### Declaration

```
yield([1] target) -> void
  syscall_num = 25

  [1] target: 0 = yield to scheduler; else an EC handle to yield to
```

#### Capabilities

None.

#### Errors

**E_BADCAP** — `[1]` is nonzero and not a valid EC handle.

**E_INVAL** — reserved bits set in `[1]`.

#### Tests

[test 01] returns E_BADCAP if [1] is nonzero and not a valid EC handle.
[test 02] returns E_INVAL if any reserved bits are set in [1].
[test 03] on success, when [1] is a valid handle to a runnable EC, an observable side effect performed by the target EC (e.g., a write to shared memory) is visible to the caller before the caller's next syscall returns.
[test 04] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

### priority

#### Summary

Sets the target execution context's priority.

#### Declaration

```
priority([1] target, [2] new_priority) -> void
  syscall_num = 26

  [1] target: EC handle
  [2] new_priority: 0..3
```

#### Description

The new priority applies to subsequent scheduling, port event delivery, and futex wake ordering. If the target is currently suspended on a port or waiting on a futex, the new priority takes effect immediately and reorders the target into the appropriate priority bucket (this is the mechanism priority inheritance is built on).

#### Capabilities

- EC handle `[1]`: `spri`
- `[2]` ≤ caller's self-handle `pri`

#### Errors

**E_BADCAP** — `[1]` is not a valid EC handle.

**E_PERM** — `[1]` does not have the `spri` cap; `[2]` exceeds the caller's self-handle `pri`.

**E_INVAL** — `[2]` is greater than 3; reserved bits set in `[1]`.

#### Tests

[test 01] returns E_BADCAP if [1] is not a valid EC handle.
[test 02] returns E_PERM if [1] does not have the `spri` cap.
[test 03] returns E_PERM if [2] exceeds the caller's self-handle `pri`.
[test 04] returns E_INVAL if [2] is greater than 3.
[test 05] returns E_INVAL if any reserved bits are set in [1].
[test 06] on success, when two ECs are blocked in `futex_wait_val` on the same address and a `futex_wake` is issued, the EC whose priority was last set higher via `priority` is woken first; the same ordering applies to `recv` selection when the two ECs are both queued senders on the same port.
[test 07] on success, when the target is suspended on a port or waiting on a futex, [2] takes effect on the target's next port event delivery and futex wake.
[test 08] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

### affinity

#### Summary

Sets the target execution context's CPU affinity mask.

#### Declaration

```
affinity([1] target, [2] new_affinity) -> void
  syscall_num = 27

  [1] target: EC handle
  [2] new_affinity: 64-bit core mask. 0 = kernel picks any core.
                    Otherwise, bit N = 1 allows the target EC to run on core N;
                    bit N must only be set for cores the system actually has.
```

#### Capabilities

- EC handle `[1]`: `saff`

#### Errors

**E_BADCAP** — `[1]` is not a valid EC handle.

**E_PERM** — `[1]` does not have the `saff` cap.

**E_INVAL** — any bit set in `[2]` corresponds to a core the system does not have; reserved bits set in `[1]`.

#### Tests

[test 01] returns E_BADCAP if [1] is not a valid EC handle.
[test 02] returns E_PERM if [1] does not have the `saff` cap.
[test 03] returns E_INVAL if any bit set in [2] corresponds to a core the system does not have.
[test 04] returns E_INVAL if any reserved bits are set in [1].
[test 05] on success, the target EC's affinity is set to [2].
[test 06] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

### perfmon_info

#### Summary

Queries system PMU capabilities.

#### Declaration

```
perfmon_info() -> [1] caps_word, [2] supported_events
  syscall_num = 28

  [1] caps_word: u64 packed as
    bits 0-7: num_counters
    bit 8:    overflow_support
    bits 9-63: _reserved

  [2] supported_events: u64 bitmask
```

#### Description

Supported event bits:

| Bit | Event |
|---|---|
| 0 | cycles |
| 1 | instructions |
| 2 | cache_references |
| 3 | cache_misses |
| 4 | branch_instructions |
| 5 | branch_misses |
| 6 | bus_cycles |
| 7 | stalled_cycles_frontend |
| 8 | stalled_cycles_backend |

#### Capabilities

- Self-handle: `pmu`

#### Return value

`[1]`: caps_word with num_counters and overflow_support. `[2]`: bitmask of supported events.

#### Errors

**E_PERM** — caller's self-handle lacks `pmu`.

#### Tests

[test 01] returns E_PERM if the caller's self-handle lacks `pmu`.
[test 02] [1] bits 0-7 contain the number of available PMU counters.
[test 03] [1] bit 8 is set when the hardware supports counter overflow events.
[test 04] [2] is a bitmask of supported events indexed by the table above.

### perfmon_start

#### Summary

Starts hardware performance counters on the target EC.

#### Declaration

```
perfmon_start([1] target, [2] num_configs, [3 + 2i] config_event, [3 + 2i + 1] config_threshold) -> void
  syscall_num = 29

  [1] target:        EC handle
  [2] num_configs:   N, the number of counter configs supplied
  [3 + 2i] config_event: u64 packed as
    bits 0-7: event index (per perfmon_info supported_events bitmask)
    bit 8:    has_threshold
    bits 9-63: _reserved
  [3 + 2i + 1] config_threshold: u64 overflow threshold (used only when has_threshold = 1)

  for i in 0..N-1.
```

#### Capabilities

- Self-handle: `pmu`

#### Errors

**E_PERM** — caller's self-handle lacks `pmu`.

**E_BADCAP** — `[1]` is not a valid EC handle.

**E_INVAL** — `[2]` is 0 or exceeds num_counters; any config's event is not in supported_events; any config has `has_threshold = 1` but the hardware does not support overflow; reserved bits set in any config_event.

**E_BUSY** — `[1]` is not the calling EC and not currently suspended.

#### Tests

[test 01] returns E_PERM if the caller's self-handle lacks `pmu`.
[test 02] returns E_BADCAP if [1] is not a valid EC handle.
[test 03] returns E_INVAL if [2] is 0 or exceeds num_counters.
[test 04] returns E_INVAL if any config's event is not in supported_events.
[test 05] returns E_INVAL if any config has has_threshold = 1 but the hardware does not support overflow.
[test 06] returns E_INVAL if any reserved bits are set in any config_event.
[test 07] returns E_BUSY if [1] is not the calling EC and not currently suspended.
[test 08] on success, a subsequent `perfmon_read` on the target EC returns nonzero values in vregs `[1..2]` after the target EC has executed enough work to register the configured events.
[test 09] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

### perfmon_read

#### Summary

Reads the current counter values from the target EC.

#### Declaration

```
perfmon_read([1] target) -> [1..num_counters] counter_values, [num_counters + 1] timestamp
  syscall_num = 30

  [1] target: EC handle
```

#### Capabilities

- Self-handle: `pmu`

#### Return value

`[1..num_counters]`: current counter values. `[num_counters + 1]`: u64 nanosecond timestamp.

#### Errors

**E_PERM** — caller's self-handle lacks `pmu`.

**E_BADCAP** — `[1]` is not a valid EC handle.

**E_INVAL** — perfmon was not started on the target EC.

**E_BUSY** — `[1]` is not the calling EC and not currently suspended.

#### Tests

[test 01] returns E_PERM if the caller's self-handle lacks `pmu`.
[test 02] returns E_BADCAP if [1] is not a valid EC handle.
[test 03] returns E_INVAL if perfmon was not started on the target EC.
[test 04] returns E_BUSY if [1] is not the calling EC and not currently suspended.
[test 05] on success, [1..num_counters] contain the current counter values for the active counters.
[test 06] on success, [num_counters + 1] is a u64 nanosecond timestamp strictly greater than the timestamp from any prior `perfmon_read` on the same target EC, and each counter value is greater than or equal to the value returned by the prior `perfmon_read` on that target.
[test 07] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

### perfmon_stop

#### Summary

Stops counting on the target EC and releases PMU state.

#### Declaration

```
perfmon_stop([1] target) -> void
  syscall_num = 31

  [1] target: EC handle
```

#### Capabilities

- Self-handle: `pmu`

#### Errors

**E_PERM** — caller's self-handle lacks `pmu`.

**E_BADCAP** — `[1]` is not a valid EC handle.

**E_INVAL** — perfmon was not started on the target EC.

**E_BUSY** — `[1]` is not the calling EC and not currently suspended.

#### Tests

[test 01] returns E_PERM if the caller's self-handle lacks `pmu`.
[test 02] returns E_BADCAP if [1] is not a valid EC handle.
[test 03] returns E_INVAL if perfmon was not started on the target EC.
[test 04] returns E_BUSY if [1] is not the calling EC and not currently suspended.
[test 05] on success, a subsequent `perfmon_read` on the target EC returns E_INVAL (perfmon was not started).
[test 06] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

## §[address_space] Address Space Layout

Each capability domain owns a per-domain virtual address space. The user half is split into three zones with distinct placement semantics:

| Zone | Placement |
|---|---|
| NULL guard | unmapped; any access faults |
| ASLR zone | kernel-chosen base, randomized at placement time. Used for ELF segments, EC stacks, and `create_vmar` with `preferred_base = 0` |
| Static zone | userspace-chosen base via `create_vmar` with `preferred_base != 0`. Placement is deterministic |

ELF images loaded by `create_capability_domain` must be position-independent; the kernel relocates them to a randomized base in the ASLR zone. The first faulted page in the NULL guard always faults regardless of any other mapping.

Concrete numeric boundaries are architecture-specific.

x86-64 (4-level paging, 47-bit canonical user VA):

| Zone | Range | Size |
|---|---|---|
| NULL guard | `[0x0000_0000_0000_0000, 0x0000_0000_0000_1000)` | 4 KiB |
| ASLR zone | `[0x0000_0000_0000_1000, 0x0000_1000_0000_0000)` | ~16 TiB |
| Static zone | `[0x0000_1000_0000_0000, 0x0000_8000_0000_0000)` | 112 TiB |

aarch64 (4-level paging, 48-bit TTBR0 user VA):

| Zone | Range | Size |
|---|---|---|
| NULL guard | `[0x0000_0000_0000_0000, 0x0000_0000_0000_1000)` | 4 KiB |
| ASLR zone | `[0x0000_0000_0000_1000, 0x0000_1000_0000_0000)` | ~16 TiB |
| Static zone | `[0x0000_1000_0000_0000, 0x0001_0000_0000_0000)` | 240 TiB |

## §[vmar] Virtual Memory Address Region

A virtual memory address region is a contiguous span of the virtual address space bound to a capability domain. It is available for demand-paged memory, or for installing page frames or device regions. See §[address_space] for the zone layout governing where VMARs are placed.

A regular VMAR (`caps.mmio = 0, caps.dma = 0`) created without explicit mapping starts at `map = 0`. The first faulted access transitions it to `map = 3` (demand): the kernel allocates a fresh zero-filled page_frame and installs it at the faulting offset, with effective permissions = `VMAR.cur_rwx`. Once `map = 3`, the VMAR cannot be `map_pf`'d until it is `unmap`'d back to `map = 0`.

Handle ABI:

```
word 0:
 63            48 47                          16 15   12 11         0
┌────────────────┬──────────────────────────────┬───────┬────────────┐
│   cap (16)     │       _reserved (32)         │type(4)│   id(12)   │
└────────────────┴──────────────────────────────┴───────┴────────────┘

word 1 (field0):
 63                                                                  0
┌─────────────────────────────────────────────────────────────────────┐
│                     base virtual address (64)                       │
└─────────────────────────────────────────────────────────────────────┘

word 2 (field1):
 63          53 52        41 40 39 38    36 35 34 33 32 31             0
┌──────────────┬────────────┬─────┬────────┬─────┬──────┬────────────────┐
│_reserved (11)│ device(12) │ map │cur_rwx │ cch │  sz  │ page_count (32)│
└──────────────┴────────────┴─────┴────────┴─────┴──────┴────────────────┘
```

Field layout:

| field | location | meaning |
|---|---|---|
| base vaddr | field0 bits 0-63 | base virtual address of the VMAR (or base IOVA, for DMA VMARs) |
| page_count | field1 bits 0-31 | number of pages (in `sz` units) |
| sz | field1 bits 32-33 | page size (immutable): 0=4 KiB, 1=2 MiB, 2=1 GiB, 3=reserved |
| cch | field1 bits 34-35 | cache type (immutable): 0=wb, 1=uc, 2=wc, 3=wt |
| cur_rwx | field1 bits 36-38 | current mapping permissions (bit 36=r, 37=w, 38=x) |
| map | field1 bits 39-40 | mapping type: 0=unmapped, 1=pf, 2=mmio, 3=demand |
| device | field1 bits 41-52 | bound device_region handle id (DMA VMARs immutably from `create_vmar`; MMIO VMARs set by `map_mmio` and cleared by `unmap_mmio`; 0 otherwise) |

cap (word 0, bits 48-63):

```
 15    11 10        9 8  7   6 5    4 3    2   1    0
┌────────┬─────────────┬───┬──────┬──────┬───┬───┬───┬────┬────┐
│_rsvd(5)│restart_plcy │dma│max_sz│ mmio │ x │ w │ r │copy│move│
│        │    (2)      │   │      │      │   │   │   │    │    │
└────────┴─────────────┴───┴──────┴──────┴───┴───┴───┴────┴────┘
```

| Bit(s) | Name | Meaning |
|---|---|---|
| 0 | `move` | transferring this handle via move to another capability domain |
| 1 | `copy` | transferring this handle via copy to another capability domain |
| 2 | `r` | max read |
| 3 | `w` | max write |
| 4 | `x` | max execute |
| 5 | `mmio` | mmio mode |
| 6-7 | `max_sz` | max page size: 0=4 KiB, 1=2 MiB, 2=1 GiB, 3=reserved |
| 8 | `dma` | dma mode (VMAR represents a device-IOVA range) |
| 9-10 | `restart_policy` | VMAR behavior on domain restart: 0=free, 1=decommit, 2=preserve, 3=snapshot (see §[restart_semantics]) |
| 11-15 | `_reserved` | |

`r`/`w`/`x` and `max_sz` are ceiling-checked against the domain's `vmar_inner_ceiling`. `mmio`, `dma`, and `max_sz` describe the VMAR object and are immutable after creation. `mmio` and `dma` are mutually exclusive. `dma` VMARs cannot have `x` set. `sz`, `cch`, and `cur_rwx` in field1 are observable state on the VMAR. Move/copy semantics on VMARs are bounded by `vmar_outer_ceiling` for the receiving handle.

### create_vmar

#### Summary

Reserves a range of virtual address space bound to the caller's domain.

#### Declaration

```
create_vmar([1] caps, [2] props, [3] pages, [4] preferred_base, [5] device_region) -> [1] handle
  syscall_num = 32

  [1] caps: u64 packed as
    bits  0-15: caps        — caps on the VMAR handle returned to the caller
    bits 16-63: _reserved

  [2] props: u64 packed as
    bits 0-2: cur_rwx       — initial current rwx
    bits 3-4: sz            — page size (immutable; must be 0 when caps.mmio = 1)
    bits 5-6: cch           — cache type (immutable)
    bits 7-63: _reserved

  [3] pages:          number of `sz` pages to reserve
  [4] preferred_base: 0 = kernel chooses an ASLR-zone base; nonzero = use this base
                      (must lie wholly within the static zone — see §[address_space])
  [5] device_region:  device_region handle to bind for the IOMMU mapping
                      (required when caps.dma = 1; ignored otherwise)
```

#### Capabilities

- Self-handle: `crvr`
- `[1].caps` r/w/x ⊆ caller's `vmar_inner_ceiling` r/w/x
- `[1].caps.max_sz` ≤ caller's `vmar_inner_ceiling.max_sz`
- `[1].caps.mmio = 1` requires the caller's `vmar_inner_ceiling` to permit mmio
- device_region `[5]` (when `caps.dma = 1`): `dma`

#### Return value

`[1]`: VMAR handle with caps = `[1].caps`. field0 contains the assigned base address; field1 contains props together with `[3]` pages.

#### Errors

**E_PERM** — self-handle lacks `crvr`; `[1].caps` r/w/x or max_sz exceeds `vmar_inner_ceiling`; `caps.mmio = 1` and ceiling does not permit mmio; `caps.dma = 1` and `[5]` lacks `dma`.

**E_BADCAP** — `caps.dma = 1` and `[5]` is not a valid device_region handle.

**E_INVAL** — `[3] pages = 0`; `[4]` nonzero and not aligned to `props.sz`; `[4]` nonzero and the requested range does not lie wholly within the static zone; `caps.max_sz = 3` (reserved); `caps.mmio = 1` and `props.sz != 0`; `props.sz = 3` (reserved); `props.sz` exceeds `caps.max_sz`; `caps.mmio = 1` and `caps.x` set; `caps.dma = 1` and `caps.x` set; `caps.mmio = 1` and `caps.dma = 1`; `props.cur_rwx` not a subset of `caps.r/w/x`; reserved bits set in `[1]` or `[2]`.

**E_NOMEM** — insufficient kernel memory.

**E_NOSPC** — address space has no room for the requested range.

**E_FULL** — caller's handle table has no free slot.

#### Tests

[test 01] returns E_PERM if the caller's self-handle lacks `crvr`.
[test 02] returns E_PERM if caps' r/w/x bits are not a subset of the caller's `vmar_inner_ceiling`'s r/w/x bits.
[test 03] returns E_PERM if caps.max_sz exceeds the caller's `vmar_inner_ceiling`'s max_sz.
[test 04] returns E_PERM if caps.mmio = 1 and the caller's `vmar_inner_ceiling` does not permit mmio.
[test 05] returns E_INVAL if [3] pages is 0.
[test 06] returns E_INVAL if [4] preferred_base is nonzero and not aligned to the page size encoded in props.sz.
[test 07] returns E_INVAL if caps.max_sz is 3 (reserved).
[test 08] returns E_INVAL if caps.mmio = 1 and props.sz != 0.
[test 09] returns E_INVAL if props.sz is 3 (reserved).
[test 10] returns E_INVAL if props.sz exceeds caps.max_sz.
[test 11] returns E_INVAL if caps.mmio = 1 and caps.x is set.
[test 12] returns E_INVAL if caps.dma = 1 and caps.x is set.
[test 13] returns E_INVAL if caps.mmio = 1 and caps.dma = 1.
[test 14] returns E_BADCAP if caps.dma = 1 and [5] is not a valid device_region handle.
[test 15] returns E_PERM if caps.dma = 1 and [5] does not have the `dma` cap.
[test 16] returns E_INVAL if props.cur_rwx is not a subset of caps.r/w/x.
[test 17] returns E_INVAL if any reserved bits are set in [1] or [2].
[test 18] on success, the caller receives a VMAR handle with caps = `[1].caps`.
[test 19] on success, field0 contains the assigned base address.
[test 20] on success, field1 contains `[2].props` together with `[3]` pages.
[test 21] on success, when [4] preferred_base is nonzero and the range is available, the assigned base address equals `[4]`.
[test 22] on success, when caps.dma = 1, field1's `device` field equals [5]'s handle id, and a subsequent `map_pf` into this VMAR routes the bound device's accesses at field0 + offset to the installed page_frame.
[test 23] returns E_INVAL if [4] preferred_base is nonzero and the requested range does not lie wholly within the static zone (see §[address_space]).
[test 24] on success, when [4] preferred_base = 0, the assigned base address lies within the ASLR zone (see §[address_space]).

### map_pf

#### Summary

Installs page_frames into a regular or DMA-flagged VMAR.

#### Declaration

```
map_pf([1] vmar, [2 + 2i] offset, [2 + 2i + 1] page_frame) -> void
  syscall_num = 33

  syscall word bits 12-19: N (number of (offset, page_frame) pairs)

  [1] vmar: VMAR handle
  [2 + 2i] offset: byte offset within the VMAR
  [2 + 2i + 1] page_frame: page_frame handle to install at that offset

  for i in 0..N-1.
```

#### Description

The kernel dispatches based on `caps.dma`:
- Regular VMAR (`caps.dma = 0`): pages are mapped into the CPU's virtual address space at `VMAR.base + offset`.
- DMA VMAR (`caps.dma = 1`): pages are mapped into the bound device's IOMMU page tables at `VMAR.base + offset` (an IOVA).

#### Capabilities

None beyond holding the VMAR handle. `[1].caps` must not have `mmio` set (mmio VMARs accept only `map_mmio`).

#### Errors

**E_BADCAP** — `[1]` is not a valid VMAR handle; any `[2 + 2i + 1]` is not a valid page_frame handle.

**E_PERM** — `[1].caps` has `mmio` set.

**E_INVAL** — N is 0; any offset not aligned to the VMAR's `sz`; any page_frame's `sz` smaller than the VMAR's; any pair's range exceeds the VMAR's size; two pairs' ranges overlap; pair's range overlaps an existing mapping; `[1].field1.map` is 2 (mmio) or 3 (demand).

#### Tests

[test 01] returns E_BADCAP if [1] is not a valid VMAR handle.
[test 02] returns E_BADCAP if any [2 + 2i + 1] is not a valid page_frame handle.
[test 03] returns E_PERM if [1].caps has `mmio` set (mmio VMARs accept only `map_mmio`).
[test 04] returns E_INVAL if N is 0.
[test 05] returns E_INVAL if any offset is not aligned to the VMAR's `sz` page size.
[test 06] returns E_INVAL if any page_frame's `sz` is smaller than the VMAR's `sz`.
[test 07] returns E_INVAL if any pair's range exceeds the VMAR's size.
[test 08] returns E_INVAL if any two pairs' ranges overlap.
[test 09] returns E_INVAL if any pair's range overlaps an existing mapping in the VMAR.
[test 10] returns E_INVAL if [1].field1 `map` is 2 (mmio) or 3 (demand) — pf installation requires `map = 0` or `map = 1`.
[test 11] on success, [1].field1 `map` becomes 1 if it was 0; otherwise stays 1.
[test 12] on success, when [1].caps.dma = 0, CPU accesses to `VMAR.base + offset` use effective permissions = `VMAR.cur_rwx` ∩ `page_frame.r/w/x` per page.
[test 13] on success, when [1].caps.dma = 1, a DMA read by the bound device from `VMAR.base + offset` returns the installed page_frame's contents, and a DMA access whose access type is not in `VMAR.cur_rwx` ∩ `page_frame.r/w/x` is rejected by the IOMMU rather than reaching the page_frame.
[test 14] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

### map_mmio

#### Summary

Installs a device_region as an MMIO mapping into an MMIO-flagged VMAR.

#### Declaration

```
map_mmio([1] vmar, [2] device_region) -> void
  syscall_num = 34

  [1] vmar: VMAR handle (must have `mmio` cap)
  [2] device_region: device_region handle
```

#### Capabilities

- VMAR handle `[1]`: `mmio`

#### Errors

**E_BADCAP** — `[1]` is not a valid VMAR handle; `[2]` is not a valid device_region handle.

**E_PERM** — `[1]` does not have the `mmio` cap.

**E_INVAL** — `[1].field1.map` is not 0 (mmio mappings are atomic; the VMAR must be unmapped); `[2]`'s size does not equal `[1]`'s size.

#### Tests

[test 01] returns E_BADCAP if [1] is not a valid VMAR handle.
[test 02] returns E_BADCAP if [2] is not a valid device_region handle.
[test 03] returns E_PERM if [1] does not have the `mmio` cap.
[test 04] returns E_INVAL if [1].field1 `map` is not 0 (mmio mappings are atomic; the VMAR must be unmapped).
[test 05] returns E_INVAL if [2]'s size does not equal [1]'s size.
[test 06] on success, [1].field1 `map` becomes 2.
[test 07] on success, [1].field1 `device` is set to [2]'s handle id.
[test 08] on success, CPU accesses to the VMAR's range use effective permissions = `VMAR.cur_rwx`.
[test 09] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

### unmap

#### Summary

Removes mappings from a VMAR.

#### Declaration

```
unmap([1] vmar, [2..N+1] selectors) -> void
  syscall_num = 35

  syscall word bits 12-19: N (number of selectors; 0 = unmap everything)

  [1] vmar: VMAR handle
  [2..N+1] selectors:
    - map = 1 (pf):     page_frame handles to unmap
    - map = 3 (demand): byte offsets into the VMAR
    - map = 2 (mmio):   N must be 0
```

#### Description

Dispatches on the VMAR's `map` field. With `N = 0`, unmaps everything; with `N > 0`, the selectors specify which mappings to remove and depend on `map`.

#### Capabilities

None beyond holding the VMAR handle.

#### Errors

**E_BADCAP** — `[1]` is not a valid VMAR handle; `[1].field1.map = 1` and any selector is not a valid page_frame handle.

**E_INVAL** — `[1].field1.map = 0` (nothing to unmap); `[1].field1.map = 2` and `N > 0`; `[1].field1.map = 3` and any offset selector is not aligned to `[1].sz`.

**E_NOENT** — `[1].field1.map = 1` and any page_frame selector is not currently installed; `[1].field1.map = 3` and no demand-allocated page exists at any offset selector.

#### Tests

[test 01] returns E_BADCAP if [1] is not a valid VMAR handle.
[test 02] returns E_INVAL if [1].field1 `map` is 0 (nothing to unmap).
[test 03] returns E_INVAL if [1].field1 `map` is 2 (mmio) and N > 0.
[test 04] returns E_BADCAP if [1].field1 `map` is 1 and any selector is not a valid page_frame handle.
[test 05] returns E_NOENT if [1].field1 `map` is 1 and any page_frame selector is not currently installed in [1].
[test 06] returns E_INVAL if [1].field1 `map` is 3 and any offset selector is not aligned to [1]'s `sz`.
[test 07] returns E_NOENT if [1].field1 `map` is 3 and no demand-allocated page exists at any offset selector.
[test 08] on success, when N is 0, all installations or demand-allocated pages are removed and `map` is set to 0.
[test 09] on success, when N is 0 and `map` was 2, the device_region installation is removed and `device` is cleared to 0.
[test 10] on success, when N > 0 and `map` is 1, only the specified page_frames are removed; `map` stays 1 unless every installed page_frame has been removed, in which case it becomes 0.
[test 11] on success, when N > 0 and `map` is 3, only the pages at the specified offsets are freed; `map` stays 3 unless every demand-allocated page has been freed, in which case it becomes 0.
[test 12] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

### remap

#### Summary

Updates a VMAR's `cur_rwx`, changing the effective permissions on its currently-mapped pages. Applies to pf and demand mappings only.

#### Declaration

```
remap([1] vmar, [2] new_cur_rwx) -> void
  syscall_num = 36

  [1] vmar: VMAR handle
  [2] new_cur_rwx: u64 packed as
    bits 0-2: new r/w/x
    bits 3-63: _reserved
```

#### Capabilities

None beyond holding the VMAR handle.

#### Errors

**E_BADCAP** — `[1]` is not a valid VMAR handle.

**E_INVAL** — `[1].field1.map` is 0 or 2 (no pf or demand mapping to remap); `[2]` not a subset of `[1].caps.r/w/x`; `[1].field1.map = 1` and `[2]` not a subset of the intersection of all installed page_frames' r/w/x caps; `[1].caps.dma = 1` and `[2]` has `x` set; reserved bits set in `[2]`.

#### Tests

[test 01] returns E_BADCAP if [1] is not a valid VMAR handle.
[test 02] returns E_INVAL if [1].field1 `map` is 0 or 2 (no pf or demand mapping to remap).
[test 03] returns E_INVAL if [2] new_cur_rwx is not a subset of [1]'s caps r/w/x.
[test 04] returns E_INVAL if [1].field1 `map` is 1 and [2] new_cur_rwx is not a subset of the intersection of all installed page_frames' r/w/x caps.
[test 05] returns E_INVAL if [1].caps.dma = 1 and [2] new_cur_rwx has bit 2 (x) set.
[test 06] returns E_INVAL if any reserved bits are set in [2].
[test 07] on success, [1].field1 `cur_rwx` is set to [2] new_cur_rwx.
[test 08] on success, subsequent accesses to mapped pages use effective permissions = `cur_rwx` ∩ `page_frame.r/w/x` (for map=1) or `cur_rwx` (for map=3).
[test 09] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

### snapshot

#### Summary

Binds a source VMAR to a target VMAR. On the owning domain's restart, the kernel copies the source's contents into the target before the domain resumes. Used together with `restart_policy = snapshot` on the target VMAR — see §[restart_semantics].

#### Declaration

```
snapshot([1] target_vmar, [2] source_vmar) -> void
  syscall_num = 37

  [1] target_vmar: VMAR handle (must have `caps.restart_policy = snapshot` (3))
  [2] source_vmar: VMAR handle (must have `caps.restart_policy = preserve` (2))
```

#### Description

Calling `snapshot` again replaces any prior binding for `[1]`.

At restart time, the source-to-target copy succeeds only if the source is stable:
- For `[2].field1.map = 1` (page_frame-backed): every backing page_frame has `field1.mapcnt = 1` AND the source's effective write permission is 0 (`[2].field1.cur_rwx` write bit ∩ each page_frame's `caps.w` is 0).
- For `[2].field1.map = 3` (demand-paged): the source's `cur_rwx.w = 0`. Demand-paged pages are kernel-allocated and not exposed elsewhere, so `mapcnt = 1` is implicit.

If the source's stability cannot be verified at restart, the restart fails and the domain is terminated.

#### Capabilities

- VMAR `[1]`: `restart_policy = snapshot` (3)
- VMAR `[2]`: `restart_policy = preserve` (2)

#### Errors

**E_BADCAP** — `[1]` or `[2]` is not a valid VMAR handle.

**E_INVAL** — `[1].caps.restart_policy != 3`; `[2].caps.restart_policy != 2`; sizes differ (`page_count × sz`); reserved bits set in `[1]` or `[2]`.

#### Tests

[test 01] returns E_BADCAP if [1] is not a valid VMAR handle.
[test 02] returns E_BADCAP if [2] is not a valid VMAR handle.
[test 03] returns E_INVAL if [1].caps.restart_policy is not 3 (snapshot).
[test 04] returns E_INVAL if [2].caps.restart_policy is not 2 (preserve).
[test 05] returns E_INVAL if [1] and [2] have different sizes (`page_count` × `sz`).
[test 06] returns E_INVAL if any reserved bits are set in [1] or [2].
[test 07] calling `snapshot` a second time on the same target replaces the prior source binding.
[test 08] if the source [2] is deleted before restart, the binding is cleared; on restart with no source bound, the domain is terminated rather than restarted.
[test 09] on domain restart, when the source's stability constraints hold, [1]'s contents are replaced by a copy of [2]'s contents before the domain resumes.
[test 10] on domain restart, when [2].map = 1 and any backing page_frame has `mapcnt > 1` or the source's effective write permission is nonzero, the restart fails and the domain is terminated.
[test 11] on domain restart, when [2].map = 3 and `[2].cur_rwx.w = 1`, the restart fails and the domain is terminated.

### idc_read

#### Summary

Reads qwords from a VMAR into the caller's vregs. Used for cross-domain memory inspection (e.g., debugger reads of an acquired VMAR's contents).

#### Declaration

```
idc_read([1] vmar, [2] offset) -> [3..2+count] qwords
  syscall_num = 38

  syscall word bits 12-19: count (number of qwords; max 125)

  [1] vmar:    VMAR handle
  [2] offset: byte offset within the VMAR (must be 8-byte aligned)
```

#### Description

The kernel pauses every EC in the VMAR's owning domain for the duration of the call so the read returns a consistent snapshot; this is intended as a debugger primitive, not a performance path.

#### Capabilities

- VMAR handle `[1]`: `r`

#### Return value

`[3..2+count]`: qwords read from the VMAR starting at `[2]`.

#### Errors

**E_BADCAP** — `[1]` is not a valid VMAR handle.

**E_PERM** — `[1]` does not have the `r` cap.

**E_INVAL** — `[2]` not 8-byte aligned; count is 0 or > 125; `[2] + count*8` exceeds the VMAR's size; reserved bits set in `[1]` or `[2]`.

#### Tests

[test 01] returns E_BADCAP if [1] is not a valid VMAR handle.
[test 02] returns E_PERM if [1] does not have the `r` cap.
[test 03] returns E_INVAL if [2] offset is not 8-byte aligned.
[test 04] returns E_INVAL if count is 0 or count > 125.
[test 05] returns E_INVAL if [2] + count*8 exceeds the VMAR's size.
[test 06] returns E_INVAL if any reserved bits are set in [1] or [2].
[test 07] on success, vregs `[3..2+count]` contain the qwords from the VMAR starting at [2] offset.
[test 08] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

### idc_write

#### Summary

Writes qwords from the caller's vregs into a VMAR. Used for cross-domain memory writes (e.g., debugger writes of an acquired VMAR's contents).

#### Declaration

```
idc_write([1] vmar, [2] offset, [3..2+count] qwords) -> void
  syscall_num = 39

  syscall word bits 12-19: count (number of qwords; max 125)

  [1] vmar:    VMAR handle
  [2] offset: byte offset within the VMAR (must be 8-byte aligned)
  [3..2+count] qwords: bytes to write into the VMAR
```

#### Description

The kernel pauses every EC in the VMAR's owning domain for the duration of the call so the write commits without observable interleaving; this is intended as a debugger primitive, not a performance path.

#### Capabilities

- VMAR handle `[1]`: `w`

#### Errors

**E_BADCAP** — `[1]` is not a valid VMAR handle.

**E_PERM** — `[1]` does not have the `w` cap.

**E_INVAL** — `[2]` not 8-byte aligned; count is 0 or > 125; `[2] + count*8` exceeds the VMAR's size; reserved bits set in `[1]` or `[2]`.

#### Tests

[test 01] returns E_BADCAP if [1] is not a valid VMAR handle.
[test 02] returns E_PERM if [1] does not have the `w` cap.
[test 03] returns E_INVAL if [2] offset is not 8-byte aligned.
[test 04] returns E_INVAL if count is 0 or count > 125.
[test 05] returns E_INVAL if [2] + count*8 exceeds the VMAR's size.
[test 06] returns E_INVAL if any reserved bits are set in [1] or [2].
[test 07] on success, the qwords from vregs `[3..2+count]` are written into the VMAR starting at [2] offset.
[test 08] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

## §[page_frame] Page Frame

A page frame is a reference to physical memory. Installing it into virtual memory address regions bound to multiple capability domains creates shared memory.

Handle ABI:

```
word 0:
 63            48 47                          16 15   12 11         0
┌────────────────┬──────────────────────────────┬───────┬────────────┐
│   cap (16)     │       _reserved (32)         │type(4)│   id(12)   │
└────────────────┴──────────────────────────────┴───────┴────────────┘

word 1 (field0):
 63                         34 33 32 31                            0
┌─────────────────────────────┬──────┬────────────────────────────────┐
│        _reserved (30)       │  sz  │        page_count (32)         │
└─────────────────────────────┴──────┴────────────────────────────────┘

word 2 (field1):
 63                            32 31                               0
┌────────────────────────────────┬──────────────────────────────────┐
│         _reserved (32)         │           mapcnt (32)            │
└────────────────────────────────┴──────────────────────────────────┘
```

Field layout:

| field | location | meaning |
|---|---|---|
| page_count | field0 bits 0-31 | number of pages (in `sz` units) |
| sz | field0 bits 32-33 | page size (immutable): 0=4 KiB, 1=2 MiB, 2=1 GiB, 3=reserved |
| mapcnt | field1 bits 0-31 | total number of active installations of this physical page across all VMARs and IOMMU domains; sync-refreshed on any syscall touching the handle |

cap (word 0, bits 48-63):

```
 15           8 7      6   5  4   3   2    1    0
┌──────────────┬──────┬──────┬───┬───┬───┬────┬────┐
│_reserved (8) │rstrt │max_sz│ x │ w │ r │copy│move│
│              │_plcy │      │   │   │   │    │    │
└──────────────┴──────┴──────┴───┴───┴───┴────┴────┘
```

| Bit(s) | Name | Meaning |
|---|---|---|
| 0 | `move` | transferring this handle via move to another capability domain |
| 1 | `copy` | transferring this handle via copy to another capability domain |
| 2 | `r` | read; applied only if the installing VMAR's `cur_rwx.r` is set |
| 3 | `w` | write; applied only if the installing VMAR's `cur_rwx.w` is set |
| 4 | `x` | execute; applied only if the installing VMAR's `cur_rwx.x` is set |
| 5-6 | `max_sz` | max page size: 0=4 KiB, 1=2 MiB, 2=1 GiB, 3=reserved |
| 7 | `restart_policy` | page_frame behavior on domain restart: 0=drop, 1=keep (see §[restart_semantics]) |
| 8-15 | `_reserved` | |

### create_page_frame

#### Summary

Allocates physical memory and returns a page frame handle.

#### Declaration

```
create_page_frame([1] caps, [2] props, [3] pages) -> [1] handle
  syscall_num = 40

  [1] caps: u64 packed as
    bits  0-15: caps        — caps on the page frame handle returned to the caller
    bits 16-63: _reserved

  [2] props: u64 packed as
    bits  0-1: sz           — page size (immutable)
    bits  2-63: _reserved

  [3] pages: number of `sz` pages to allocate
```

#### Capabilities

- Self-handle: `crpf`
- `[1].caps` r/w/x ⊆ caller's `pf_ceiling.max_rwx`
- `[1].caps.max_sz` ≤ caller's `pf_ceiling.max_sz`

#### Return value

`[1]`: page frame handle with caps = `[1].caps`.

#### Errors

**E_PERM** — self-handle lacks `crpf`; `caps.r/w/x` not a subset of `pf_ceiling.max_rwx`; `caps.max_sz` exceeds `pf_ceiling.max_sz`.

**E_INVAL** — `[3] pages = 0`; `caps.max_sz = 3` (reserved); `props.sz = 3` (reserved); `props.sz` exceeds `caps.max_sz`; reserved bits set in `[1]` or `[2]`.

**E_NOMEM** — insufficient physical memory.

**E_FULL** — caller's handle table has no free slot.

#### Tests

[test 01] returns E_PERM if the caller's self-handle lacks `crpf`.
[test 02] returns E_PERM if caps' r/w/x bits are not a subset of the caller's `pf_ceiling.max_rwx`.
[test 03] returns E_PERM if caps.max_sz exceeds the caller's `pf_ceiling.max_sz`.
[test 04] returns E_INVAL if [3] pages is 0.
[test 05] returns E_INVAL if caps.max_sz is 3 (reserved).
[test 06] returns E_INVAL if props.sz is 3 (reserved).
[test 07] returns E_INVAL if props.sz exceeds caps.max_sz.
[test 08] returns E_INVAL if any reserved bits are set in [1] or [2].
[test 09] on success, the caller receives a page frame handle with caps = `[1].caps`.
[test 10] on success, field0 contains `[3]` pages and `[2].props.sz`.

## §[device_region] Device Region

A device region is a reference to a physical device's MMIO region or x86-64 I/O port range. Installing it into a virtual memory address region makes the device directly accessible to execution contexts in that capability domain.

Handle ABI:

```
word 0:
 63            48 47                          16 15   12 11         0
┌────────────────┬──────────────────────────────┬───────┬────────────┐
│   cap (16)     │       _reserved (32)         │type(4)│   id(12)   │
└────────────────┴──────────────────────────────┴───────┴────────────┘

word 1 (field0):
 63                            36 35              20 19              4 3       0
┌────────────────────────────────┬──────────────────┬──────────────────┬─────────┐
│        _reserved (28)          │  port_count (16) │  base_port (16)  │dev_type │
│                                │                  │                  │  (4)    │
└────────────────────────────────┴──────────────────┴──────────────────┴─────────┘

word 2 (field1):
 63                                                                  0
┌─────────────────────────────────────────────────────────────────────┐
│                       irq_count (64)                                │
└─────────────────────────────────────────────────────────────────────┘
```

Field layout:

| field | location | meaning |
|---|---|---|
| dev_type | field0 bits 0-3 | device region kind (immutable): 0=mmio, 1=port_io (x86-64 only); other values _reserved |
| base_port | field0 bits 4-19 | x86-64 I/O port base (u16) for `dev_type = port_io`; _reserved otherwise |
| port_count | field0 bits 20-35 | number of consecutive x86-64 I/O ports (u16) for `dev_type = port_io`; _reserved otherwise |
| irq_count | field1 bits 0-63 | u64 IRQ counter, kernel-incremented (saturating at u64::MAX) on each device IRQ; cleared by `ack`. The kernel propagates each increment to every domain-local copy of the handle, but propagation is not atomic across copies — different copies may transiently observe different counts (see §[device_irq]). 0 stays 0 for device regions that do not deliver IRQs |

cap (word 0, bits 48-63):

```
 15                              5    4    3    2    1    0
┌─────────────────────────────────┬──────┬────┬────┬────┬────┐
│         _reserved (11)          │rstrt │ irq│dma │copy│move│
│                                 │_plcy │    │    │    │    │
└─────────────────────────────────┴──────┴────┴────┴────┴────┘
```

| Bit | Name | Gates |
|---|---|---|
| 0 | `move` | transferring this handle via move to another capability domain |
| 1 | `copy` | transferring this handle via copy to another capability domain |
| 2 | `dma` | binding this device_region to a DMA-flagged VMAR via `create_vmar`, authorizing IOMMU mappings for the device |
| 3 | `irq` | acknowledging IRQs from this device via `ack` |
| 4 | `restart_policy` | device_region behavior on domain restart: 0=drop, 1=keep (see §[restart_semantics]) |

### §[port_io_virtualization] x86-64 Port I/O Virtualization

A device_region with `dev_type = port_io` carries a 16-bit `base_port` and `port_count`. Installing it into an MMIO VMAR via `map_mmio` reserves the VMAR's virtual range without populating CPU page tables: every CPU access to the range page-faults into the kernel.

The kernel handles such faults by decoding the faulting MOV instruction, computing the target port as `base_port + (fault_vaddr - VMAR.base)`, executing the corresponding x86-64 `in`/`out` of the operand width, writing the result into the destination GPR (loads) or committing the source value (stores), and advancing RIP past the instruction.

Supported decoder forms: `MOV r/m ↔ reg` and `MOV r/m ← imm` with operand widths of 1, 2, or 4 bytes. Other instruction forms targeting the range — `IN`/`OUT` named mnemonics, `INS`/`OUTS`, 8-byte operand widths, and `LOCK`-prefixed variants — deliver a `thread_fault` event with the protection_fault sub-code.

Effective permissions follow `VMAR.cur_rwx`: a read MOV when `cur_rwx.r = 0`, or a write MOV when `cur_rwx.w = 0`, delivers a `memory_fault` event. Accesses with computed offset `>= port_count` deliver a `memory_fault` event.

[test 01] `map_mmio` returns E_INVAL if [2].field0.dev_type = port_io and the running architecture is not x86-64.
[test 02] `map_mmio` returns E_INVAL if [2].field0.dev_type = port_io and [1].field1.cch != 1 (uc).
[test 03] `map_mmio` returns E_INVAL if [2].field0.dev_type = port_io and [1].caps.x is set.
[test 04] a 1-, 2-, or 4-byte MOV load from `VMAR.base + offset` (offset < port_count, `cur_rwx.r = 1`) leaves the destination GPR holding the value an x86-64 `in` of the matching operand width at port `base_port + offset` would produce, and execution resumes at the instruction immediately following the MOV.
[test 05] a 1-, 2-, or 4-byte MOV store to `VMAR.base + offset` (offset < port_count, `cur_rwx.w = 1`) commits the source value to port `base_port + offset` (observable on a loopback device_region as a subsequent MOV load returning that value), and execution resumes at the instruction immediately following the MOV.
[test 06] a MOV access to `VMAR.base + offset` with `offset >= port_count` delivers a `memory_fault` event.
[test 07] a MOV load when `VMAR.cur_rwx.r = 0` delivers a `memory_fault` event.
[test 08] a MOV store when `VMAR.cur_rwx.w = 0` delivers a `memory_fault` event.
[test 09] an `IN`, `OUT`, `INS`, or `OUTS` instruction targeting the VMAR delivers a `thread_fault` event with the protection_fault sub-code.
[test 10] a `LOCK`-prefixed MOV targeting the VMAR delivers a `thread_fault` event with the protection_fault sub-code.
[test 11] an 8-byte MOV access targeting the VMAR delivers a `thread_fault` event with the protection_fault sub-code.

### §[device_irq] Device IRQ Delivery

A device_region configured for IRQ delivery exposes its IRQ counter directly as `field1.irq_count` of every handle to it. The handle table is mapped read-only into the holding domain, so the field's vaddr (computable as `cap_table_base + handle_id * sizeof(handle) + offsetof(field1)`) is a valid futex address.

On each IRQ from the bound device, the kernel:
1. Atomically increments `field1.irq_count` by 1 (saturating at `u64::MAX`) in every domain-local copy of the handle. Increments are propagated to all copies but not atomically across copies — different copies may transiently observe different counts.
2. Masks the IRQ line at the interrupt controller.
3. Issues a futex wake on the physical address of `field1` for each copy.

Userspace pairs the counter with `futex_wait_val(addr=&handle.field1, expected=last_seen)` to sleep until the next IRQ. After observing one or more IRQs, userspace calls `ack` to clear the counter and unmask the line.

[test 01] when the device fires an IRQ, within a bounded delay every domain-local copy of [1] returns `field1.irq_count = (prior + 1)` from a fresh `sync`.
[test 02] when the device fires a second IRQ before `ack` is called, [1].field1.irq_count is not incremented a second time; only after `ack` does a subsequent IRQ from the device increment it again.
[test 03] when the device fires an IRQ, every EC blocked in futex_wait_val keyed on the paddr of any domain-local copy of [1].field1 returns from the call with [1] = the corresponding domain-local vaddr of field1.
[test 04] when the device has no IRQ delivery configured, [1].field1.irq_count remains 0.

### ack

#### Summary

Acknowledges accumulated IRQs from a device_region. Atomically reads the current IRQ counter, resets it to 0, and unmasks the IRQ line at the interrupt controller.

#### Declaration

```
ack([1] device_region) -> [1] prior_count
  syscall_num = 41

  [1] device_region: device_region handle
```

#### Capabilities

- device_region handle `[1]`: `irq`

#### Return value

`[1]`: prior IRQ counter value (counter immediately before the call).

#### Errors

**E_BADCAP** — `[1]` is not a valid device_region handle.

**E_PERM** — `[1]` does not have the `irq` cap.

**E_INVAL** — the device_region has no IRQ delivery configured; reserved bits set in `[1]`.

#### Tests

[test 01] returns E_BADCAP if [1] is not a valid device_region handle.
[test 02] returns E_PERM if [1] does not have the `irq` cap.
[test 03] returns E_INVAL if the device_region has no IRQ delivery configured.
[test 04] returns E_INVAL if any reserved bits are set in [1].
[test 05] on success, the returned `prior_count` equals [1].field1.irq_count immediately before the call.
[test 06] on success, the calling domain's copy of [1] has `field1.irq_count = 0` immediately on return; every other domain-local copy returns 0 from a fresh `sync` within a bounded delay.
[test 07] on success, after a subsequent IRQ from the device, every domain-local copy's `field1.irq_count` reaches the new value within a bounded delay and an EC blocked in `futex_wait_val` on each copy's `field1` paddr is woken.
[test 08] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

## §[virtual_machine] Virtual Machine

A virtual machine is a guest execution environment with its own guest physical address space. Execution contexts enter guest mode within a VM to run.

Handle ABI:

```
word 0:
 63            48 47                          16 15   12 11         0
┌────────────────┬──────────────────────────────┬───────┬────────────┐
│   cap (16)     │       _reserved (32)         │type(4)│   id(12)   │
└────────────────┴──────────────────────────────┴───────┴────────────┘

word 1 (field0):
 63                                                                  0
┌─────────────────────────────────────────────────────────────────────┐
│                         _reserved (64)                              │
└─────────────────────────────────────────────────────────────────────┘

word 2 (field1):
 63                                                                  0
┌─────────────────────────────────────────────────────────────────────┐
│                         _reserved (64)                              │
└─────────────────────────────────────────────────────────────────────┘
```

cap (word 0, bits 48-63):

```
 15                                                  2    1     0
┌────────────────────────────────────────────────────┬──────┬──────┐
│              _reserved (14)                        │rstrt │policy│
│                                                    │_plcy │      │
└────────────────────────────────────────────────────┴──────┴──────┘
```

| Bit | Name | Gates |
|---|---|---|
| 0 | `policy` | mutating this VM's policy tables (§[vm_policy]) via runtime syscalls |
| 1 | `restart_policy` | VM behavior on domain restart: 0=drop, 1=keep (see §[restart_semantics]) |

### create_virtual_machine

#### Summary

Allocates a VM with its own guest physical address space and initializes kernel-emulated LAPIC/IOAPIC state. vCPUs are created separately via `create_vcpu`.

#### Declaration

```
create_virtual_machine([1] caps, [2] policy_page_frame) -> [1] handle
  syscall_num = 42

  [1] caps: u64 packed as
    bits  0-15: caps       — caps on the VM handle returned to the caller
    bits 16-63: _reserved

  [2] policy_page_frame: page frame handle containing a VmPolicy struct at
                         offset 0 (static CPUID responses and CR access
                         policies applied to all vCPUs on exits; layout in
                         §[vm_policy])
```

#### Description

The kernel retains a reference on `policy_page_frame` for the lifetime of the VM.

#### Capabilities

- Self-handle: `crvm`
- `[1].caps` ⊆ caller's `vm_ceiling`

#### Return value

`[1]`: VM handle with caps = `[1].caps`.

#### Errors

**E_PERM** — self-handle lacks `crvm`; `caps` not a subset of `vm_ceiling`.

**E_BADCAP** — `[2]` is not a valid page frame handle.

**E_INVAL** — `policy_page_frame` smaller than `sizeof(VmPolicy)`; `VmPolicy.num_cpuid_responses` exceeds `MAX_CPUID_POLICIES`; `VmPolicy.num_cr_policies` exceeds `MAX_CR_POLICIES`; reserved bits set in `[1]`.

**E_NODEV** — platform does not support hardware virtualization.

**E_NOMEM** — insufficient kernel memory.

**E_FULL** — caller's handle table has no free slot.

#### Tests

[test 01] returns E_PERM if the caller's self-handle lacks `crvm`.
[test 02] returns E_PERM if caps is not a subset of the caller's `vm_ceiling`.
[test 03] returns E_NODEV if the platform does not support hardware virtualization.
[test 04] returns E_BADCAP if [2] is not a valid page frame handle.
[test 05] returns E_INVAL if `policy_page_frame` is smaller than `sizeof(VmPolicy)`.
[test 06] returns E_INVAL if `VmPolicy.num_cpuid_responses` exceeds `MAX_CPUID_POLICIES`.
[test 07] returns E_INVAL if `VmPolicy.num_cr_policies` exceeds `MAX_CR_POLICIES`.
[test 08] returns E_INVAL if any reserved bits are set in [1].
[test 09] on success, the caller receives a VM handle with caps = `[1].caps`.

### §[vm_policy] VM Policy

`VmPolicy` is a per-arch struct carrying fixed-size tables consulted by the kernel on guest exits to handle selected operations inline. Each table has an entry array and a count; only the first `num_*` entries are consulted. Tables seed with `create_virtual_machine` and are mutable at runtime by VMs holding the `policy` cap via `vm_set_policy`.

**x86-64**

```
VmPolicy {
  cpuid_responses: CpuidPolicy[MAX_CPUID_POLICIES],
  num_cpuid_responses: u32,
  _pad0: u32,
  cr_policies: CrPolicy[MAX_CR_POLICIES],
  num_cr_policies: u32,
  _pad1: u32,
}

CpuidPolicy {
  leaf: u32,
  subleaf: u32,
  eax: u32,
  ebx: u32,
  ecx: u32,
  edx: u32,
}

CrPolicy {
  cr_num: u8,
  _pad: u8[7],
  read_value: u64,
  write_mask: u64,
}

MAX_CPUID_POLICIES = 32
MAX_CR_POLICIES = 8
```

Semantics:
- A guest `CPUID` matching `(leaf, subleaf)` in `cpuid_responses` resumes with `(eax, ebx, ecx, edx)` from the entry. Non-matching CPUIDs deliver a `vm_exit` event.
- A guest CR read matching `cr_num` in `cr_policies` resumes with `read_value`; a guest CR write matching `cr_num` is applied masked by `write_mask` (bits not set in `write_mask` are ignored). Non-matching CR accesses deliver a `vm_exit` event.
- MSR accesses are not covered by `VmPolicy` today; they always deliver a `vm_exit` event unless explicitly configured via a separate passthrough mechanism.

**aarch64**

```
VmPolicy {
  id_reg_responses: IdRegResponse[MAX_ID_REG_RESPONSES],
  num_id_reg_responses: u32,
  _pad0: u32,
  sysreg_policies: SysregPolicy[MAX_SYSREG_POLICIES],
  num_sysreg_policies: u32,
  _pad1: u32,
}

IdRegResponse {
  op0: u8,
  op1: u8,
  crn: u8,
  crm: u8,
  op2: u8,
  _pad: u8[3],
  value: u64,
}

SysregPolicy {
  op0: u8,
  op1: u8,
  crn: u8,
  crm: u8,
  op2: u8,
  _pad: u8[3],
  read_value: u64,
  write_mask: u64,
}

MAX_ID_REG_RESPONSES = 62
MAX_SYSREG_POLICIES = 32
```

Sysreg identifiers `(op0, op1, crn, crm, op2)` follow Arm ARM C5.3.

Semantics:
- A guest read of an `ID_AA64*` register matching the `(op0, op1, crn, crm, op2)` tuple in `id_reg_responses` resumes with `value`. Writes to ID registers are silently ignored.
- A guest sysreg read matching the tuple in `sysreg_policies` resumes with `read_value`; a guest sysreg write matching the tuple is applied masked by `write_mask` (bits not set in `write_mask` are ignored). Non-matching sysreg accesses deliver a `vm_exit` event.

### create_vcpu

#### Summary

Creates a vCPU execution context bound to a VM. The vCPU is created suspended on its exit port with zeroed guest state; the creator installs initial guest state through the same mechanism used to handle vm exits — recv on the exit port, modify the vregs, reply with a resume action.

#### Declaration

```
create_vcpu([1] caps, [2] vm_handle, [3] affinity, [4] exit_port) -> [1] handle
  syscall_num = 43

  [1] caps: u64 packed as
    bits  0-15: caps       — caps on the EC handle returned to the caller
    bits 32-33: priority   — scheduling priority, 0-3, bounded by caller's priority ceiling
    bits 34-63: _reserved

  [2] vm_handle:  VM handle the vCPU binds to
  [3] affinity:   64-bit core mask; bit N = 1 allows the vCPU to run on core N.
                  0 = any core (kernel chooses)
  [4] exit_port:  port handle where vm_exit events for this vCPU are delivered
```

#### Description

The vCPU EC is bound to the capability domain that holds the VM handle. `create_vcpu` binds `exit_port` as the destination for its vm_exit events. Immediately upon creation, the kernel enqueues a vm_exit-style delivery on `exit_port` representing the initial "not yet started" condition: the reply cap is valid, all guest-state vregs are zero, and the exit sub-code is the `initial_state` sub-code. The creator recvs this event, writes the real initial guest state into the vregs, and replies with a resume action to enter guest mode. All subsequent guest exits flow through the same port and the same reply-cap lifecycle.

#### Capabilities

- Self-handle: `crec`. Holding the VM handle implies the authority to spawn vCPUs in it.
- `[1].caps` ⊆ VM's owning domain's `ec_inner_ceiling`
- `[1].priority` ≤ caller's priority ceiling

#### Return value

`[1]`: EC handle with caps = `[1].caps`.

#### Errors

**E_PERM** — self-handle lacks `crec`; `caps` not a subset of the VM's owning domain's `ec_inner_ceiling`; `priority` exceeds the caller's priority ceiling.

**E_BADCAP** — `[2]` is not a valid VM handle; `[4]` is not a valid port handle.

**E_INVAL** — `[3]` affinity has bits set outside the system's core count; reserved bits set in `[1]`.

**E_NOMEM** — insufficient kernel memory.

**E_FULL** — caller's handle table has no free slot.

#### Tests

[test 01] returns E_PERM if the caller's self-handle lacks `crec`.
[test 02] returns E_PERM if caps is not a subset of the VM's owning domain's `ec_inner_ceiling`.
[test 03] returns E_PERM if priority exceeds the caller's priority ceiling.
[test 04] returns E_BADCAP if [2] is not a valid VM handle.
[test 05] returns E_BADCAP if [4] is not a valid port handle.
[test 06] returns E_INVAL if [3] affinity has bits set outside the system's core count.
[test 07] returns E_INVAL if any reserved bits are set in [1].
[test 08] on success, the caller receives an EC handle with caps = `[1].caps`.
[test 09] on success, `suspend` on the returned EC handle returns E_INVAL, and after `recv` on [4] consumes the initial vm_exit and `reply` on its reply handle, a subsequent `recv` on [4] returns a vm_exit whose vreg layout matches §[vm_exit_state] for VM [2]'s architecture.
[test 10] on success, the EC's priority is set to `[1].priority`.
[test 11] on success, the EC's affinity is set to `[3]`.
[test 12] immediately after creation, an initial vm_exit event is delivered on `[4] exit_port` with zeroed guest state in the vregs and the `initial_state` sub-code.

### map_guest

#### Summary

Installs page_frames into the VM's guest physical address space. Subsequent guest accesses to `guest_addr` translate via the second-stage page tables to the corresponding page_frame.

#### Declaration

```
map_guest([1] vm, [2 + 2i] guest_addr, [2 + 2i + 1] page_frame) -> void
  syscall_num = 44

  syscall word bits 12-19: N (number of (guest_addr, page_frame) pairs)

  [1] vm: VM handle
  [2 + 2i] guest_addr: guest physical address
  [2 + 2i + 1] page_frame: page_frame handle to install at that guest_addr

  for i in 0..N-1.
```

#### Capabilities

None beyond holding the VM handle.

#### Errors

**E_BADCAP** — `[1]` is not a valid VM handle; any `[2 + 2i + 1]` is not a valid page_frame handle.

**E_INVAL** — N is 0; any `guest_addr` not aligned to its paired page_frame's `sz`; any two pairs' ranges overlap; any pair's range overlaps an existing mapping.

#### Tests

[test 01] returns E_BADCAP if [1] is not a valid VM handle.
[test 02] returns E_BADCAP if any [2 + 2i + 1] is not a valid page_frame handle.
[test 03] returns E_INVAL if N is 0.
[test 04] returns E_INVAL if any guest_addr is not aligned to its paired page_frame's `sz`.
[test 05] returns E_INVAL if any two pairs' ranges overlap.
[test 06] returns E_INVAL if any pair's range overlaps an existing mapping in the VM's guest physical address space.
[test 07] on success, a guest read from `guest_addr` returns the paired page_frame's contents, and a guest access whose required rwx is not a subset of `page_frame.r/w/x` delivers a `vm_exit` event on the vCPU's bound exit_port with sub-code = `ept` (x86-64) or `stage2_fault` (aarch64).

### unmap_guest

#### Summary

Removes page_frame mappings from a VM's guest physical address space.

#### Declaration

```
unmap_guest([1] vm, [2 + i] page_frame for i in 0..N-1) -> void
  syscall_num = 45

  syscall word bits 12-19: N (number of page_frames to unmap)

  [1] vm: VM handle
  [2 + i] page_frame: page_frame handle to unmap from the VM
```

#### Capabilities

None beyond holding the VM handle.

#### Errors

**E_BADCAP** — `[1]` is not a valid VM handle; any `[2 + i]` is not a valid page_frame handle.

**E_INVAL** — N is 0.

**E_NOENT** — any page_frame is not currently mapped in `[1]`.

#### Tests

[test 01] returns E_BADCAP if [1] is not a valid VM handle.
[test 02] returns E_BADCAP if any [2 + i] is not a valid page_frame handle.
[test 03] returns E_INVAL if N is 0.
[test 04] returns E_NOENT if any page_frame is not currently mapped in [1].
[test 05] on success, each page_frame's installation in [1]'s guest physical address space is removed; subsequent guest accesses to those guest_addr ranges deliver a `vm_exit` event on the vCPU's bound exit_port with sub-code = `ept` (x86-64) or `stage2_fault` (aarch64).

### vm_set_policy

#### Summary

Replaces a single VmPolicy table on the VM, atomically. Tables for other kinds are unchanged.

#### Declaration

```
vm_set_policy([1] vm, [2..] entries) -> void
  syscall_num = 46

  syscall word bit 12:     kind
  syscall word bits 13-20: count (number of entries supplied)

  [1] vm: VM handle
```

#### Description

The kind selector is overloaded across architectures; see the per-arch tables below.

**x86-64**

| kind | meaning | vregs/entry | layout (entry 0 starts at vreg 2) |
|---|---|---|---|
| 0 | replaces `cpuid_responses` | 3 | `[2+3i+0]` = `{leaf u32, subleaf u32}`; `[2+3i+1]` = `{eax u32, ebx u32}`; `[2+3i+2]` = `{ecx u32, edx u32}` |
| 1 | replaces `cr_policies` | 3 | `[2+3i+0]` = `{cr_num u8, _pad u8[7]}`; `[2+3i+1]` = `read_value u64`; `[2+3i+2]` = `write_mask u64` |

**aarch64**

| kind | meaning | vregs/entry | layout (entry 0 starts at vreg 2) |
|---|---|---|---|
| 0 | replaces `id_reg_responses` | 2 | `[2+2i+0]` = `{op0 u8, op1 u8, crn u8, crm u8, op2 u8, _pad u8[3]}`; `[2+2i+1]` = `value u64` |
| 1 | replaces `sysreg_policies` | 3 | `[2+3i+0]` = `{op0 u8, op1 u8, crn u8, crm u8, op2 u8, _pad u8[3]}`; `[2+3i+1]` = `read_value u64`; `[2+3i+2]` = `write_mask u64` |

#### Capabilities

- VM handle `[1]`: `policy`

#### Errors

**E_BADCAP** — `[1]` is not a valid VM handle.

**E_PERM** — `[1]` does not have the `policy` cap.

**E_INVAL** — count exceeds the active (kind, arch)'s `MAX_*` constant from §[vm_policy]; reserved bits set in `[1]` or any entry.

#### Tests

[test 01] returns E_BADCAP if [1] is not a valid VM handle.
[test 02] returns E_PERM if [1] does not have the `policy` cap.
[test 03] returns E_INVAL if count exceeds the active (kind, arch)'s MAX_* constant from §[vm_policy].
[test 04] returns E_INVAL if any reserved bits are set in [1] or any entry.
[test 05] on x86-64 with kind=0, the VM's `cpuid_responses` table is replaced by the count entries; subsequent guest CPUIDs match against this table per §[vm_policy], and the prior contents are no longer matched.
[test 06] on x86-64 with kind=1, the VM's `cr_policies` table is replaced by the count entries; subsequent guest CR accesses match against this table per §[vm_policy].
[test 07] on aarch64 with kind=0, the VM's `id_reg_responses` table is replaced by the count entries; subsequent guest reads of matching ID_AA64* registers return the configured values per §[vm_policy].
[test 08] on aarch64 with kind=1, the VM's `sysreg_policies` table is replaced by the count entries; subsequent guest sysreg accesses match against this table per §[vm_policy].
[test 09] on success, the table for the other kind is unchanged.

### vm_inject_irq

#### Summary

Asserts or deasserts a virtual IRQ line on the VM's emulated interrupt controller.

#### Declaration

```
vm_inject_irq([1] vm, [2] irq_num, [3] assert) -> void
  syscall_num = 47

  [1] vm:      VM handle
  [2] irq_num: u64 virtual IRQ line number
  [3] assert:  u64 packed as
    bit 0: 1 = assert, 0 = deassert
    bits 1-63: _reserved
```

#### Description

Routing to vCPUs follows the guest's configured redirection (IOAPIC RTE on x86-64, GIC distributor on aarch64).

#### Capabilities

None beyond holding `[1]`.

#### Errors

**E_BADCAP** — `[1]` is not a valid VM handle.

**E_INVAL** — `[2]` exceeds the maximum IRQ line supported by the VM's emulated interrupt controller; reserved bits set in `[1]` or `[3]`.

#### Tests

[test 01] returns E_BADCAP if [1] is not a valid VM handle.
[test 02] returns E_INVAL if [2] exceeds the maximum IRQ line supported by the VM's emulated interrupt controller.
[test 03] returns E_INVAL if any reserved bits are set in [1] or [3].
[test 04] on success with [3].assert = 1, IRQ line [2] is asserted on the VM's emulated interrupt controller; if a vCPU is unmasked for the line, an interrupt event is delivered to the vCPU on its next runnable opportunity (observable as an exception/interrupt vm_exit or as a guest interrupt handler invocation per the guest's IDT/GIC configuration).
[test 05] on success with [3].assert = 0 immediately after a prior `vm_inject_irq([1], [2], assert = 1)`, no interrupt vm_exit corresponding to line [2] is delivered to any vCPU even when the vCPU's interrupt window opens or it becomes runnable with the line unmasked.

## §[port] Port

A port is a rendezvous point between a calling execution context and a receiving execution context, used for IDC, transfer of capabilities, and execution context event delivery.

Handle ABI:

```
word 0:
 63            48 47                          16 15   12 11         0
┌────────────────┬──────────────────────────────┬───────┬────────────┐
│   cap (16)     │       _reserved (32)         │type(4)│   id(12)   │
└────────────────┴──────────────────────────────┴───────┴────────────┘

word 1 (field0):
 63                                                                  0
┌─────────────────────────────────────────────────────────────────────┐
│                         _reserved (64)                              │
└─────────────────────────────────────────────────────────────────────┘

word 2 (field1):
 63                                                                  0
┌─────────────────────────────────────────────────────────────────────┐
│                         _reserved (64)                              │
└─────────────────────────────────────────────────────────────────────┘
```

cap (word 0, bits 48-63):

```
 15                  6    5    4    3    2    1    0
┌─────────────────────┬──────┬────┬────┬────┬────┬────┐
│  _reserved (10)     │rstrt │bind│recv│xfer│copy│move│
│                     │_plcy │    │    │    │    │    │
└─────────────────────┴──────┴────┴────┴────┴────┴────┘
```

| Bit | Name | Meaning |
|---|---|---|
| 0 | `move` | transferring this handle via move to another capability domain |
| 1 | `copy` | transferring this handle via copy to another capability domain |
| 2 | `xfer` | transferring capabilities on this port (attaching handles to a suspension event payload, or to a reply payload) |
| 3 | `recv` | reading events off this port and receiving the associated reply capability |
| 4 | `bind` | using this port as the destination of a `suspend` syscall, the `exit_port` of a `create_vcpu`, or an `event_route` registration |
| 5 | `restart_policy` | port behavior on domain restart: 0=drop, 1=keep (see §[restart_semantics]) |

### create_port

#### Summary

Allocates a port and returns a handle to it.

#### Declaration

```
create_port([1] caps) -> [1] handle
  syscall_num = 48

  [1] caps: u64 packed as
    bits  0-15: caps       — caps on the port handle returned to the caller
    bits 16-63: _reserved
```

#### Capabilities

- Self-handle: `crpt`
- `[1].caps` ⊆ caller's `port_ceiling`

#### Return value

`[1]`: port handle with caps = `[1].caps`.

#### Errors

**E_PERM** — self-handle lacks `crpt`; `caps` not a subset of `port_ceiling`.

**E_INVAL** — reserved bits set in `[1]`.

**E_NOMEM** — insufficient kernel memory.

**E_FULL** — caller's handle table has no free slot.

#### Tests

[test 01] returns E_PERM if the caller's self-handle lacks `crpt`.
[test 02] returns E_PERM if caps is not a subset of the caller's `port_ceiling`.
[test 03] returns E_INVAL if any reserved bits are set in [1].
[test 04] on success, the caller receives a port handle with caps = `[1].caps`.

### suspend

#### Summary

Suspends the target execution context and delivers a suspension event to a port.

#### Declaration

Suspend has two encodings on the wire — a fast variant for the L4-style IPC fast path (no handle attachments, payload entirely in GPR-backed vregs) and a general variant that supports handle attachments and the full payload range.

**Fast variant** — `syscall_op` ∈ `0..13`. The op value IS `payload_count`; `pair_count` is implicitly 0. The entire syscall word must equal exactly the op value (bits 4-63 must be zero on entry). The fast range is reserved exclusively for this encoding — no other syscall may take a value in `0..13`.

```
suspend([1] target, [2] port) -> void
  syscall_op = 0..13   (op value = payload_count; pair_count = 0)

  syscall word entry layout:
    bits  0- 3: syscall_op
    bits  4-63: _reserved (must be zero)

  [1] target: EC handle
  [2] port: port handle (suspension event delivery target)
```

**General variant** — `syscall_op = 14`.

```
suspend([1] target, [2] port) -> void
  syscall_op = 14

  syscall word entry layout:
    bits  0-11: syscall_op
    bits 12-19: pair_count           — handles attached by sender (0..63)
    bits 20-26: payload_count        — count of GPR-backed vregs (1..payload_count) the sender delivers as event-state payload (0..127)
    bits 27-63: _reserved

  [1] target: EC handle
  [2] port: port handle (suspension event delivery target)
```

#### Description

The event exposes the EC's state per §[event_state]; the receiver may modify state and reply through the included reply capability to resume the EC.

`[1]` may reference the calling EC; the syscall returns after the calling EC is resumed.

Handle attachments in the suspension event payload follow §[handle_attachments].

The receiver only reads vregs 1..payload_count as event-state payload; vregs above payload_count are undefined. The sender is responsible for zeroing or otherwise preparing its own register state before issuing suspend — the kernel does not zero or restore unused vregs.

#### Capabilities

- EC handle `[1]`: `susp`. Visibility and writability of the target's state in the suspension event are gated by `[1]`'s `read` and `write` caps.
- Port handle `[2]`: `bind`. Additionally `xfer` if any handles are attached.

#### Errors

**E_BADCAP** — `[1]` is not a valid EC handle; `[2]` is not a valid port handle.

**E_PERM** — `[1]` lacks `susp`; `[2]` lacks `bind`.

**E_INVAL** — reserved bits set; `[1]` references a vCPU; `[1]` is already suspended.

#### Tests

[test 01] returns E_BADCAP if [1] is not a valid EC handle.
[test 02] returns E_BADCAP if [2] is not a valid port handle.
[test 03] returns E_PERM if [1] does not have the `susp` cap.
[test 04] returns E_PERM if [2] does not have the `bind` cap.
[test 05] returns E_INVAL if any reserved bits are set.
[test 06] returns E_INVAL if [1] references a vCPU.
[test 07] returns E_INVAL if [1] is already suspended.
[test 08] on success, the target EC stops executing.
[test 09] on success, a suspension event is delivered on [2].
[test 10] on success, when [1] has the `read` cap, the suspension event payload exposes the target's EC state per §[event_state]; otherwise the state in the payload is zeroed.
[test 11] on success, when [1] has the `write` cap, modifications written to the event payload are applied to the target's EC state on reply; otherwise modifications are discarded.
[test 12] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

### recv

#### Summary

Blocks waiting for an event on a port.

#### Declaration

```
recv([1] port, [2] timeout_ns) -> void
  syscall_num = 49

  syscall word return layout (per §[event_state]):
    bits  0-11: _reserved
    bits 12-19: pair_count           — handles attached by sender (0..63)
    bits 20-31: tstart               — slot id of first attached handle
    bits 32-43: reply_handle_id      — slot id of the reply handle
    bits 44-48: event_type
    bits 49-55: payload_count        — count of GPR-backed vregs (1..payload_count) the sender delivered as event-state payload (0..127)
    bits 56-63: _reserved

  [1] port: port handle
  [2] timeout_ns: 0 = block indefinitely; nonzero = give up after this
                  many nanoseconds with E_TIMEOUT
```

#### Description

On return, the kernel has dequeued one suspended sender, allocated a reply handle for it in the caller's table, allocated slots for any handles the sender attached, written the suspended EC's state to the caller's vregs per §[event_state] (and §[vm_exit_state] for vm_exits), and populated the syscall word with the reply handle id, event_type, pair_count, and tstart.

When multiple senders are queued on the port, the kernel selects the highest-priority sender; ties resolve FIFO. The chosen sender remains suspended until the reply handle is consumed: `reply` resumes them, `delete` on the reply handle resolves them with `E_ABANDONED`.

#### Capabilities

- Port handle `[1]`: `recv`

#### Errors

**E_BADCAP** — `[1]` is not a valid port handle.

**E_PERM** — `[1]` does not have the `recv` cap.

**E_INVAL** — reserved bits set in `[1]`.

**E_CLOSED** — port has no bind-cap holders, no event_routes targeting it, and no queued events (call returns immediately rather than blocking); also raised if the port becomes terminally closed while a recv is blocked.

**E_TIMEOUT** — `[2] timeout_ns` is nonzero, no sender queued, and none becomes queued within the deadline.

**E_FULL** — caller's handle table cannot accommodate the reply handle plus `pair_count` attached handles.

#### Tests

[test 01] returns E_BADCAP if [1] is not a valid port handle.
[test 02] returns E_PERM if [1] does not have the `recv` cap.
[test 03] returns E_INVAL if any reserved bits are set in [1].
[test 04] returns E_CLOSED if the port has no bind-cap holders, no event_routes targeting it, and no queued events.
[test 05] returns E_CLOSED when a recv is blocked on a port and the last bind-cap holder releases its handle while no event_routes target the port and no events are queued.
[test 06] returns E_FULL if the caller's handle table cannot accommodate the reply handle and pair_count attached handles.
[test 07] on success, the syscall word's reply_handle_id is the slot id of a reply handle inserted into the caller's table referencing the dequeued sender.
[test 08] on success, the syscall word's event_type equals the event_type that triggered delivery.
[test 09] on success when the sender attached N handles, the syscall word's pair_count = N and the next N table slots [tstart, tstart+N) contain the inserted handles per §[handle_attachments].
[test 10] on success when the sender attached no handles, pair_count = 0.
[test 11] on success when the suspending EC handle had the `read` cap, the receiver's vregs reflect the suspended EC's state per §[event_state] (or §[vm_exit_state] when event_type = vm_exit).
[test 12] on success when the suspending EC handle did not have the `read` cap, all event-state vregs are zeroed.
[test 13] when multiple senders are queued, the kernel selects the highest-priority sender; ties resolve FIFO.
[test 14] returns E_TIMEOUT if [2] timeout_ns is nonzero, no sender is queued, and no sender becomes queued within [2] timeout_ns.
[test 15] on success when [2] timeout_ns is nonzero and a sender is delivered before the deadline, the deadline is cancelled and no E_TIMEOUT is later observed.
[test 16] on success, until the reply handle is consumed, the dequeued sender remains suspended; deleting the reply handle resolves the sender with E_ABANDONED.

### §[event_type] Event Type

Event type identifies the kind of event an event route binds or that a reply originated from.

| Value | Name | Description |
|---|---|---|
| 0 | _reserved | |
| 1 | memory_fault | invalid read/write/execute, unmapped access, protection violation |
| 2 | thread_fault | arithmetic fault, illegal instruction, alignment check, stack overflow |
| 3 | breakpoint | software or hardware breakpoint trap |
| 4 | suspension | EC suspended via the `suspend` syscall (subsumes IDC call delivery; the receiver inspects/mutates the suspended EC's state per §[event_state] gated by the `read`/`write` caps on the EC handle the suspender used) |
| 5 | vm_exit | vCPU exited guest mode |
| 6 | pmu_overflow | performance counter overflowed |
| 7..31 | _reserved | |

Sub-codes within an event type (e.g., read vs write vs execute within memory_fault; arithmetic vs illegal_instruction vs alignment vs stack_overflow within thread_fault; the architecture-specific exit reason within vm_exit) are carried in the event payload rather than as separate event type values.

### §[event_state] Event State

When the EC handle that triggered the event held the `read` and/or `write` cap, the kernel exposes the suspended EC's state through the vreg layout at recv time and consumes modifications on reply. GPRs are 1:1 with hardware registers during handler execution — the handler reads or modifies EC state by directly reading or writing the hardware register. Non-GPR state lives on the stack at fixed offsets. The reply handle id is returned in the receiver's syscall word, not a vreg, so receivers handling small events do not need to allocate stack to reach a high vreg slot. VM exit events expose additional state — see §[vm_exit_state]. Handle attachments ride in pair vregs at the top of the vreg range — see §[handle_attachments].

The receiver's syscall word on recv return carries:

```
bits  0-11: _reserved
bits 12-19: pair_count           — count of handles attached by sender (0..63)
bits 20-31: tstart               — slot id of first attached handle (valid when pair_count > 0)
bits 32-43: reply_handle_id      — slot id of the inserted reply handle in the receiver's table
bits 44-48: event_type           — per §[event_type]
bits 49-55: payload_count        — count of GPR-backed vregs (1..payload_count) the sender delivered as event-state payload (0..127)
bits 56-63: _reserved
```

The receiver only sees vregs 1..payload_count as the valid event-state window; vregs payload_count+1..127 are undefined.

**x86-64**

| vreg | location | content |
|---|---|---|
| 1..13 | GPRs | EC's rax, rbx, rdx, rbp, rsi, rdi, r8, r9, r10, r12, r13, r14, r15 |
| 14 | `[rsp + 8]` | RIP |
| 15 | `[rsp + 16]` | RFLAGS |
| 16 | `[rsp + 24]` | RSP |
| 17 | `[rsp + 32]` | FS.base |
| 18 | `[rsp + 40]` | GS.base |
| 19..127 | `[rsp + ...]` | event-specific payload |

**aarch64**

| vreg | location | content |
|---|---|---|
| 1..31 | x0..x30 | EC's x0..x30 |
| 32 | `[sp + 8]` | PC |
| 33 | `[sp + 16]` | PSTATE |
| 34 | `[sp + 24]` | SP_EL0 |
| 35 | `[sp + 32]` | TPIDR_EL0 |
| 36..127 | `[sp + ...]` | event-specific payload |

FPU, SIMD, and other extended state (XSAVE area on x86-64, SVE/NEON state on aarch64) is not exposed through vregs and is accessed through a separate mechanism. When copied to a buffer, the state is laid out per-architecture:

- **x86-64**: XSAVE(C) format, as defined in Intel® 64 and IA-32 Architectures Software Developer's Manual Vol. 1, Chapter 13 ("Managing State Using the XSAVE Feature Set"). Layout and offsets of individual state components are enumerated at runtime via `CPUID.0xD`.
- **aarch64**: V0..V31 packed from offset 0 (16 bytes each, 512 bytes total), FPSR at offset 512, FPCR at offset 516. If SVE is enabled, SVE state (Z0..Z31, P0..P15, FFR) follows in the architecturally canonical layout as defined in Arm Architecture Reference Manual (DDI0487), §B1.

### §[handle_attachments] Handle Attachments

A suspending EC may attach handles to the event by encoding them as pair entries in the high vregs and writing the count into the syscall word.

The syscall word at suspend time carries `pair_count` `N` in bits 12-19 (0..255). When `N > 0`, the entries occupy vregs `[128-N..127]`. Each entry is a u64 packed as:

```
bits  0-11: source handle id (in the suspending EC's domain)
bits 12-15: _reserved
bits 16-31: caps to install on the handle in the receiver's domain
bit     32: move (1 = remove from sender's table; 0 = copy)
bits 33-63: _reserved
```

The kernel validates the entries at suspend time. The actual move/copy is performed at recv time — if the suspend resumes with `E_CLOSED` before any recv, no attachment is moved or copied and the sender's table is unchanged.

At recv time the kernel inserts the `N` handles into the receiving EC's table at contiguous slots `[S, S+N)` with `S` chosen by the kernel, and sets the receiver's syscall word with `pair_count = N`, `tstart = S`, `reply_handle_id` (slot id of the inserted reply handle), and `event_type` per the layout in §[event_state]. Each installed handle's caps are the entry's `caps` intersected with the receiver's `idc_rx` for IDC handles, or the entry's `caps` verbatim for other handle types.

[test 01] returns E_PERM if `N > 0` and the port handle does not have the `xfer` cap.
[test 02] returns E_BADCAP if any entry's source handle id is not valid in the suspending EC's domain.
[test 03] returns E_PERM if any entry's caps are not a subset of the source handle's current caps.
[test 04] returns E_PERM if any entry with `move = 1` references a source handle that lacks the `move` cap.
[test 05] returns E_PERM if any entry with `move = 0` references a source handle that lacks the `copy` cap.
[test 06] returns E_INVAL if any reserved bits are set in an entry.
[test 07] returns E_INVAL if two entries reference the same source handle.
[test 08] on recv, the receiver's syscall word `pair_count` equals `N` and the next `N` table slots `[tstart, tstart+N)` contain the inserted handles, each with caps = entry.caps intersected with `idc_rx` for IDC handles, or entry.caps verbatim for other handle types.
[test 09] on recv, source entries with `move = 1` are removed from the sender's table; entries with `move = 0` are not removed.
[test 10] when the suspend resumes with `E_CLOSED` before any recv, no entry is moved or copied.

### §[vm_exit_state] VM Exit State

VM exit events (`event_type` = `vm_exit`) extend §[event_state] to expose the full architectural guest state the handler needs to emulate trapped instructions and resume the vCPU. The exit sub-code identifies what caused the exit; the exit payload carries sub-code-specific data (faulting address, port number, MSR index, etc.).

**x86-64**

Exit sub-codes:

| Value | Name | Description |
|---|---|---|
| 0 | cpuid | guest executed CPUID |
| 1 | io | guest executed IN/OUT to a trapped port |
| 2 | mmio | guest memory access to a trapped MMIO region |
| 3 | cr | guest accessed a trapped control register |
| 4 | msr_r | guest executed RDMSR |
| 5 | msr_w | guest executed WRMSR |
| 6 | ept | EPT violation (unmapped guest physical access) |
| 7 | except | guest took an exception delivered to the host |
| 8 | intwin | interrupt window opened |
| 9 | hlt | guest executed HLT |
| 10 | shutdown | guest triggered shutdown |
| 11 | triple | guest triple-faulted |
| 12 | unknown | unknown or unhandled exit reason |
| 13 | initial_state | vCPU has not yet been entered; reply with this sub-code keeps the vCPU not-started and re-delivers an initial vm_exit (see §[reply]) |

vreg layout:

| vreg | location | content |
|---|---|---|
| 1..13 | GPRs | guest rax, rbx, rdx, rbp, rsi, rdi, r8, r9, r10, r12, r13, r14, r15 |
| 14 | `[rsp + 8]` | guest RIP |
| 15 | `[rsp + 16]` | guest RFLAGS |
| 16 | `[rsp + 24]` | guest RSP |
| 17 | `[rsp + 32]` | guest RCX |
| 18 | `[rsp + 40]` | guest R11 |
| 19 | `[rsp + 48]` | CR0 |
| 20 | `[rsp + 56]` | CR2 |
| 21 | `[rsp + 64]` | CR3 |
| 22 | `[rsp + 72]` | CR4 |
| 23 | `[rsp + 80]` | CR8 |
| 24 | `[rsp + 88]` | EFER |
| 25 | `[rsp + 96]` | APIC_BASE |
| 26..41 | `[rsp + 104..231]` | segment registers (cs, ds, es, fs, gs, ss, tr, ldtr); each occupies 2 vregs: base u64, then `{limit u32, selector u16, access_rights u16}` packed |
| 42..43 | `[rsp + 232..247]` | GDTR base, GDTR limit (u32) |
| 44..45 | `[rsp + 248..263]` | IDTR base, IDTR limit (u32) |
| 46..55 | `[rsp + 264..343]` | STAR, LSTAR, CSTAR, SFMASK, KERNEL_GS_BASE, SYSENTER_CS, SYSENTER_ESP, SYSENTER_EIP, PAT, TSC_AUX |
| 56..61 | `[rsp + 344..391]` | DR0, DR1, DR2, DR3, DR6, DR7 |
| 62..65 | `[rsp + 392..423]` | vcpu_events: exception state packed, exception payload, interrupt/nmi packed, sipi/smi/triple_fault packed |
| 66..69 | `[rsp + 424..455]` | interrupt_bitmap (256 bits = 4 u64s) |
| 70 | `[rsp + 456]` | exit sub-code |
| 71..73 | `[rsp + 464..487]` | exit payload (per sub-code below) |
| 74..127 | `[rsp + 488..919]` | _reserved |

Exit payload per sub-code (up to 3 vregs = 24 bytes; unused vregs in the payload band are `_reserved` for that sub-code):

| Sub-code | vreg[71] | vreg[72] | vreg[73] |
|---|---|---|---|
| cpuid | `{leaf u32, subleaf u32}` | _reserved | _reserved |
| io | next_rip | `{value u32, port u16, size u8, is_write u8}` | _reserved |
| mmio | guest_phys | value | `{size u8, is_write u8}` |
| cr | value | `{cr_num u4, is_write u1, gpr u4}` packed | _reserved |
| msr_r, msr_w | value | msr index (u32) | _reserved |
| ept | guest_phys | `{is_read u1, is_write u1, is_exec u1}` packed | _reserved |
| except | `{vector u8}` | error_code | _reserved |
| intwin, hlt, shutdown, triple | _reserved | _reserved | _reserved |
| unknown | raw exit reason | _reserved | _reserved |
| initial_state | _reserved | _reserved | _reserved |

**aarch64**

Exit sub-codes:

| Value | Name | Description |
|---|---|---|
| 0 | stage2_fault | stage-2 translation fault (unmapped guest physical access) |
| 1 | hvc | hypervisor call |
| 2 | smc | secure monitor call |
| 3 | sysreg | trapped system register access |
| 4 | wfi_wfe | guest executed WFI or WFE |
| 5 | unknown_ec | unrecognized exception class |
| 6 | sync_el1 | synchronous EL1 exception |
| 7 | halt | guest requested halt |
| 8 | shutdown | guest triggered shutdown |
| 9 | unknown | other unhandled exit |
| 10 | initial_state | vCPU has not yet been entered; reply with this sub-code keeps the vCPU not-started and re-delivers an initial vm_exit (see §[reply]) |

vreg layout:

| vreg | location | content |
|---|---|---|
| 1..31 | x0..x30 | guest x0..x30 |
| 32 | `[sp + 8]` | guest PC |
| 33 | `[sp + 16]` | PSTATE |
| 34 | `[sp + 24]` | SP_EL0 |
| 35 | `[sp + 32]` | SP_EL1 |
| 36..54 | `[sp + 40..183]` | SCTLR_EL1, TTBR0_EL1, TTBR1_EL1, TCR_EL1, MAIR_EL1, AMAIR_EL1, CPACR_EL1, CONTEXTIDR_EL1, TPIDR_EL0, TPIDR_EL1, TPIDRRO_EL0, VBAR_EL1, ELR_EL1, SPSR_EL1, ESR_EL1, FAR_EL1, AFSR0_EL1, AFSR1_EL1, MDSCR_EL1 |
| 55..57 | `[sp + 192..207]` | MIDR_EL1, MPIDR_EL1, REVIDR_EL1 |
| 58..73 | `[sp + 216..335]` | ID_AA64PFR0_EL1, ID_AA64PFR1_EL1, ID_AA64ZFR0_EL1, ID_AA64SMFR0_EL1, ID_AA64DFR0_EL1, ID_AA64DFR1_EL1, ID_AA64AFR0_EL1, ID_AA64AFR1_EL1, ID_AA64ISAR0_EL1, ID_AA64ISAR1_EL1, ID_AA64ISAR2_EL1, ID_AA64MMFR0_EL1, ID_AA64MMFR1_EL1, ID_AA64MMFR2_EL1, ID_AA64MMFR3_EL1, ID_AA64MMFR4_EL1 |
| 74..81 | `[sp + 344..399]` | CNTV_CVAL_EL0, CNTV_CTL_EL0, CNTV_TVAL_EL0, CNTP_CVAL_EL0, CNTP_CTL_EL0, CNTP_TVAL_EL0, CNTKCTL_EL1, CNTVOFF_EL2 |
| 82..101 | `[sp + 408..559]` | debug regs: DBGBVR0..5_EL1, DBGBCR0..5_EL1, DBGWVR0..3_EL1, DBGWCR0..3_EL1 |
| 102..115 | `[sp + 568..671]` | PMU regs: PMCR_EL0, PMCNTENSET_EL0, PMCNTENCLR_EL0, PMOVSR_EL0, PMOVSSET_EL0, PMSELR_EL0, PMCCNTR_EL0, PMXEVTYPER_EL0, PMXEVCNTR_EL0, PMCCFILTR_EL0, PMINTENSET_EL1, PMINTENCLR_EL1, PMUSERENR_EL0, PMEVCNTR (aggregate) |
| 116 | `[sp + 680]` | packed pending state `{virq u8, vfiq u8, vserror u8}` |
| 117 | `[sp + 688]` | exit sub-code |
| 118..120 | `[sp + 696..719]` | exit payload (per sub-code below) |
| 121..127 | `[sp + 720..775]` | _reserved |

Exit payload per sub-code (up to 3 vregs = 24 bytes; unused vregs in the payload band are `_reserved` for that sub-code):

| Sub-code | vreg[118] | vreg[119] | vreg[120] |
|---|---|---|---|
| stage2_fault | guest_phys | guest_virt | `{access_size u8, srt u8, fsc u8, flags u8}` (flags: instr, write, iss_valid, sign_extend, reg64, acqrel) |
| hvc | `{imm u16}` | _reserved | _reserved |
| smc | `{imm u16}` | _reserved | _reserved |
| sysreg | `{iss u32, op0 u2, op1 u3, crn u4, crm u4, op2 u3, rt u5, is_read u1}` packed | _reserved | _reserved |
| wfi_wfe | `{is_wfe u1}` | _reserved | _reserved |
| unknown_ec | raw EC value | _reserved | _reserved |
| sync_el1 | ESR_EL2 | _reserved | _reserved |
| halt, shutdown | _reserved | _reserved | _reserved |
| unknown | raw ESR_EL2 | _reserved | _reserved |
| initial_state | _reserved | _reserved | _reserved |

## §[event_route] Event Route

An event route is a kernel-held binding of events generated by an execution context to a given port, such that the execution context is suspended on the port when the event occurs. Event routes are not handles — they are identified by the `(execution_context, event_type)` tuple and cleared either by explicit syscall or by destruction of the execution context they are bound to.

The registerable event types (per §[event_type]) are `memory_fault` (1), `thread_fault` (2), `breakpoint` (3), and `pmu_overflow` (6). `suspension` (4) and `vm_exit` (5) are not registered through these syscalls — `suspension` is delivered to the port specified in the `suspend` syscall directly, and `vm_exit` is bound at `create_vcpu` to the vCPU's exit_port.

When an event of a registered type fires for an EC, the kernel suspends the EC and delivers an event of the corresponding type on the bound port per §[event_state]; the receiver may modify the EC's state and reply through the included reply capability to resume it.

When an event of a registerable type fires for an EC and no route is bound for `(EC, event_type)` — never bound, cleared, or the bound port lost its last `bind` holder — the kernel resolves the event per the no-route fallback:

| event_type | Fallback |
|---|---|
| memory_fault | the EC's capability domain is restarted if its self-handle has the `restart` cap (per §[restart_semantics]); otherwise the capability domain is destroyed |
| thread_fault | the EC is terminated |
| breakpoint | the event is dropped; the kernel advances past the trapping instruction and resumes the EC |
| pmu_overflow | the event is dropped; the EC continues running |

`suspension` and `vm_exit` always have a bound port by construction (the `suspend` syscall's `port` argument and the `create_vcpu` `exit_port` respectively), so the no-route fallback does not apply to them.

### bind_event_route

#### Summary

Installs the kernel-held binding `(target, event_type) → port`.

#### Declaration

```
bind_event_route([1] target, [2] event_type, [3] port) -> void
  syscall_num = 50

  [1] target:     EC handle
  [2] event_type: u64; must be a registerable event type (1, 2, 3, or 6)
  [3] port:       port handle
```

#### Description

If a binding already exists for `(target, event_type)`, it is replaced atomically — there is no window during which the route falls back to the no-route handling.

#### Capabilities

- EC handle `[1]`: `bind` if no prior route exists for `(target, event_type)`; `rebind` if one does.
- Port handle `[3]`: `bind`

#### Errors

**E_BADCAP** — `[1]` is not a valid EC handle; `[3]` is not a valid port handle.

**E_PERM** — `[3]` lacks `bind`; no prior route exists and `[1]` lacks `bind`; a prior route exists and `[1]` lacks `rebind`.

**E_INVAL** — `[2]` is not a registerable event type (i.e., not in {1, 2, 3, 6}); reserved bits set in `[1]`, `[2]`, or `[3]`.

#### Tests

[test 01] returns E_BADCAP if [1] is not a valid EC handle.
[test 02] returns E_BADCAP if [3] is not a valid port handle.
[test 03] returns E_INVAL if [2] is not a registerable event type (i.e., not in {1, 2, 3, 6}).
[test 04] returns E_INVAL if any reserved bits are set in [1], [2], or [3].
[test 05] returns E_PERM if [3] does not have the `bind` cap.
[test 06] returns E_PERM if no prior route exists for ([1], [2]) and [1] does not have the `bind` cap.
[test 07] returns E_PERM if a prior route exists for ([1], [2]) and [1] does not have the `rebind` cap.
[test 08] on success, when [2] subsequently fires for [1], the EC is suspended and an event of type [2] is delivered on [3] per §[event_state] with the reply handle id placed in the receiver's syscall word `reply_handle_id` field.
[test 09] on success when a prior route existed, the replacement is observable atomically: every subsequent firing of [2] for [1] is delivered to [3], and no firing in the interval is delivered to the prior port or to the no-route fallback.
[test 10] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

### clear_event_route

#### Summary

Removes the binding for `(target, event_type)`. Subsequent firings of that event type for the EC fall back to the no-route handling defined above.

#### Declaration

```
clear_event_route([1] target, [2] event_type) -> void
  syscall_num = 51

  [1] target:     EC handle
  [2] event_type: u64; must be a registerable event type
```

#### Capabilities

- EC handle `[1]`: `unbind`

#### Errors

**E_BADCAP** — `[1]` is not a valid EC handle.

**E_PERM** — `[1]` does not have the `unbind` cap.

**E_INVAL** — `[2]` is not a registerable event type; reserved bits set in `[1]` or `[2]`.

**E_NOENT** — no binding exists for `([1], [2])`.

#### Tests

[test 01] returns E_BADCAP if [1] is not a valid EC handle.
[test 02] returns E_PERM if [1] does not have the `unbind` cap.
[test 03] returns E_INVAL if [2] is not a registerable event type.
[test 04] returns E_INVAL if any reserved bits are set in [1] or [2].
[test 05] returns E_NOENT if no binding exists for ([1], [2]).
[test 06] on success, the binding for ([1], [2]) is removed; subsequent firings of [2] for [1] follow the no-route fallback above.
[test 07] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

## §[reply] Reply

A reply is a one-shot capability referencing a suspended execution context that has been dequeued from a port by a receive but has not yet been resumed. Holding a reply handle authorizes resuming or abandoning the suspended sender; consuming the handle (via `reply` or `delete`) is the only way to free the suspended sender.

Handle ABI:

```
word 0:
 63            48 47                          16 15   12 11         0
┌────────────────┬──────────────────────────────┬───────┬────────────┐
│   cap (16)     │       _reserved (32)         │type(4)│   id(12)   │
└────────────────┴──────────────────────────────┴───────┴────────────┘

word 1 (field0):
 63                                                                  0
┌─────────────────────────────────────────────────────────────────────┐
│                         _reserved (64)                              │
└─────────────────────────────────────────────────────────────────────┘

word 2 (field1):
 63                                                                  0
┌─────────────────────────────────────────────────────────────────────┐
│                         _reserved (64)                              │
└─────────────────────────────────────────────────────────────────────┘
```

cap (word 0, bits 48-63):

```
 15                                          2    1    0
┌─────────────────────────────────────────────┬────┬────┬────┐
│              _reserved (13)                 │xfer│copy│move│
└─────────────────────────────────────────────┴────┴────┴────┘
```

| Bit | Name | Meaning |
|---|---|---|
| 0 | `move` | transferring this reply handle via move to another capability domain |
| 1 | `copy` | always 0 — reply handles are one-shot and cannot be duplicated |
| 2 | `xfer` | attaching handles to the resumption via `reply` (when `pair_count > 0`) |
| 3-15 | `_reserved` | |

The kernel mints the reply handle at recv time with `move = 1`, `copy = 0`, and `xfer = 1` if and only if the recv'ing port had the `xfer` cap; otherwise `xfer = 0`. A holder may `restrict` away `move` or `xfer` to hand a more limited reply handle to another domain. `copy` cannot be set, so `restrict` cannot grant it.

### reply

#### Summary

Consumes a reply handle and resumes the suspended EC. Optionally attaches up to 63 handles to the resumption (when `pair_count > 0`) and/or atomically blocks the caller on a port for the next event (when `recv_port_handle_id != 0`).

#### Declaration

```
reply([128-N..127] pair_entries when pair_count > 0) -> void
  syscall_num = 52

  syscall word bits  0-11: syscall_num
  syscall word bits 12-19: pair_count (0..63)
  syscall word bits 20-31: reply_handle_id (12 bits)
  syscall word bits 32-43: recv_port_handle_id (12 bits; 0 = no recv-on-reply)
  syscall word bits 44-63: _reserved

  vregs [128-pair_count..127]: pair entries packed per §[handle_attachments]
```

#### Description

State modifications written to the receiver's event-state vregs (per §[event_state] / §[vm_exit_state]) between recv and reply are applied to the suspended EC's state on resume, gated by the `write` cap on the EC handle that originated the binding (the suspending EC handle for explicit suspend, the EC handle used at `bind_event_route` for fault events, the vCPU EC handle for vm_exit).

The reply handle id rides in the syscall word rather than vreg 1 so the GPR-backed event-state vregs (1..13 on x86-64; 1..31 on aarch64) survive intact across the reply syscall — receivers handling exits can keep modified guest GPRs in registers throughout the handler and on into the syscall, preserving the L4-style IPC fast path.

The reply handle is typed by the originating event_type at recv time. The kernel routes the reply on this type:

- For replies typed as `vm_exit`, the kernel reads the §[vm_exit_state] window from the receiver's user stack (vregs 14..N for that arch), projects it onto the vCPU's guest state gated by the `write` cap, and re-enters guest mode. As a special case, when the receiver writes the `initial_state` sub-code into the reply (vreg 70 on x86-64 / vreg 117 on aarch64), the kernel does NOT enter guest mode; instead it keeps the vCPU not-started and re-delivers an initial vm_exit on the bound exit_port. This is how a receiver acknowledges the initial vm_exit (§[create_vcpu]) without yet supplying real guest state.
- For all other reply types (`suspension`, `memory_fault`, `thread_fault`, `breakpoint`, `pmu_overflow`), the kernel applies receiver modifications to the GPR-backed event-state vregs only (vregs 1..13 on x86-64 / 1..31 on aarch64) gated by the `write` cap, and resumes the suspended EC at its pre-suspension instruction pointer. The §[vm_exit_state] window is not read.

The receiver knows the reply's type because the kernel returned the originating `event_type` in the receiver's syscall word at recv (§[event_state]); the kernel remembers the same type on the kernel-side reply handle so the routing is symmetric without a user-visible cap bit.

When `pair_count > 0`, the caller attaches `pair_count` pair entries packed in vregs `[128-pair_count..127]` per §[handle_attachments]. The resumed EC's syscall word carries `pair_count = N` and `tstart = S` (slot id of the first attached handle in the resumed EC's domain).

When `recv_port_handle_id != 0`, the caller atomically completes the reply and then parks on the named port for the next event, with no chance for another EC to interleave a syscall on the caller in between. On error before the caller would park (E_BADCAP / E_PERM on the recv arm), the caller does not park and the reply handle is unaffected. On `E_TERM` (suspended EC was terminated before reply could deliver), the reply handle is consumed but the caller still does NOT park.

#### Capabilities

The reply handle itself authorizes the operation; no self-handle cap is required.

- Reply handle: `xfer` (when `pair_count > 0`)
- Port handle named by `recv_port_handle_id` (when nonzero): `recv`

#### Errors

**E_BADCAP** — `reply_handle_id` is not a valid reply handle; `recv_port_handle_id != 0` and that slot does not name a valid port handle (reply handle NOT consumed; caller does not park).

**E_PERM** — `pair_count > 0` and the reply handle lacks `xfer`; any pair entry's caps not a subset of source's caps; pair entry with `move = 1` lacks the `move` cap; pair entry with `move = 0` lacks the `copy` cap; `recv_port_handle_id != 0` and the named port lacks `recv` (reply handle NOT consumed; caller does not park).

**E_INVAL** — reserved bits set in the syscall word; `pair_count > 63`; reserved bits set in any pair entry; two pair entries reference the same source.

**E_TERM** — suspended EC was terminated before reply could deliver; the reply handle is consumed; on `pair_count > 0` no handle transfer occurs; on `recv_port_handle_id != 0` the caller does NOT park.

**E_FULL** — `pair_count > 0` and the resumed EC's domain handle table cannot accommodate N contiguous slots (reply handle NOT consumed; caller's table unchanged).

#### Tests

[test 01] returns E_BADCAP if `reply_handle_id` is not a valid reply handle.
[test 02] returns E_INVAL if any reserved bits are set in the syscall word.
[test 03] returns E_TERM if the suspended EC was terminated before reply could deliver and `pair_count = 0`; the reply handle is consumed.
[test 04] on success when `pair_count = 0` and `recv_port_handle_id = 0`, the reply handle is consumed (removed from the caller's table).
[test 05] on success when the originating EC handle had the `write` cap, the resumed EC's state reflects modifications written to the receiver's event-state vregs between recv and reply.
[test 06] on success when the originating EC handle did not have the `write` cap, the resumed EC's state matches its pre-suspension state, ignoring any modifications made by the receiver.
[test 07] on success, the suspended EC is resumed.
[test 08] on success when the reply is typed `vm_exit` and the receiver wrote the `initial_state` sub-code into the reply (vreg 70 on x86-64, vreg 117 on aarch64), the kernel re-delivers an initial vm_exit on the vCPU's exit_port without entering guest mode; a subsequent `recv` on the exit_port returns a vm_exit whose sub-code is `initial_state`.
[test 09] returns E_PERM when `pair_count > 0` and the reply handle does not have the `xfer` cap.
[test 10] returns E_INVAL when `pair_count > 63`.
[test 11] returns E_INVAL if any reserved bits are set in any pair entry.
[test 12] returns E_BADCAP if any pair entry's source handle id is not valid in the caller's domain.
[test 13] returns E_PERM if any pair entry's caps are not a subset of the source handle's current caps.
[test 14] returns E_PERM if any pair entry with `move = 1` references a source handle that lacks the `move` cap.
[test 15] returns E_PERM if any pair entry with `move = 0` references a source handle that lacks the `copy` cap.
[test 16] returns E_INVAL if two pair entries reference the same source handle.
[test 17] returns E_TERM if the suspended EC was terminated before reply could deliver and `pair_count > 0`; the reply handle is consumed and no handle transfer occurs.
[test 18] returns E_FULL if `pair_count > 0` and the resumed EC's domain handle table cannot accommodate N contiguous slots; the reply handle is NOT consumed and the caller's table is unchanged.
[test 19] on success when `pair_count > 0`, the resumed EC's syscall word carries `pair_count = N` and `tstart = S`; the next N slots `[S, S+N)` in the resumed EC's domain contain the inserted handles per §[handle_attachments] (caps intersected with `idc_rx` for IDC handles, verbatim otherwise).
[test 20] on success when `pair_count > 0`, source pair entries with `move = 1` are removed from the caller's table; entries with `move = 0` are not removed.
[test 21] on success when `pair_count > 0` and the reply is typed `vm_exit` and the receiver wrote the `initial_state` sub-code (vreg 70 on x86-64, vreg 117 on aarch64), the kernel re-delivers an initial vm_exit on the vCPU's exit_port without entering guest mode; the N attached handles are still installed in the vCPU's domain at slots `[tstart, tstart+N)` per the standard pair-attachment rules.
[test 22] returns E_BADCAP when `recv_port_handle_id != 0` and that slot does not name a valid port handle in the caller's domain; the reply handle is NOT consumed and the caller does not park.
[test 23] returns E_PERM when `recv_port_handle_id != 0` and the named port handle does not have the `recv` cap; the reply handle is NOT consumed and the caller does not park.
[test 24] on success when `recv_port_handle_id != 0`, after the suspended EC is resumed the caller is parked on the named port and a subsequent event delivered on that port wakes the caller with the standard recv return.
[test 25] returns E_TERM when `recv_port_handle_id != 0` and the suspended EC was terminated before reply could deliver; the reply handle is consumed and the caller does NOT park on the recv port.
[test 26] on success when both `pair_count > 0` and `recv_port_handle_id != 0`, both effects are applied atomically: the resumed EC receives the attached handles, then the caller parks on the named port.

## §[timer] Timer

A timer is a kernel object that fires either once or periodically and exposes a u64 counter directly in its handle's `field0`. Userspace observes fires by polling the counter or waiting on it via `futex_wait_val`. Timers are independent of any specific EC: a timer handle can be copied, moved, or transferred over IDC, and any holder may wait on the counter (only holders with the `arm`/`cancel` caps may reconfigure or stop it).

The handle table is mapped read-only into the holding domain, so `field0`'s vaddr (computable from the handle id and table base) is a valid futex address. The kernel propagates each fire to every domain-local copy of the handle, but propagation is not atomic across copies — different copies may transiently observe different counter values.

The kernel reserves `u64::MAX` as the cancellation sentinel; fire-driven increments saturate at `u64::MAX − 1`, so a real counter value is never confused with cancellation.

Handle ABI:

```
word 0:
 63            48 47                          16 15   12 11         0
┌────────────────┬──────────────────────────────┬───────┬────────────┐
│   cap (16)     │       _reserved (32)         │type(4)│   id(12)   │
└────────────────┴──────────────────────────────┴───────┴────────────┘

word 1 (field0):
 63                                                                  0
┌─────────────────────────────────────────────────────────────────────┐
│                       counter (64)                                  │
└─────────────────────────────────────────────────────────────────────┘

word 2 (field1):
 63                                              2 1   0
┌─────────────────────────────────────────────────┬─────┬───┐
│              _reserved (62)                     │ pd  │arm│
└─────────────────────────────────────────────────┴─────┴───┘
```

Field layout:

| field | location | meaning |
|---|---|---|
| counter | field0 bits 0-63 | u64 incremented on each fire (saturating at u64::MAX − 1); set to u64::MAX by `timer_cancel`; reset to 0 by `timer_rearm`. Kernel-mutable; eagerly propagated to every domain-local copy of the handle, but not atomically across copies |
| arm | field1 bit 0 | armed (1) / not armed (0); kernel-mutable, sync-refreshed |
| pd | field1 bit 1 | periodic (1) / one-shot (0); kernel-mutable, sync-refreshed |

cap (word 0, bits 48-63):

```
 15                       5    4    3    2    1    0
┌─────────────────────────┬──────┬────┬────┬────┬────┬────┐
│    _reserved (11)       │rstrt │canc│ arm│copy│move│
│                         │_plcy │    │    │    │    │
└─────────────────────────┴──────┴────┴────┴────┴────┴────┘
```

| Bit | Name | Meaning |
|---|---|---|
| 0 | `move` | transferring this handle via move to another capability domain |
| 1 | `copy` | transferring this handle via copy to another capability domain |
| 2 | `arm` | reconfiguring the timer via `timer_rearm` |
| 3 | `cancel` | cancelling the timer via `timer_cancel` |
| 4 | `restart_policy` | timer behavior on domain restart: 0=drop, 1=keep (see §[restart_semantics]) |

### timer_arm

#### Summary

Mints a new timer handle with its own counter and arms it. Each call yields an independent timer; previously-minted timers are unaffected.

#### Declaration

```
timer_arm([1] caps, [2] deadline_ns, [3] flags) -> [1] handle
  syscall_num = 54

  [1] caps: u64 packed as
    bits  0-15: caps     — caps on the returned timer handle
    bits 16-63: _reserved

  [2] deadline_ns: nanoseconds until first fire (and period if periodic)

  [3] flags: u64 packed as
    bit 0:     periodic
    bits 1-63: _reserved
```

#### Description

On each fire, the kernel atomically increments `field0` of every domain-local copy of the handle (saturating at `u64::MAX − 1`) and issues a futex wake on each copy's `field0` paddr. One-shot timers transition `field1.arm` to 0 after the single fire; periodic timers stay armed until `timer_cancel`.

#### Capabilities

- Self-handle: `timer`
- `[1].caps.restart_policy` ≤ caller's `restart_policy_ceiling.tm_restart_max`

#### Return value

`[1]`: timer handle with caps = `[1].caps`. field0 = 0; field1.arm = 1; field1.pd = `[3].periodic`.

#### Errors

**E_PERM** — self-handle lacks `timer`; `caps.restart_policy = 1` and `restart_policy_ceiling.tm_restart_max = 0`.

**E_INVAL** — `[2] deadline_ns = 0`; reserved bits set in `[1]` or `[3]`.

**E_NOMEM** — insufficient kernel memory.

**E_FULL** — caller's handle table has no free slot.

#### Tests

[test 01] returns E_PERM if the caller's self-handle lacks `timer`.
[test 02] returns E_PERM if [1].caps.restart_policy = 1 and the caller's `restart_policy_ceiling.tm_restart_max = 0`.
[test 03] returns E_INVAL if [2] deadline_ns is 0.
[test 04] returns E_INVAL if any reserved bits are set in [1] or [3].
[test 05] on success, the caller receives a timer handle with caps = [1].caps.
[test 06] on success, [1].field0 = 0, [1].field1.arm = 1, and [1].field1.pd = [3].periodic.
[test 07] on success with [3].periodic = 0, [1].field0 is incremented by 1 once after [2] deadline_ns; [1].field1.arm becomes 0 after the fire.
[test 08] on success with [3].periodic = 1, [1].field0 is incremented by 1 every [2] deadline_ns until `timer_cancel` or `timer_rearm`; [1].field1.arm remains 1.
[test 09] on each fire, every EC blocked in futex_wait_val keyed on the paddr of any domain-local copy of [1].field0 returns from the call with [1] = the corresponding domain-local vaddr of field0.
[test 10] calling `timer_arm` again yields a fresh, independent timer handle; the prior handle's field0 and field1 are unaffected.

### timer_rearm

#### Summary

Reconfigures an existing timer. Resets `field0` to 0, sets `field1.arm = 1`, sets `field1.pd = [3].periodic`, and applies the new `deadline_ns`. Works regardless of whether the timer was armed or disarmed at call time.

#### Declaration

```
timer_rearm([1] timer, [2] deadline_ns, [3] flags) -> void
  syscall_num = 55

  [1] timer: timer handle
  [2] deadline_ns: nanoseconds until first fire (and period if periodic)
  [3] flags: u64 packed as
    bit 0:     periodic
    bits 1-63: _reserved
```

#### Capabilities

- Timer handle `[1]`: `arm`

#### Errors

**E_BADCAP** — `[1]` is not a valid timer handle.

**E_PERM** — `[1]` does not have the `arm` cap.

**E_INVAL** — `[2] deadline_ns = 0`; reserved bits set in `[1]` or `[3]`.

#### Tests

[test 01] returns E_BADCAP if [1] is not a valid timer handle.
[test 02] returns E_PERM if [1] does not have the `arm` cap.
[test 03] returns E_INVAL if [2] deadline_ns is 0.
[test 04] returns E_INVAL if any reserved bits are set in [1] or [3].
[test 05] on success, the calling domain's copy of [1] has `field0 = 0` immediately on return; every other domain-local copy returns 0 from a fresh `sync` within a bounded delay.
[test 06] on success, [1].field1.arm = 1 and [1].field1.pd = [3].periodic.
[test 07] on success with [3].periodic = 0, [1].field0 is incremented by 1 once after [2] deadline_ns and `[1].field1.arm` becomes 0; with [3].periodic = 1, [1].field0 is incremented by 1 every [2] deadline_ns until `timer_cancel` or another `timer_rearm`.
[test 08] on success, every EC blocked in futex_wait_val keyed on the paddr of any domain-local copy of [1].field0 returns from the call with [1] = the corresponding domain-local vaddr of field0.
[test 09] `timer_rearm` called on a currently-armed timer replaces the prior configuration; the prior pending fire does not occur and field0 reflects the reset to 0 rather than any partial fire.
[test 10] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

### timer_cancel

#### Summary

Disarms a timer. Sets `field0` to `u64::MAX` (the cancellation sentinel), sets `field1.arm = 0`, and wakes futex waiters.

#### Declaration

```
timer_cancel([1] timer) -> void
  syscall_num = 56

  [1] timer: timer handle
```

#### Description

Returns an error if the timer is not currently armed (e.g., a one-shot that already fired, or one already cancelled).

#### Capabilities

- Timer handle `[1]`: `cancel`

#### Errors

**E_BADCAP** — `[1]` is not a valid timer handle.

**E_PERM** — `[1]` does not have the `cancel` cap.

**E_INVAL** — `[1].field1.arm = 0`; reserved bits set in `[1]`.

#### Tests

[test 01] returns E_BADCAP if [1] is not a valid timer handle.
[test 02] returns E_PERM if [1] does not have the `cancel` cap.
[test 03] returns E_INVAL if [1].field1.arm = 0.
[test 04] returns E_INVAL if any reserved bits are set in [1].
[test 05] on success, the calling domain's copy of [1] has `field0 = u64::MAX` immediately on return; every other domain-local copy returns u64::MAX from a fresh `sync` within a bounded delay.
[test 06] on success, [1].field1.arm becomes 0.
[test 07] on success, every EC blocked in futex_wait_val keyed on the paddr of any domain-local copy of [1].field0 returns from the call with [1] = the corresponding domain-local vaddr of field0; subsequent reads observe field0 = u64::MAX.
[test 08] on success, after one full prior `deadline_ns` has elapsed, every domain-local copy of [1] still returns `field0 = u64::MAX` from a fresh `sync`.
[test 09] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

## §[futex] Futex

A futex is a user-side synchronization primitive: a thread atomically checks one or more user memory locations against a comparison and sleeps until the condition is met or another thread wakes it. The kernel keys waits by physical address, so two capability domains sharing a page_frame can synchronize through their respective virtual addresses to the same word.

Two wait primitives with opposite comparison directions:
- `futex_wait_val` — "I think these addresses currently hold these expected values; wake me when any of them differs."
- `futex_wait_change` — "I want to be woken when any of these addresses becomes its target value."

Both block until any of the per-pair conditions is met, until any thread calls `futex_wake` on one of the watched addresses, or until the timeout expires. Wake order is priority-ordered (highest first; FIFO within a priority).

### futex_wait_val

#### Summary

Blocks while every `(addr, expected)` pair satisfies `*addr == expected`. Returns when any pair has `*addr != expected` (either at call entry or after a wake), when any watched address is woken via `futex_wake`, or on timeout.

#### Declaration

```
futex_wait_val([1] timeout_ns, [2 + 2i] addr, [2 + 2i + 1] expected) -> [1] addr
  syscall_num = 57

  syscall word bits 12-19: N (1..63)

  [1] timeout_ns: 0 = non-blocking, u64::MAX = indefinite, otherwise nanoseconds
  [2 + 2i] addr: 8-byte-aligned user address in the caller's domain
  [2 + 2i + 1] expected: u64 expected value at addr

  for i in 0..N-1.
```

#### Capabilities

- Self-handle: `fut_wait_max >= 1`; the call's `N` must not exceed `fut_wait_max`.

#### Return value

`[1]`: address that triggered the wake (the addr whose pair's condition flipped, or that was passed to `futex_wake`).

#### Errors

**E_PERM** — caller's self-handle has `fut_wait_max = 0`.

**E_INVAL** — N is 0 or > 63; N exceeds caller's self-handle `fut_wait_max`; any addr not 8-byte aligned.

**E_BADADDR** — any addr is not a valid user address in the caller's domain.

**E_TIMEOUT** — timeout expired before any pair's `addr != expected` condition was met and before any watched address was woken.

#### Tests

[test 01] returns E_PERM if the caller's self-handle has `fut_wait_max = 0`.
[test 02] returns E_INVAL if N is 0 or N > 63.
[test 03] returns E_INVAL if N exceeds the caller's self-handle `fut_wait_max`.
[test 04] returns E_INVAL if any addr is not 8-byte aligned.
[test 05] returns E_BADADDR if any addr is not a valid user address in the caller's domain.
[test 06] returns E_TIMEOUT if the timeout expires before any pair's `addr != expected` condition is met and before any watched address is woken.
[test 07] on entry, when any pair's current `*addr != expected`, returns immediately with `[1]` set to that addr.
[test 08] when another EC calls `futex_wake` on any watched addr, returns with `[1]` set to that addr (caller re-checks the value to determine whether the condition is actually met or the wake was spurious).

### futex_wait_change

#### Summary

Blocks while every `(addr, target)` pair satisfies `*addr != target`. Returns when any pair has `*addr == target` (at call entry or after a wake), when any watched address is woken via `futex_wake`, or on timeout.

#### Declaration

```
futex_wait_change([1] timeout_ns, [2 + 2i] addr, [2 + 2i + 1] target) -> [1] addr
  syscall_num = 58

  syscall word bits 12-19: N (1..63)

  [1] timeout_ns: 0 = non-blocking, u64::MAX = indefinite, otherwise nanoseconds
  [2 + 2i] addr: 8-byte-aligned user address in the caller's domain
  [2 + 2i + 1] target: u64 target value at addr

  for i in 0..N-1.
```

#### Capabilities

- Self-handle: `fut_wait_max >= 1`; the call's `N` must not exceed `fut_wait_max`.

#### Return value

`[1]`: address that triggered the wake.

#### Errors

**E_PERM** — caller's self-handle has `fut_wait_max = 0`.

**E_INVAL** — N is 0 or > 63; N exceeds caller's self-handle `fut_wait_max`; any addr not 8-byte aligned.

**E_BADADDR** — any addr is not a valid user address in the caller's domain.

**E_TIMEOUT** — timeout expired before any pair's `addr == target` condition was met and before any watched address was woken.

#### Tests

[test 01] returns E_PERM if the caller's self-handle has `fut_wait_max = 0`.
[test 02] returns E_INVAL if N is 0 or N > 63.
[test 03] returns E_INVAL if N exceeds the caller's self-handle `fut_wait_max`.
[test 04] returns E_INVAL if any addr is not 8-byte aligned.
[test 05] returns E_BADADDR if any addr is not a valid user address in the caller's domain.
[test 06] returns E_TIMEOUT if the timeout expires before any pair's `addr == target` condition is met and before any watched address is woken.
[test 07] on entry, when any pair's current `*addr == target`, returns immediately with `[1]` set to that addr.
[test 08] when another EC calls `futex_wake` on any watched addr, returns with `[1]` set to that addr (caller re-checks the value to determine whether the condition is actually met or the wake was spurious).

### futex_wake

#### Summary

Wakes up to `count` ECs blocked in `futex_wait_val` or `futex_wait_change` on the given address. Wake order is priority-ordered.

#### Declaration

```
futex_wake([1] addr, [2] count) -> [1] woken
  syscall_num = 59

  [1] addr: 8-byte-aligned user address in the caller's domain
  [2] count: maximum number of ECs to wake
```

#### Capabilities

- Self-handle: `fut_wake`

#### Return value

`[1]`: number of ECs actually woken (0..count).

#### Errors

**E_PERM** — caller's self-handle lacks `fut_wake`.

**E_INVAL** — `[1]` addr is not 8-byte aligned.

**E_BADADDR** — `[1]` addr is not a valid user address in the caller's domain.

#### Tests

[test 01] returns E_PERM if the caller's self-handle lacks `fut_wake`.
[test 02] returns E_INVAL if [1] addr is not 8-byte aligned.
[test 03] returns E_BADADDR if [1] addr is not a valid user address in the caller's domain.
[test 04] on success, [1] is the number of ECs actually woken (0..count).

## §[system_services] System Services

### §[time] Time

#### time_monotonic

**Summary** — Returns nanoseconds since boot.

**Declaration**

```
time_monotonic() -> [1] ns
  syscall_num = 60
```

**Capabilities** — None.

**Return value** — `[1]`: u64 nanoseconds since boot.

**Tests**

[test 01] on success, [1] is a u64 nanosecond count strictly greater than the value returned by any prior call to `time_monotonic`.

#### time_getwall

**Summary** — Returns wall-clock time as nanoseconds since the Unix epoch.

**Declaration**

```
time_getwall() -> [1] ns_since_epoch
  syscall_num = 61
```

**Capabilities** — None.

**Return value** — `[1]`: nanoseconds since the Unix epoch.

**Tests**

[test 02] after `time_setwall(X)` succeeds, a subsequent `time_getwall` returns a value within a small bounded delta of X.

#### time_setwall

**Summary** — Sets the wall-clock time to the given nanoseconds-since-epoch.

**Declaration**

```
time_setwall([1] ns_since_epoch) -> void
  syscall_num = 62

  [1] ns_since_epoch: new wall-clock value (nanoseconds since Unix epoch)
```

**Capabilities** — Self-handle: `setwall`.

**Errors**

**E_PERM** — caller's self-handle lacks `setwall`.

**E_INVAL** — reserved bits set in `[1]`.

**Tests**

[test 03] returns E_PERM if the caller's self-handle lacks `setwall`.
[test 04] returns E_INVAL if any reserved bits are set in [1].
[test 05] on success, a subsequent `time_getwall` returns a value within a small bounded delta of [1].

### §[rng] RNG

#### random

**Summary** — Fills the requested number of vregs with cryptographically random qwords.

**Declaration**

```
random() -> [1..count] qwords
  syscall_num = 63

  syscall word bits 12-19: count (1..127)
```

**Capabilities** — None.

**Return value** — `[1..count]`: cryptographically-random u64 qwords.

**Errors**

**E_INVAL** — count is 0 or > 127.

**Tests**

[test 01] returns E_INVAL if count is 0 or count > 127.
[test 02] on success, vregs `[1..count]` contain qwords (the CSPRNG-source guarantee in the prose above is a kernel implementation contract, not a black-box-testable assertion).

### §[system_info] System Info

#### info_system

**Summary** — Returns system-wide capacity and capability information.

**Declaration**

```
info_system() -> [1] cores, [2] features, [3] total_phys_pages, [4] page_size_mask
  syscall_num = 64
```

**Capabilities** — None.

**Return value**

- `[1]` cores: total online CPU core count
- `[2]` features: bitmask
  - bit 0: hardware virtualization (Intel VMX or AMD SVM)
  - bit 1: IOMMU
  - bit 2: PMU
  - bit 3: wide vector ISA (AVX-512 on x86-64, SVE on aarch64)
  - bits 4-63: _reserved
- `[3]` total_phys_pages: total physical memory expressed in 4 KiB pages
- `[4]` page_size_mask: which physical page sizes the kernel can allocate
  - bit 0: 4 KiB
  - bit 1: 2 MiB
  - bit 2: 1 GiB
  - bits 3-63: _reserved

**Tests**

[test 01] on success, [1] equals the number of online CPU cores reported by the platform.
[test 02] on success, [3] equals the platform's total RAM divided by 4 KiB.
[test 03] on success, [4] bit 0 is set on every supported architecture.

#### info_cores

**Summary** — Returns information about a specific core.

**Declaration**

```
info_cores([1] core_id) -> [1] flags, [2] freq_hz, [3] vendor_model
  syscall_num = 65

  [1] on input: core id
```

**Capabilities** — None.

**Return value**

- `[1]` flags: bitmask
  - bit 0: online
  - bit 1: idle states supported
  - bit 2: frequency scaling supported
  - bits 3-63: _reserved
- `[2]` freq_hz: current frequency in Hz, 0 if unreadable
- `[3]` vendor_model: platform-defined packed identifier; layout follows the architecture vendor's encoding (e.g., x86 family/model/stepping, ARM IDR fields)

**Errors**

**E_INVAL** — `[1] core_id ≥ info_system().cores`; reserved bits set in `[1]`.

**Tests**

[test 04] returns E_INVAL if [1] core_id is greater than or equal to `info_system`'s `cores`.
[test 05] returns E_INVAL if any reserved bits are set in [1].
[test 06] on success, [1] flag bit 0 reflects whether the queried core is currently online.

### §[power] Power Management

All `power_*` syscalls require `power` on the caller's self-handle.

#### power_shutdown

**Summary** — Performs an immediate orderly system poweroff. Does not return on success.

**Declaration**

```
power_shutdown() -> void
  syscall_num = 66
```

**Capabilities** — Self-handle: `power`.

**Errors**

**E_PERM** — caller's self-handle lacks `power`.

**Tests**

[test 01] returns E_PERM if the caller's self-handle lacks `power`.

#### power_reboot

**Summary** — Performs a warm system reboot. Does not return on success.

**Declaration**

```
power_reboot() -> void
  syscall_num = 67
```

**Capabilities** — Self-handle: `power`.

**Errors**

**E_PERM** — caller's self-handle lacks `power`.

**Tests**

[test 02] returns E_PERM if the caller's self-handle lacks `power`.

#### power_sleep

**Summary** — Enters a system-wide low-power state at the requested depth. Returns when the system wakes.

**Declaration**

```
power_sleep([1] depth) -> void
  syscall_num = 68

  [1] depth: 1 = sleep (S1/S3-equivalent), 3 = deep sleep (S4-equivalent), 4 = hibernate (S5-equivalent)
```

**Capabilities** — Self-handle: `power`.

**Errors**

**E_PERM** — caller's self-handle lacks `power`.

**E_INVAL** — `[1]` is not 1, 3, or 4.

**E_NODEV** — platform does not support the requested sleep depth.

**Tests**

[test 03] returns E_PERM if the caller's self-handle lacks `power`.
[test 04] returns E_INVAL if [1] is not 1, 3, or 4.
[test 05] returns E_NODEV if the platform does not support the requested sleep depth.

#### power_screen_off

**Summary** — Turns the primary display off. Subsequent input wakes it.

**Declaration**

```
power_screen_off() -> void
  syscall_num = 69
```

**Capabilities** — Self-handle: `power`.

**Errors**

**E_PERM** — caller's self-handle lacks `power`.

**Tests**

[test 06] returns E_PERM if the caller's self-handle lacks `power`.

#### power_set_freq

**Summary** — Sets the target frequency for a specific core in Hz.

**Declaration**

```
power_set_freq([1] core_id, [2] hz) -> void
  syscall_num = 70

  [1] core_id: target core
  [2] hz: target frequency in Hz; 0 = let the kernel pick
```

**Capabilities** — Self-handle: `power`.

**Errors**

**E_PERM** — caller's self-handle lacks `power`.

**E_INVAL** — `[1] ≥ info_system().cores`; `[2]` is nonzero and outside the platform's supported frequency range.

**E_NODEV** — the queried core does not support frequency scaling (per `info_cores` flag bit 2).

**Tests**

[test 07] returns E_PERM if the caller's self-handle lacks `power`.
[test 08] returns E_INVAL if [1] is greater than or equal to `info_system`'s `cores`.
[test 09] returns E_NODEV if the queried core does not support frequency scaling (per `info_cores` flag bit 2).
[test 10] returns E_INVAL if [2] is nonzero and outside the platform's supported frequency range.
[test 11] on success, a subsequent `info_cores([1])` reports a `freq_hz` consistent with the requested target (within hardware tolerance).

#### power_set_idle

**Summary** — Sets the idle policy for a specific core.

**Declaration**

```
power_set_idle([1] core_id, [2] policy) -> void
  syscall_num = 71

  [1] core_id: target core
  [2] policy: 0 = busy-poll (no idle entry), 1 = halt only (shallow), 2 = deepest available c-state
```

**Capabilities** — Self-handle: `power`.

**Errors**

**E_PERM** — caller's self-handle lacks `power`.

**E_INVAL** — `[1] ≥ info_system().cores`; `[2]` is greater than 2.

**E_NODEV** — the queried core does not support idle states (per `info_cores` flag bit 1).

**Tests**

[test 12] returns E_PERM if the caller's self-handle lacks `power`.
[test 13] returns E_INVAL if [1] is greater than or equal to `info_system`'s `cores`.
[test 14] returns E_NODEV if the queried core does not support idle states (per `info_cores` flag bit 1).
[test 15] returns E_INVAL if [2] is greater than 2.
