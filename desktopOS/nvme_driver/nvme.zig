// NVMe controller — hardware logic ported from desktopOS commit
// 1f0b273ec, adapted to the spec-v3 vreg ABI.
//
// Major differences vs the pre-v3 driver:
//   - vm_reserve / mmio_map / shm_create / shm_map / dma_map →
//     createVmar / mapMmio / createPageFrame / mapPf, with caps.dma=1
//     baking the IOMMU mapping in atomically with createVmar.
//   - On a DMA-capable VMAR the kernel hands back a base address that
//     is BOTH the userspace VA and the device-visible IOVA, so
//     dma_virt == dma_phys (the IOMMU translates to the host PA where
//     the page_frame lives).
//   - clock_gettime → time_monotonic syscall (returns ns in v1).
//   - thread_yield → yieldEc.
//
// All NVMe spec references match the original — register layout,
// queue offsets, command opcodes, identify field offsets, doorbell
// stride math, completion phase tag handling, etc. unchanged.

const lib = @import("lib");
const log = @import("log");

const caps = lib.caps;
const syscall = lib.syscall;

const HandleId = caps.HandleId;

// ── NVMe Controller Register Offsets (Spec Section 3.1.3, Figure 33) ──
const REG_CAP: u32 = 0x00;
const REG_VS: u32 = 0x08;
const REG_CC: u32 = 0x14;
const REG_CSTS: u32 = 0x1C;
const REG_AQA: u32 = 0x24;
const REG_ASQ: u32 = 0x28;
const REG_ACQ: u32 = 0x30;

// ── Queue sizes ───────────────────────────────────────────────────
const ADMIN_QUEUE_SIZE: u16 = 64;
const IO_QUEUE_SIZE: u16 = 64;
const SQE_SIZE: u32 = 64; // Spec Section 4.1
const CQE_SIZE: u32 = 16; // Spec Section 4.2

// ── DMA region layout (page-aligned per Spec 3.1.3.6/7) ──────────
const DMA_ADMIN_SQ: u64 = 0x0000;
const DMA_ADMIN_CQ: u64 = 0x1000;
const DMA_IO_SQ: u64 = 0x2000;
const DMA_IO_CQ: u64 = 0x3000;
const DMA_IDENTIFY: u64 = 0x4000;
const DMA_DATA: u64 = 0x5000; // Read buffer (4 KiB)
const DMA_WRITE: u64 = 0x6000; // Write buffer (4 KiB)
const DMA_TOTAL: u64 = 0x7000;
const DMA_PAGES: u64 = DMA_TOTAL / 4096;

// ── Admin Command Opcodes (Spec Section 5, Figure 89) ─────────────
const ADMIN_OPC_CREATE_IO_SQ: u8 = 0x01;
const ADMIN_OPC_CREATE_IO_CQ: u8 = 0x05;
const ADMIN_OPC_IDENTIFY: u8 = 0x06;
const ADMIN_OPC_SET_FEATURES: u8 = 0x09;

// ── NVM I/O Command Opcodes (NVM Command Set Spec) ────────────────
const IO_OPC_WRITE: u8 = 0x01;
const IO_OPC_READ: u8 = 0x02;

// ── Submission Queue Entry (Spec Section 4.1.1, Figure 92) ────────
const SubmissionQueueEntry = extern struct {
    cdw0: u32 = 0,
    nsid: u32 = 0,
    cdw2: u32 = 0,
    cdw3: u32 = 0,
    mptr_lo: u32 = 0,
    mptr_hi: u32 = 0,
    prp1_lo: u32 = 0,
    prp1_hi: u32 = 0,
    prp2_lo: u32 = 0,
    prp2_hi: u32 = 0,
    cdw10: u32 = 0,
    cdw11: u32 = 0,
    cdw12: u32 = 0,
    cdw13: u32 = 0,
    cdw14: u32 = 0,
    cdw15: u32 = 0,
};

// ── Completion Queue Entry (Spec Section 4.2.1, Figure 96) ────────
const CompletionQueueEntry = extern struct {
    dw0: u32,
    dw1: u32,
    dw2: u32,
    dw3: u32,
};

pub const InitError = enum {
    none,
    mmio_vmar_create,
    mmio_map,
    dma_pf_create,
    dma_vmar_create,
    dma_map,
    controller_init,
};

pub const Controller = struct {
    mmio_base: u64 = 0,
    dma_virt: u64 = 0,
    dma_phys: u64 = 0,
    db_stride: u32 = 0,
    max_queue_entries: u16 = 0,
    admin_sq_tail: u16 = 0,
    admin_cq_head: u16 = 0,
    admin_cq_phase: u1 = 1,
    io_sq_tail: u16 = 0,
    io_cq_head: u16 = 0,
    io_cq_phase: u1 = 1,
    next_cid: u16 = 0,
    nn: u32 = 0,
    ns_size: u64 = 0,
    lba_size: u32 = 0,

    /// Map BAR0 as MMIO + allocate DMA-capable VMAR + run controller init.
    pub fn initFromHandle(self: *Controller, device_handle: HandleId, mmio_size: u64) InitError {
        const mmio_pages = (mmio_size + 4095) / 4096;
        const mmio_var_caps = caps.VmarCap{
            .r = true,
            .w = true,
            .mmio = true,
        };
        const mmio_props: u64 = (1 << 5) | // cch=1 (uc)
            (0 << 3) | // sz=0 (4 KiB)
            0b011; // cur_rwx=r|w
        const mmio_cvar = syscall.createVmar(
            @as(u64, mmio_var_caps.toU16()),
            mmio_props,
            mmio_pages,
            0,
            0,
        );
        if (mmio_cvar.v1 < 16) {
            log.print("nvme: createVmar(mmio) err=");
            log.dec(mmio_cvar.v1);
            log.print("\n");
            return .mmio_vmar_create;
        }
        const mmio_vmar_handle: HandleId = @truncate(mmio_cvar.v1 & 0xFFF);
        self.mmio_base = mmio_cvar.v2;
        log.print("nvme: mmio vmar base=0x");
        log.hex64(self.mmio_base);
        log.print("\n");

        const mm = syscall.mapMmio(mmio_vmar_handle, device_handle);
        if (mm.v1 != 0) {
            log.print("nvme: mapMmio err=");
            log.dec(mm.v1);
            log.print("\n");
            return .mmio_map;
        }
        log.print("nvme: mapMmio ok, reading CAP\n");

        // ── Allocate DMA-capable VMAR bound to this device ──────────
        // caps.dma=1 + [5] device_region binds the IOMMU mapping
        // atomically. dma_virt and dma_phys end up identical.
        const dma_pf_caps = caps.PfCap{
            .move = false,
            .r = true,
            .w = true,
        };
        const dma_pf = syscall.createPageFrame(
            @as(u64, dma_pf_caps.toU16()),
            0,
            DMA_PAGES,
        );
        if (dma_pf.v1 < 16) {
            log.print("nvme: createPageFrame(dma) err=");
            log.dec(dma_pf.v1);
            log.print("\n");
            return .dma_pf_create;
        }
        const dma_pf_handle: HandleId = @truncate(dma_pf.v1 & 0xFFF);

        const dma_var_caps = caps.VmarCap{
            .r = true,
            .w = true,
            .dma = true,
        };
        const dma_props: u64 = (0 << 5) | // cch=0 (wb)
            (0 << 3) | // sz=0 (4 KiB)
            0b011; // cur_rwx=r|w
        const dma_cvar = syscall.createVmar(
            @as(u64, dma_var_caps.toU16()),
            dma_props,
            DMA_PAGES,
            0,
            device_handle,
        );
        if (dma_cvar.v1 < 16) {
            log.print("nvme: createVmar(dma) err=");
            log.dec(dma_cvar.v1);
            log.print("\n");
            return .dma_vmar_create;
        }
        const dma_vmar_handle: HandleId = @truncate(dma_cvar.v1 & 0xFFF);
        self.dma_virt = dma_cvar.v2;
        self.dma_phys = dma_cvar.v2;
        log.print("nvme: dma vmar base=0x");
        log.hex64(self.dma_virt);
        log.print("\n");

        // Spec §[map_pf] pair order: (offset_bytes, page_frame_handle).
        const map_pairs = [_]u64{ 0, dma_pf_handle };
        log.print("nvme: dma mapPf calling, vmar=");
        log.dec(dma_vmar_handle);
        log.print(" pf=");
        log.dec(dma_pf_handle);
        log.print("\n");
        const mp = syscall.mapPf(dma_vmar_handle, map_pairs[0..]);
        log.print("nvme: dma mapPf returned v1=");
        log.dec(mp.v1);
        log.print("\n");
        if (mp.v1 != 0) return .dma_map;
        log.print("nvme: dma mapPf ok, zeroing\n");

        // Zero all DMA memory — phase tags must start at 0 for new CQEs.
        const dma_buf: [*]u8 = @ptrFromInt(self.dma_virt);
        var z: usize = 0;
        while (z < DMA_TOTAL) : (z += 1) dma_buf[z] = 0;

        if (!self.initController()) return .controller_init;
        return .none;
    }

    /// Full controller init sequence per Spec Section 3.5.1.
    fn initController(self: *Controller) bool {
        const cap = self.readReg64(REG_CAP);

        // CAP.MQES [15:0]: 0's based.
        self.max_queue_entries = @truncate(cap & 0xFFFF);

        // CAP.TO [31:24]: 500ms units.
        const timeout_500ms: u32 = @truncate((cap >> 24) & 0xFF);
        const timeout_ns: u64 = @as(u64, timeout_500ms) * 500_000_000;

        // CAP.DSTRD [35:32]: doorbell stride power.
        self.db_stride = @truncate((cap >> 32) & 0xF);

        // CAP.MPSMIN [51:48]: minimum host page size = 2^(12+MPSMIN).
        const mpsmin: u32 = @truncate((cap >> 48) & 0xF);
        if (mpsmin != 0) {
            log.print("nvme: MPSMIN != 0, unsupported\n");
            return false;
        }

        const vs = self.readReg32(REG_VS);
        log.print("nvme: version ");
        log.dec((vs >> 16) & 0xFFFF);
        log.print(".");
        log.dec((vs >> 8) & 0xFF);
        log.print("\n");

        // Step 1 — disable controller, wait CSTS.RDY=0.
        var cc = self.readReg32(REG_CC);
        if (cc & 1 != 0) {
            self.writeReg32(REG_CC, cc & ~@as(u32, 1));
        }
        if (!self.waitForReady(0, timeout_ns)) {
            log.print("nvme: timeout waiting for CSTS.RDY=0\n");
            return false;
        }

        // Step 2 — admin queue attrs + base addresses.
        const aqa: u32 = (@as(u32, ADMIN_QUEUE_SIZE - 1) << 16) | (ADMIN_QUEUE_SIZE - 1);
        self.writeReg32(REG_AQA, aqa);

        const asq_phys = self.dma_phys + DMA_ADMIN_SQ;
        self.writeReg64(REG_ASQ, asq_phys);
        const acq_phys = self.dma_phys + DMA_ADMIN_CQ;
        self.writeReg64(REG_ACQ, acq_phys);

        // Step 3-5 — CC.IOSQES=6, IOCQES=4, MPS=0, AMS=0, CSS=0, EN=1.
        cc = (6 << 16) |
            (4 << 20) |
            (0 << 7) |
            (0 << 4) |
            (0 << 11) |
            1;
        self.writeReg32(REG_CC, cc);

        if (!self.waitForReady(1, timeout_ns)) {
            const csts = self.readReg32(REG_CSTS);
            if (csts & (1 << 1) != 0) {
                log.print("nvme: fatal controller error (CFS=1)\n");
            } else {
                log.print("nvme: timeout waiting for CSTS.RDY=1\n");
            }
            return false;
        }
        log.print("nvme: controller enabled\n");

        if (!self.identifyController()) return false;
        if (self.nn > 0) {
            if (!self.identifyNamespace(1)) return false;
        }
        if (!self.setNumberOfQueues(1, 1)) return false;
        if (!self.createIoCq(1, IO_QUEUE_SIZE, self.dma_phys + DMA_IO_CQ)) return false;
        if (!self.createIoSq(1, IO_QUEUE_SIZE, 1, self.dma_phys + DMA_IO_SQ)) return false;
        log.print("nvme: I/O queues created\n");

        if (self.nn > 0 and self.lba_size > 0) {
            if (self.readSectors(1, 0, 1)) {
                log.print("nvme: test read LBA 0 success\n");
            } else {
                log.print("nvme: test read LBA 0 failed\n");
            }
        }

        return true;
    }

    fn identifyController(self: *Controller) bool {
        var sqe = SubmissionQueueEntry{};
        sqe.cdw0 = buildCdw0(ADMIN_OPC_IDENTIFY, self.nextCid());
        sqe.cdw10 = 0x01; // CNS = Identify Controller
        const id_phys = self.dma_phys + DMA_IDENTIFY;
        sqe.prp1_lo = @truncate(id_phys);
        sqe.prp1_hi = @truncate(id_phys >> 32);

        self.submitAdmin(sqe);
        const status = self.pollAdminCompletion();
        if (status != 0) {
            log.print("nvme: identify controller failed\n");
            return false;
        }

        const id_buf: [*]const u8 = @ptrFromInt(self.dma_virt + DMA_IDENTIFY);
        // NN at bytes 519:516 (Spec Figure 313).
        self.nn = @as(u32, id_buf[516]) |
            (@as(u32, id_buf[517]) << 8) |
            (@as(u32, id_buf[518]) << 16) |
            (@as(u32, id_buf[519]) << 24);

        log.print("nvme: namespaces=");
        log.dec(self.nn);
        log.print("\n");
        return true;
    }

    fn identifyNamespace(self: *Controller, nsid: u32) bool {
        var sqe = SubmissionQueueEntry{};
        sqe.cdw0 = buildCdw0(ADMIN_OPC_IDENTIFY, self.nextCid());
        sqe.nsid = nsid;
        sqe.cdw10 = 0x00; // CNS = Identify Namespace
        const id_phys = self.dma_phys + DMA_IDENTIFY;
        sqe.prp1_lo = @truncate(id_phys);
        sqe.prp1_hi = @truncate(id_phys >> 32);

        self.submitAdmin(sqe);
        const status = self.pollAdminCompletion();
        if (status != 0) {
            log.print("nvme: identify namespace failed\n");
            return false;
        }

        const id_buf: [*]const u8 = @ptrFromInt(self.dma_virt + DMA_IDENTIFY);
        // NSZE at bytes 7:0.
        self.ns_size = @as(u64, id_buf[0]) |
            (@as(u64, id_buf[1]) << 8) |
            (@as(u64, id_buf[2]) << 16) |
            (@as(u64, id_buf[3]) << 24) |
            (@as(u64, id_buf[4]) << 32) |
            (@as(u64, id_buf[5]) << 40) |
            (@as(u64, id_buf[6]) << 48) |
            (@as(u64, id_buf[7]) << 56);

        // FLBAS byte 26: bits [3:0] = LBAF index.
        const flbas = id_buf[26];
        const lba_format_idx: u8 = flbas & 0x0F;

        // LBAF[n] at byte 128 + 4*n; bits [19:16] = LBADS.
        const lbaf_offset: usize = 128 + @as(usize, lba_format_idx) * 4;
        const lbaf: u32 = @as(u32, id_buf[lbaf_offset]) |
            (@as(u32, id_buf[lbaf_offset + 1]) << 8) |
            (@as(u32, id_buf[lbaf_offset + 2]) << 16) |
            (@as(u32, id_buf[lbaf_offset + 3]) << 24);
        const lbads: u5 = @truncate((lbaf >> 16) & 0x1F);
        self.lba_size = @as(u32, 1) << lbads;

        log.print("nvme: ns1 lba_size=");
        log.dec(self.lba_size);
        log.print(" blocks=");
        log.dec(self.ns_size);
        log.print("\n");
        return true;
    }

    fn setNumberOfQueues(self: *Controller, nsq: u16, ncq: u16) bool {
        var sqe = SubmissionQueueEntry{};
        sqe.cdw0 = buildCdw0(ADMIN_OPC_SET_FEATURES, self.nextCid());
        sqe.cdw10 = 0x07; // FID = Number of Queues
        sqe.cdw11 = (@as(u32, ncq - 1) << 16) | (nsq - 1);

        self.submitAdmin(sqe);
        const status = self.pollAdminCompletion();
        if (status != 0) {
            log.print("nvme: set number of queues failed\n");
            return false;
        }
        return true;
    }

    fn createIoCq(self: *Controller, qid: u16, size: u16, phys_addr: u64) bool {
        var sqe = SubmissionQueueEntry{};
        sqe.cdw0 = buildCdw0(ADMIN_OPC_CREATE_IO_CQ, self.nextCid());
        sqe.prp1_lo = @truncate(phys_addr);
        sqe.prp1_hi = @truncate(phys_addr >> 32);
        sqe.cdw10 = (@as(u32, size - 1) << 16) | qid;
        // PC=1, IEN=0 (we poll), IV=0.
        sqe.cdw11 = 1;

        self.submitAdmin(sqe);
        const status = self.pollAdminCompletion();
        if (status != 0) {
            log.print("nvme: create I/O CQ failed\n");
            return false;
        }
        return true;
    }

    fn createIoSq(self: *Controller, qid: u16, size: u16, cqid: u16, phys_addr: u64) bool {
        var sqe = SubmissionQueueEntry{};
        sqe.cdw0 = buildCdw0(ADMIN_OPC_CREATE_IO_SQ, self.nextCid());
        sqe.prp1_lo = @truncate(phys_addr);
        sqe.prp1_hi = @truncate(phys_addr >> 32);
        sqe.cdw10 = (@as(u32, size - 1) << 16) | qid;
        sqe.cdw11 = (@as(u32, cqid) << 16) | 1; // PC=1

        self.submitAdmin(sqe);
        const status = self.pollAdminCompletion();
        if (status != 0) {
            log.print("nvme: create I/O SQ failed\n");
            return false;
        }
        return true;
    }

    pub fn readSectors(self: *Controller, nsid: u32, lba: u64, count: u16) bool {
        var sqe = SubmissionQueueEntry{};
        sqe.cdw0 = buildCdw0(IO_OPC_READ, self.nextCid());
        sqe.nsid = nsid;
        const buf_phys = self.dma_phys + DMA_DATA;
        sqe.prp1_lo = @truncate(buf_phys);
        sqe.prp1_hi = @truncate(buf_phys >> 32);
        sqe.cdw10 = @truncate(lba);
        sqe.cdw11 = @truncate(lba >> 32);
        sqe.cdw12 = count - 1;

        self.submitIo(sqe);
        const status = self.pollIoCompletion();
        if (status != 0) {
            log.print("nvme: read failed status=");
            log.dec(status);
            log.print("\n");
            return false;
        }
        return true;
    }

    pub fn writeSectors(self: *Controller, nsid: u32, lba: u64, count: u16) bool {
        var sqe = SubmissionQueueEntry{};
        sqe.cdw0 = buildCdw0(IO_OPC_WRITE, self.nextCid());
        sqe.nsid = nsid;
        const buf_phys = self.dma_phys + DMA_WRITE;
        sqe.prp1_lo = @truncate(buf_phys);
        sqe.prp1_hi = @truncate(buf_phys >> 32);
        sqe.cdw10 = @truncate(lba);
        sqe.cdw11 = @truncate(lba >> 32);
        sqe.cdw12 = count - 1;

        self.submitIo(sqe);
        const status = self.pollIoCompletion();
        if (status != 0) {
            log.print("nvme: write failed status=");
            log.dec(status);
            log.print("\n");
            return false;
        }
        return true;
    }

    pub fn getReadBuf(self: *const Controller) [*]u8 {
        return @ptrFromInt(self.dma_virt + DMA_DATA);
    }

    pub fn getWriteBuf(self: *const Controller) [*]u8 {
        return @ptrFromInt(self.dma_virt + DMA_WRITE);
    }

    fn sqDoorbell(self: *const Controller, qid: u16) u32 {
        const stride: u32 = @as(u32, 4) << @intCast(self.db_stride);
        return 0x1000 + @as(u32, 2 * qid) * stride;
    }

    fn cqDoorbell(self: *const Controller, qid: u16) u32 {
        const stride: u32 = @as(u32, 4) << @intCast(self.db_stride);
        return 0x1000 + @as(u32, 2 * qid + 1) * stride;
    }

    fn submitAdmin(self: *Controller, sqe: SubmissionQueueEntry) void {
        const sq_base: [*]volatile SubmissionQueueEntry = @ptrFromInt(self.dma_virt + DMA_ADMIN_SQ);
        sq_base[self.admin_sq_tail] = sqe;
        self.admin_sq_tail = (self.admin_sq_tail + 1) % ADMIN_QUEUE_SIZE;
        self.writeReg32(self.sqDoorbell(0), self.admin_sq_tail);
    }

    fn pollAdminCompletion(self: *Controller) u16 {
        const cq_base: [*]volatile CompletionQueueEntry = @ptrFromInt(self.dma_virt + DMA_ADMIN_CQ);
        const timeout_ns: u64 = 5_000_000_000;
        const start = monotonicNs();

        while (true) {
            const cqe = cq_base[self.admin_cq_head];
            const phase: u1 = @truncate(cqe.dw3 >> 16);
            if (phase == self.admin_cq_phase) {
                const status: u16 = @truncate(cqe.dw3 >> 17);
                self.admin_cq_head = (self.admin_cq_head + 1) % ADMIN_QUEUE_SIZE;
                if (self.admin_cq_head == 0) self.admin_cq_phase ^= 1;
                self.writeReg32(self.cqDoorbell(0), self.admin_cq_head);
                return status;
            }

            if (monotonicNs() - start > timeout_ns) {
                log.print("nvme: admin completion timeout\n");
                return 0xFFFF;
            }
            _ = syscall.yieldEc(0);
        }
    }

    fn submitIo(self: *Controller, sqe: SubmissionQueueEntry) void {
        const sq_base: [*]volatile SubmissionQueueEntry = @ptrFromInt(self.dma_virt + DMA_IO_SQ);
        sq_base[self.io_sq_tail] = sqe;
        self.io_sq_tail = (self.io_sq_tail + 1) % IO_QUEUE_SIZE;
        self.writeReg32(self.sqDoorbell(1), self.io_sq_tail);
    }

    fn pollIoCompletion(self: *Controller) u16 {
        const cq_base: [*]volatile CompletionQueueEntry = @ptrFromInt(self.dma_virt + DMA_IO_CQ);
        const timeout_ns: u64 = 5_000_000_000;
        const start = monotonicNs();

        while (true) {
            const cqe = cq_base[self.io_cq_head];
            const phase: u1 = @truncate(cqe.dw3 >> 16);
            if (phase == self.io_cq_phase) {
                const status: u16 = @truncate(cqe.dw3 >> 17);
                self.io_cq_head = (self.io_cq_head + 1) % IO_QUEUE_SIZE;
                if (self.io_cq_head == 0) self.io_cq_phase ^= 1;
                self.writeReg32(self.cqDoorbell(1), self.io_cq_head);
                return status;
            }

            if (monotonicNs() - start > timeout_ns) {
                log.print("nvme: I/O completion timeout\n");
                return 0xFFFF;
            }
            _ = syscall.yieldEc(0);
        }
    }

    fn waitForReady(self: *Controller, expected: u1, timeout_ns: u64) bool {
        const start = monotonicNs();
        while (true) {
            const csts = self.readReg32(REG_CSTS);
            const rdy: u1 = @truncate(csts & 1);
            if (rdy == expected) return true;
            if (expected == 1 and (csts & (1 << 1) != 0)) return false;
            if (monotonicNs() - start > timeout_ns) return false;
            _ = syscall.yieldEc(0);
        }
    }

    fn buildCdw0(opcode: u8, cid: u16) u32 {
        return @as(u32, opcode) | (@as(u32, cid) << 16);
    }

    fn nextCid(self: *Controller) u16 {
        const cid = self.next_cid;
        self.next_cid +%= 1;
        return cid;
    }

    fn readReg32(self: *const Controller, offset: u32) u32 {
        const ptr: *const volatile u32 = @ptrFromInt(self.mmio_base + offset);
        return ptr.*;
    }

    fn readReg64(self: *const Controller, offset: u32) u64 {
        const lo: u64 = self.readReg32(offset);
        const hi: u64 = self.readReg32(offset + 4);
        return lo | (hi << 32);
    }

    fn writeReg32(self: *const Controller, offset: u32, val: u32) void {
        const ptr: *volatile u32 = @ptrFromInt(self.mmio_base + offset);
        ptr.* = val;
    }

    fn writeReg64(self: *const Controller, offset: u32, val: u64) void {
        self.writeReg32(offset, @truncate(val));
        self.writeReg32(offset + 4, @truncate(val >> 32));
    }
};

fn monotonicNs() u64 {
    return syscall.timeMonotonic().v1;
}
