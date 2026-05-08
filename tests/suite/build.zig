const std = @import("std");

const TestEntry = struct {
    name: []const u8,
    path: []const u8,
};

// Authoritative list of spec test ELFs the runner will spawn. Each
// entry corresponds to a `[test NN]` tag in docs/kernel/specv3.md.
// Manifest order is also spawn order; tests that conflict on global
// resources should be ordered serially here. New tests: add a file
// under tests/ then add an entry below.
const test_entries = [_]TestEntry{
    .{ .name = "ack_01", .path = "cases/ack_01.zig" },
    .{ .name = "ack_02", .path = "cases/ack_02.zig" },
    .{ .name = "ack_03", .path = "cases/ack_03.zig" },
    .{ .name = "ack_04", .path = "cases/ack_04.zig" },
    .{ .name = "ack_05", .path = "cases/ack_05.zig" },
    .{ .name = "ack_06", .path = "cases/ack_06.zig" },
    .{ .name = "ack_07", .path = "cases/ack_07.zig" },
    .{ .name = "ack_08", .path = "cases/ack_08.zig" },
    .{ .name = "acquire_ecs_01", .path = "cases/acquire_ecs_01.zig" },
    .{ .name = "acquire_ecs_02", .path = "cases/acquire_ecs_02.zig" },
    .{ .name = "acquire_ecs_03", .path = "cases/acquire_ecs_03.zig" },
    .{ .name = "acquire_ecs_04", .path = "cases/acquire_ecs_04.zig" },
    .{ .name = "acquire_ecs_05", .path = "cases/acquire_ecs_05.zig" },
    .{ .name = "acquire_ecs_06", .path = "cases/acquire_ecs_06.zig" },
    .{ .name = "acquire_ecs_07", .path = "cases/acquire_ecs_07.zig" },
    .{ .name = "acquire_vmars_01", .path = "cases/acquire_vmars_01.zig" },
    .{ .name = "acquire_vmars_02", .path = "cases/acquire_vmars_02.zig" },
    .{ .name = "acquire_vmars_03", .path = "cases/acquire_vmars_03.zig" },
    .{ .name = "acquire_vmars_04", .path = "cases/acquire_vmars_04.zig" },
    .{ .name = "acquire_vmars_05", .path = "cases/acquire_vmars_05.zig" },
    .{ .name = "acquire_vmars_06", .path = "cases/acquire_vmars_06.zig" },
    .{ .name = "acquire_vmars_07", .path = "cases/acquire_vmars_07.zig" },
    .{ .name = "affinity_01", .path = "cases/affinity_01.zig" },
    .{ .name = "affinity_02", .path = "cases/affinity_02.zig" },
    .{ .name = "affinity_03", .path = "cases/affinity_03.zig" },
    .{ .name = "affinity_04", .path = "cases/affinity_04.zig" },
    .{ .name = "affinity_05", .path = "cases/affinity_05.zig" },
    .{ .name = "affinity_06", .path = "cases/affinity_06.zig" },
    .{ .name = "bind_event_route_01", .path = "cases/bind_event_route_01.zig" },
    .{ .name = "bind_event_route_02", .path = "cases/bind_event_route_02.zig" },
    .{ .name = "bind_event_route_03", .path = "cases/bind_event_route_03.zig" },
    .{ .name = "bind_event_route_04", .path = "cases/bind_event_route_04.zig" },
    .{ .name = "bind_event_route_05", .path = "cases/bind_event_route_05.zig" },
    .{ .name = "bind_event_route_06", .path = "cases/bind_event_route_06.zig" },
    .{ .name = "bind_event_route_07", .path = "cases/bind_event_route_07.zig" },
    .{ .name = "bind_event_route_08", .path = "cases/bind_event_route_08.zig" },
    .{ .name = "bind_event_route_09", .path = "cases/bind_event_route_09.zig" },
    .{ .name = "bind_event_route_10", .path = "cases/bind_event_route_10.zig" },
    .{ .name = "clear_event_route_01", .path = "cases/clear_event_route_01.zig" },
    .{ .name = "clear_event_route_02", .path = "cases/clear_event_route_02.zig" },
    .{ .name = "clear_event_route_03", .path = "cases/clear_event_route_03.zig" },
    .{ .name = "clear_event_route_04", .path = "cases/clear_event_route_04.zig" },
    .{ .name = "clear_event_route_05", .path = "cases/clear_event_route_05.zig" },
    .{ .name = "clear_event_route_06", .path = "cases/clear_event_route_06.zig" },
    .{ .name = "clear_event_route_07", .path = "cases/clear_event_route_07.zig" },
    .{ .name = "create_capability_domain_01", .path = "cases/create_capability_domain_01.zig" },
    .{ .name = "create_capability_domain_02", .path = "cases/create_capability_domain_02.zig" },
    .{ .name = "create_capability_domain_03", .path = "cases/create_capability_domain_03.zig" },
    .{ .name = "create_capability_domain_04", .path = "cases/create_capability_domain_04.zig" },
    .{ .name = "create_capability_domain_05", .path = "cases/create_capability_domain_05.zig" },
    .{ .name = "create_capability_domain_06", .path = "cases/create_capability_domain_06.zig" },
    .{ .name = "create_capability_domain_07", .path = "cases/create_capability_domain_07.zig" },
    .{ .name = "create_capability_domain_08", .path = "cases/create_capability_domain_08.zig" },
    .{ .name = "create_capability_domain_09", .path = "cases/create_capability_domain_09.zig" },
    .{ .name = "create_capability_domain_10", .path = "cases/create_capability_domain_10.zig" },
    .{ .name = "create_capability_domain_11", .path = "cases/create_capability_domain_11.zig" },
    .{ .name = "create_capability_domain_12", .path = "cases/create_capability_domain_12.zig" },
    .{ .name = "create_capability_domain_13", .path = "cases/create_capability_domain_13.zig" },
    .{ .name = "create_capability_domain_14", .path = "cases/create_capability_domain_14.zig" },
    .{ .name = "create_capability_domain_15", .path = "cases/create_capability_domain_15.zig" },
    .{ .name = "create_capability_domain_16", .path = "cases/create_capability_domain_16.zig" },
    .{ .name = "create_capability_domain_17", .path = "cases/create_capability_domain_17.zig" },
    .{ .name = "create_capability_domain_18", .path = "cases/create_capability_domain_18.zig" },
    .{ .name = "create_capability_domain_19", .path = "cases/create_capability_domain_19.zig" },
    .{ .name = "create_capability_domain_20", .path = "cases/create_capability_domain_20.zig" },
    .{ .name = "create_capability_domain_21", .path = "cases/create_capability_domain_21.zig" },
    .{ .name = "create_capability_domain_22", .path = "cases/create_capability_domain_22.zig" },
    .{ .name = "create_capability_domain_23", .path = "cases/create_capability_domain_23.zig" },
    .{ .name = "create_capability_domain_24", .path = "cases/create_capability_domain_24.zig" },
    .{ .name = "create_capability_domain_25", .path = "cases/create_capability_domain_25.zig" },
    .{ .name = "create_capability_domain_26", .path = "cases/create_capability_domain_26.zig" },
    .{ .name = "create_capability_domain_27", .path = "cases/create_capability_domain_27.zig" },
    .{ .name = "create_capability_domain_28", .path = "cases/create_capability_domain_28.zig" },
    .{ .name = "create_capability_domain_29", .path = "cases/create_capability_domain_29.zig" },
    .{ .name = "create_capability_domain_16a", .path = "cases/create_capability_domain_16a.zig" },
    .{ .name = "create_capability_domain_30", .path = "cases/create_capability_domain_30.zig" },
    .{ .name = "create_capability_domain_31", .path = "cases/create_capability_domain_31.zig" },
    .{ .name = "create_capability_domain_32", .path = "cases/create_capability_domain_32.zig" },
    .{ .name = "create_execution_context_01", .path = "cases/create_execution_context_01.zig" },
    .{ .name = "create_execution_context_02", .path = "cases/create_execution_context_02.zig" },
    .{ .name = "create_execution_context_03", .path = "cases/create_execution_context_03.zig" },
    .{ .name = "create_execution_context_04", .path = "cases/create_execution_context_04.zig" },
    .{ .name = "create_execution_context_05", .path = "cases/create_execution_context_05.zig" },
    .{ .name = "create_execution_context_06", .path = "cases/create_execution_context_06.zig" },
    .{ .name = "create_execution_context_07", .path = "cases/create_execution_context_07.zig" },
    .{ .name = "create_execution_context_08", .path = "cases/create_execution_context_08.zig" },
    .{ .name = "create_execution_context_09", .path = "cases/create_execution_context_09.zig" },
    .{ .name = "create_execution_context_10", .path = "cases/create_execution_context_10.zig" },
    .{ .name = "create_execution_context_11", .path = "cases/create_execution_context_11.zig" },
    .{ .name = "create_execution_context_12", .path = "cases/create_execution_context_12.zig" },
    .{ .name = "create_execution_context_13", .path = "cases/create_execution_context_13.zig" },
    .{ .name = "create_execution_context_14", .path = "cases/create_execution_context_14.zig" },
    .{ .name = "create_execution_context_15", .path = "cases/create_execution_context_15.zig" },
    .{ .name = "create_page_frame_01", .path = "cases/create_page_frame_01.zig" },
    .{ .name = "create_page_frame_02", .path = "cases/create_page_frame_02.zig" },
    .{ .name = "create_page_frame_03", .path = "cases/create_page_frame_03.zig" },
    .{ .name = "create_page_frame_04", .path = "cases/create_page_frame_04.zig" },
    .{ .name = "create_page_frame_05", .path = "cases/create_page_frame_05.zig" },
    .{ .name = "create_page_frame_06", .path = "cases/create_page_frame_06.zig" },
    .{ .name = "create_page_frame_07", .path = "cases/create_page_frame_07.zig" },
    .{ .name = "create_page_frame_08", .path = "cases/create_page_frame_08.zig" },
    .{ .name = "create_page_frame_09", .path = "cases/create_page_frame_09.zig" },
    .{ .name = "create_page_frame_10", .path = "cases/create_page_frame_10.zig" },
    .{ .name = "create_port_01", .path = "cases/create_port_01.zig" },
    .{ .name = "create_port_02", .path = "cases/create_port_02.zig" },
    .{ .name = "create_port_03", .path = "cases/create_port_03.zig" },
    .{ .name = "create_port_04", .path = "cases/create_port_04.zig" },
    .{ .name = "create_vmar_01", .path = "cases/create_vmar_01.zig" },
    .{ .name = "create_vmar_02", .path = "cases/create_vmar_02.zig" },
    .{ .name = "create_vmar_03", .path = "cases/create_vmar_03.zig" },
    .{ .name = "create_vmar_04", .path = "cases/create_vmar_04.zig" },
    .{ .name = "create_vmar_05", .path = "cases/create_vmar_05.zig" },
    .{ .name = "create_vmar_06", .path = "cases/create_vmar_06.zig" },
    .{ .name = "create_vmar_07", .path = "cases/create_vmar_07.zig" },
    .{ .name = "create_vmar_08", .path = "cases/create_vmar_08.zig" },
    .{ .name = "create_vmar_09", .path = "cases/create_vmar_09.zig" },
    .{ .name = "create_vmar_10", .path = "cases/create_vmar_10.zig" },
    .{ .name = "create_vmar_11", .path = "cases/create_vmar_11.zig" },
    .{ .name = "create_vmar_12", .path = "cases/create_vmar_12.zig" },
    .{ .name = "create_vmar_13", .path = "cases/create_vmar_13.zig" },
    .{ .name = "create_vmar_14", .path = "cases/create_vmar_14.zig" },
    .{ .name = "create_vmar_15", .path = "cases/create_vmar_15.zig" },
    .{ .name = "create_vmar_16", .path = "cases/create_vmar_16.zig" },
    .{ .name = "create_vmar_17", .path = "cases/create_vmar_17.zig" },
    .{ .name = "create_vmar_18", .path = "cases/create_vmar_18.zig" },
    .{ .name = "create_vmar_19", .path = "cases/create_vmar_19.zig" },
    .{ .name = "create_vmar_20", .path = "cases/create_vmar_20.zig" },
    .{ .name = "create_vmar_21", .path = "cases/create_vmar_21.zig" },
    .{ .name = "create_vmar_22", .path = "cases/create_vmar_22.zig" },
    .{ .name = "create_vmar_23", .path = "cases/create_vmar_23.zig" },
    .{ .name = "create_vmar_24", .path = "cases/create_vmar_24.zig" },
    .{ .name = "create_vcpu_01", .path = "cases/create_vcpu_01.zig" },
    .{ .name = "create_vcpu_02", .path = "cases/create_vcpu_02.zig" },
    .{ .name = "create_vcpu_03", .path = "cases/create_vcpu_03.zig" },
    .{ .name = "create_vcpu_04", .path = "cases/create_vcpu_04.zig" },
    .{ .name = "create_vcpu_05", .path = "cases/create_vcpu_05.zig" },
    .{ .name = "create_vcpu_06", .path = "cases/create_vcpu_06.zig" },
    .{ .name = "create_vcpu_07", .path = "cases/create_vcpu_07.zig" },
    .{ .name = "create_vcpu_08", .path = "cases/create_vcpu_08.zig" },
    .{ .name = "create_vcpu_09", .path = "cases/create_vcpu_09.zig" },
    .{ .name = "create_vcpu_10", .path = "cases/create_vcpu_10.zig" },
    .{ .name = "create_vcpu_11", .path = "cases/create_vcpu_11.zig" },
    .{ .name = "create_vcpu_12", .path = "cases/create_vcpu_12.zig" },
    .{ .name = "create_virtual_machine_01", .path = "cases/create_virtual_machine_01.zig" },
    .{ .name = "create_virtual_machine_02", .path = "cases/create_virtual_machine_02.zig" },
    .{ .name = "create_virtual_machine_03", .path = "cases/create_virtual_machine_03.zig" },
    .{ .name = "create_virtual_machine_04", .path = "cases/create_virtual_machine_04.zig" },
    .{ .name = "create_virtual_machine_05", .path = "cases/create_virtual_machine_05.zig" },
    .{ .name = "create_virtual_machine_06", .path = "cases/create_virtual_machine_06.zig" },
    .{ .name = "create_virtual_machine_07", .path = "cases/create_virtual_machine_07.zig" },
    .{ .name = "create_virtual_machine_08", .path = "cases/create_virtual_machine_08.zig" },
    .{ .name = "create_virtual_machine_09", .path = "cases/create_virtual_machine_09.zig" },
    .{ .name = "delete_01", .path = "cases/delete_01.zig" },
    .{ .name = "delete_02", .path = "cases/delete_02.zig" },
    .{ .name = "delete_03", .path = "cases/delete_03.zig" },
    .{ .name = "device_irq_01", .path = "cases/device_irq_01.zig" },
    .{ .name = "device_irq_02", .path = "cases/device_irq_02.zig" },
    .{ .name = "device_irq_03", .path = "cases/device_irq_03.zig" },
    .{ .name = "device_irq_04", .path = "cases/device_irq_04.zig" },
    .{ .name = "futex_wait_change_01", .path = "cases/futex_wait_change_01.zig" },
    .{ .name = "futex_wait_change_02", .path = "cases/futex_wait_change_02.zig" },
    .{ .name = "futex_wait_change_03", .path = "cases/futex_wait_change_03.zig" },
    .{ .name = "futex_wait_change_04", .path = "cases/futex_wait_change_04.zig" },
    .{ .name = "futex_wait_change_05", .path = "cases/futex_wait_change_05.zig" },
    .{ .name = "futex_wait_change_06", .path = "cases/futex_wait_change_06.zig" },
    .{ .name = "futex_wait_change_07", .path = "cases/futex_wait_change_07.zig" },
    .{ .name = "futex_wait_change_08", .path = "cases/futex_wait_change_08.zig" },
    .{ .name = "futex_wait_val_01", .path = "cases/futex_wait_val_01.zig" },
    .{ .name = "futex_wait_val_02", .path = "cases/futex_wait_val_02.zig" },
    .{ .name = "futex_wait_val_03", .path = "cases/futex_wait_val_03.zig" },
    .{ .name = "futex_wait_val_04", .path = "cases/futex_wait_val_04.zig" },
    .{ .name = "futex_wait_val_05", .path = "cases/futex_wait_val_05.zig" },
    .{ .name = "futex_wait_val_06", .path = "cases/futex_wait_val_06.zig" },
    .{ .name = "futex_wait_val_07", .path = "cases/futex_wait_val_07.zig" },
    .{ .name = "futex_wait_val_08", .path = "cases/futex_wait_val_08.zig" },
    .{ .name = "futex_wake_01", .path = "cases/futex_wake_01.zig" },
    .{ .name = "futex_wake_02", .path = "cases/futex_wake_02.zig" },
    .{ .name = "futex_wake_03", .path = "cases/futex_wake_03.zig" },
    .{ .name = "futex_wake_04", .path = "cases/futex_wake_04.zig" },
    .{ .name = "handle_attachments_01", .path = "cases/handle_attachments_01.zig" },
    .{ .name = "handle_attachments_02", .path = "cases/handle_attachments_02.zig" },
    .{ .name = "handle_attachments_03", .path = "cases/handle_attachments_03.zig" },
    .{ .name = "handle_attachments_04", .path = "cases/handle_attachments_04.zig" },
    .{ .name = "handle_attachments_05", .path = "cases/handle_attachments_05.zig" },
    .{ .name = "handle_attachments_06", .path = "cases/handle_attachments_06.zig" },
    .{ .name = "handle_attachments_07", .path = "cases/handle_attachments_07.zig" },
    .{ .name = "handle_attachments_08", .path = "cases/handle_attachments_08.zig" },
    .{ .name = "handle_attachments_09", .path = "cases/handle_attachments_09.zig" },
    .{ .name = "handle_attachments_10", .path = "cases/handle_attachments_10.zig" },
    .{ .name = "idc_read_01", .path = "cases/idc_read_01.zig" },
    .{ .name = "idc_read_02", .path = "cases/idc_read_02.zig" },
    .{ .name = "idc_read_03", .path = "cases/idc_read_03.zig" },
    .{ .name = "idc_read_04", .path = "cases/idc_read_04.zig" },
    .{ .name = "idc_read_05", .path = "cases/idc_read_05.zig" },
    .{ .name = "idc_read_06", .path = "cases/idc_read_06.zig" },
    .{ .name = "idc_read_07", .path = "cases/idc_read_07.zig" },
    .{ .name = "idc_read_08", .path = "cases/idc_read_08.zig" },
    .{ .name = "idc_write_01", .path = "cases/idc_write_01.zig" },
    .{ .name = "idc_write_02", .path = "cases/idc_write_02.zig" },
    .{ .name = "idc_write_03", .path = "cases/idc_write_03.zig" },
    .{ .name = "idc_write_04", .path = "cases/idc_write_04.zig" },
    .{ .name = "idc_write_05", .path = "cases/idc_write_05.zig" },
    .{ .name = "idc_write_06", .path = "cases/idc_write_06.zig" },
    .{ .name = "idc_write_07", .path = "cases/idc_write_07.zig" },
    .{ .name = "idc_write_08", .path = "cases/idc_write_08.zig" },
    .{ .name = "map_guest_01", .path = "cases/map_guest_01.zig" },
    .{ .name = "map_guest_02", .path = "cases/map_guest_02.zig" },
    .{ .name = "map_guest_03", .path = "cases/map_guest_03.zig" },
    .{ .name = "map_guest_04", .path = "cases/map_guest_04.zig" },
    .{ .name = "map_guest_05", .path = "cases/map_guest_05.zig" },
    .{ .name = "map_guest_06", .path = "cases/map_guest_06.zig" },
    .{ .name = "map_guest_07", .path = "cases/map_guest_07.zig" },
    .{ .name = "map_mmio_01", .path = "cases/map_mmio_01.zig" },
    .{ .name = "map_mmio_02", .path = "cases/map_mmio_02.zig" },
    .{ .name = "map_mmio_03", .path = "cases/map_mmio_03.zig" },
    .{ .name = "map_mmio_04", .path = "cases/map_mmio_04.zig" },
    .{ .name = "map_mmio_05", .path = "cases/map_mmio_05.zig" },
    .{ .name = "map_mmio_06", .path = "cases/map_mmio_06.zig" },
    .{ .name = "map_mmio_07", .path = "cases/map_mmio_07.zig" },
    .{ .name = "map_mmio_08", .path = "cases/map_mmio_08.zig" },
    .{ .name = "map_mmio_09", .path = "cases/map_mmio_09.zig" },
    .{ .name = "map_pf_01", .path = "cases/map_pf_01.zig" },
    .{ .name = "map_pf_02", .path = "cases/map_pf_02.zig" },
    .{ .name = "map_pf_03", .path = "cases/map_pf_03.zig" },
    .{ .name = "map_pf_04", .path = "cases/map_pf_04.zig" },
    .{ .name = "map_pf_05", .path = "cases/map_pf_05.zig" },
    .{ .name = "map_pf_06", .path = "cases/map_pf_06.zig" },
    .{ .name = "map_pf_07", .path = "cases/map_pf_07.zig" },
    .{ .name = "map_pf_08", .path = "cases/map_pf_08.zig" },
    .{ .name = "map_pf_09", .path = "cases/map_pf_09.zig" },
    .{ .name = "map_pf_10", .path = "cases/map_pf_10.zig" },
    .{ .name = "map_pf_11", .path = "cases/map_pf_11.zig" },
    .{ .name = "map_pf_12", .path = "cases/map_pf_12.zig" },
    .{ .name = "map_pf_13", .path = "cases/map_pf_13.zig" },
    .{ .name = "map_pf_14", .path = "cases/map_pf_14.zig" },
    .{ .name = "perfmon_info_01", .path = "cases/perfmon_info_01.zig" },
    .{ .name = "perfmon_info_02", .path = "cases/perfmon_info_02.zig" },
    .{ .name = "perfmon_info_03", .path = "cases/perfmon_info_03.zig" },
    .{ .name = "perfmon_info_04", .path = "cases/perfmon_info_04.zig" },
    .{ .name = "perfmon_read_01", .path = "cases/perfmon_read_01.zig" },
    .{ .name = "perfmon_read_02", .path = "cases/perfmon_read_02.zig" },
    .{ .name = "perfmon_read_03", .path = "cases/perfmon_read_03.zig" },
    .{ .name = "perfmon_read_04", .path = "cases/perfmon_read_04.zig" },
    .{ .name = "perfmon_read_05", .path = "cases/perfmon_read_05.zig" },
    .{ .name = "perfmon_read_06", .path = "cases/perfmon_read_06.zig" },
    .{ .name = "perfmon_read_07", .path = "cases/perfmon_read_07.zig" },
    .{ .name = "perfmon_start_01", .path = "cases/perfmon_start_01.zig" },
    .{ .name = "perfmon_start_02", .path = "cases/perfmon_start_02.zig" },
    .{ .name = "perfmon_start_03", .path = "cases/perfmon_start_03.zig" },
    .{ .name = "perfmon_start_04", .path = "cases/perfmon_start_04.zig" },
    .{ .name = "perfmon_start_05", .path = "cases/perfmon_start_05.zig" },
    .{ .name = "perfmon_start_06", .path = "cases/perfmon_start_06.zig" },
    .{ .name = "perfmon_start_07", .path = "cases/perfmon_start_07.zig" },
    .{ .name = "perfmon_start_08", .path = "cases/perfmon_start_08.zig" },
    .{ .name = "perfmon_start_09", .path = "cases/perfmon_start_09.zig" },
    .{ .name = "perfmon_stop_01", .path = "cases/perfmon_stop_01.zig" },
    .{ .name = "perfmon_stop_02", .path = "cases/perfmon_stop_02.zig" },
    .{ .name = "perfmon_stop_03", .path = "cases/perfmon_stop_03.zig" },
    .{ .name = "perfmon_stop_04", .path = "cases/perfmon_stop_04.zig" },
    .{ .name = "perfmon_stop_05", .path = "cases/perfmon_stop_05.zig" },
    .{ .name = "perfmon_stop_06", .path = "cases/perfmon_stop_06.zig" },
    .{ .name = "port_io_virtualization_01", .path = "cases/port_io_virtualization_01.zig" },
    .{ .name = "port_io_virtualization_02", .path = "cases/port_io_virtualization_02.zig" },
    .{ .name = "port_io_virtualization_03", .path = "cases/port_io_virtualization_03.zig" },
    .{ .name = "port_io_virtualization_04", .path = "cases/port_io_virtualization_04.zig" },
    .{ .name = "port_io_virtualization_05", .path = "cases/port_io_virtualization_05.zig" },
    .{ .name = "port_io_virtualization_06", .path = "cases/port_io_virtualization_06.zig" },
    .{ .name = "port_io_virtualization_07", .path = "cases/port_io_virtualization_07.zig" },
    .{ .name = "port_io_virtualization_08", .path = "cases/port_io_virtualization_08.zig" },
    .{ .name = "port_io_virtualization_09", .path = "cases/port_io_virtualization_09.zig" },
    .{ .name = "port_io_virtualization_10", .path = "cases/port_io_virtualization_10.zig" },
    .{ .name = "port_io_virtualization_11", .path = "cases/port_io_virtualization_11.zig" },
    .{ .name = "power_01", .path = "cases/power_01.zig" },
    .{ .name = "power_02", .path = "cases/power_02.zig" },
    .{ .name = "power_03", .path = "cases/power_03.zig" },
    .{ .name = "power_04", .path = "cases/power_04.zig" },
    .{ .name = "power_05", .path = "cases/power_05.zig" },
    .{ .name = "power_06", .path = "cases/power_06.zig" },
    .{ .name = "power_07", .path = "cases/power_07.zig" },
    .{ .name = "power_08", .path = "cases/power_08.zig" },
    .{ .name = "power_09", .path = "cases/power_09.zig" },
    .{ .name = "power_10", .path = "cases/power_10.zig" },
    .{ .name = "power_11", .path = "cases/power_11.zig" },
    .{ .name = "power_12", .path = "cases/power_12.zig" },
    .{ .name = "power_13", .path = "cases/power_13.zig" },
    .{ .name = "power_14", .path = "cases/power_14.zig" },
    .{ .name = "power_15", .path = "cases/power_15.zig" },
    .{ .name = "priority_01", .path = "cases/priority_01.zig" },
    .{ .name = "priority_02", .path = "cases/priority_02.zig" },
    .{ .name = "priority_03", .path = "cases/priority_03.zig" },
    .{ .name = "priority_04", .path = "cases/priority_04.zig" },
    .{ .name = "priority_05", .path = "cases/priority_05.zig" },
    .{ .name = "priority_06", .path = "cases/priority_06.zig" },
    .{ .name = "priority_07", .path = "cases/priority_07.zig" },
    .{ .name = "priority_08", .path = "cases/priority_08.zig" },
    .{ .name = "recv_01", .path = "cases/recv_01.zig" },
    .{ .name = "recv_02", .path = "cases/recv_02.zig" },
    .{ .name = "recv_03", .path = "cases/recv_03.zig" },
    .{ .name = "recv_04", .path = "cases/recv_04.zig" },
    .{ .name = "recv_05", .path = "cases/recv_05.zig" },
    .{ .name = "recv_06", .path = "cases/recv_06.zig" },
    .{ .name = "recv_07", .path = "cases/recv_07.zig" },
    .{ .name = "recv_08", .path = "cases/recv_08.zig" },
    .{ .name = "recv_09", .path = "cases/recv_09.zig" },
    .{ .name = "recv_10", .path = "cases/recv_10.zig" },
    .{ .name = "recv_11", .path = "cases/recv_11.zig" },
    .{ .name = "recv_12", .path = "cases/recv_12.zig" },
    .{ .name = "recv_13", .path = "cases/recv_13.zig" },
    .{ .name = "recv_14", .path = "cases/recv_14.zig" },
    .{ .name = "recv_15", .path = "cases/recv_15.zig" },
    .{ .name = "recv_16", .path = "cases/recv_16.zig" },
    .{ .name = "recv_17", .path = "cases/recv_17.zig" },
    .{ .name = "recv_18", .path = "cases/recv_18.zig" },
    .{ .name = "remap_01", .path = "cases/remap_01.zig" },
    .{ .name = "remap_02", .path = "cases/remap_02.zig" },
    .{ .name = "remap_03", .path = "cases/remap_03.zig" },
    .{ .name = "remap_04", .path = "cases/remap_04.zig" },
    .{ .name = "remap_05", .path = "cases/remap_05.zig" },
    .{ .name = "remap_06", .path = "cases/remap_06.zig" },
    .{ .name = "remap_07", .path = "cases/remap_07.zig" },
    .{ .name = "remap_08", .path = "cases/remap_08.zig" },
    .{ .name = "remap_09", .path = "cases/remap_09.zig" },
    .{ .name = "reply_01", .path = "cases/reply_01.zig" },
    .{ .name = "reply_02", .path = "cases/reply_02.zig" },
    .{ .name = "reply_03", .path = "cases/reply_03.zig" },
    .{ .name = "reply_04", .path = "cases/reply_04.zig" },
    .{ .name = "reply_05", .path = "cases/reply_05.zig" },
    .{ .name = "reply_06", .path = "cases/reply_06.zig" },
    .{ .name = "reply_07", .path = "cases/reply_07.zig" },
    .{ .name = "reply_08", .path = "cases/reply_08.zig" },
    .{ .name = "reply_09", .path = "cases/reply_09.zig" },
    .{ .name = "reply_10", .path = "cases/reply_10.zig" },
    .{ .name = "reply_11", .path = "cases/reply_11.zig" },
    .{ .name = "reply_12", .path = "cases/reply_12.zig" },
    .{ .name = "reply_13", .path = "cases/reply_13.zig" },
    .{ .name = "reply_14", .path = "cases/reply_14.zig" },
    .{ .name = "reply_15", .path = "cases/reply_15.zig" },
    .{ .name = "reply_16", .path = "cases/reply_16.zig" },
    .{ .name = "reply_17", .path = "cases/reply_17.zig" },
    .{ .name = "reply_18", .path = "cases/reply_18.zig" },
    .{ .name = "reply_19", .path = "cases/reply_19.zig" },
    .{ .name = "reply_20", .path = "cases/reply_20.zig" },
    .{ .name = "reply_21", .path = "cases/reply_21.zig" },
    .{ .name = "reply_22", .path = "cases/reply_22.zig" },
    .{ .name = "reply_23", .path = "cases/reply_23.zig" },
    .{ .name = "reply_24", .path = "cases/reply_24.zig" },
    .{ .name = "reply_25", .path = "cases/reply_25.zig" },
    .{ .name = "reply_26", .path = "cases/reply_26.zig" },
    .{ .name = "restart_semantics_01", .path = "cases/restart_semantics_01.zig" },
    .{ .name = "restart_semantics_02", .path = "cases/restart_semantics_02.zig" },
    .{ .name = "restart_semantics_03", .path = "cases/restart_semantics_03.zig" },
    .{ .name = "restart_semantics_04", .path = "cases/restart_semantics_04.zig" },
    .{ .name = "restart_semantics_05", .path = "cases/restart_semantics_05.zig" },
    .{ .name = "restart_semantics_06", .path = "cases/restart_semantics_06.zig" },
    .{ .name = "restart_semantics_07", .path = "cases/restart_semantics_07.zig" },
    .{ .name = "restart_semantics_08", .path = "cases/restart_semantics_08.zig" },
    .{ .name = "restrict_01", .path = "cases/restrict_01.zig" },
    .{ .name = "restrict_02", .path = "cases/restrict_02.zig" },
    .{ .name = "restrict_03", .path = "cases/restrict_03.zig" },
    .{ .name = "restrict_04", .path = "cases/restrict_04.zig" },
    .{ .name = "restrict_05", .path = "cases/restrict_05.zig" },
    .{ .name = "restrict_06", .path = "cases/restrict_06.zig" },
    .{ .name = "restrict_07", .path = "cases/restrict_07.zig" },
    .{ .name = "restrict_08", .path = "cases/restrict_08.zig" },
    .{ .name = "revoke_01", .path = "cases/revoke_01.zig" },
    .{ .name = "revoke_02", .path = "cases/revoke_02.zig" },
    .{ .name = "revoke_03", .path = "cases/revoke_03.zig" },
    .{ .name = "revoke_04", .path = "cases/revoke_04.zig" },
    .{ .name = "revoke_05", .path = "cases/revoke_05.zig" },
    .{ .name = "revoke_06", .path = "cases/revoke_06.zig" },
    .{ .name = "rng_01", .path = "cases/rng_01.zig" },
    .{ .name = "rng_02", .path = "cases/rng_02.zig" },
    .{ .name = "self_01", .path = "cases/self_01.zig" },
    .{ .name = "self_02", .path = "cases/self_02.zig" },
    .{ .name = "self_handle_01", .path = "cases/self_handle_01.zig" },
    .{ .name = "snapshot_01", .path = "cases/snapshot_01.zig" },
    .{ .name = "snapshot_02", .path = "cases/snapshot_02.zig" },
    .{ .name = "snapshot_03", .path = "cases/snapshot_03.zig" },
    .{ .name = "snapshot_04", .path = "cases/snapshot_04.zig" },
    .{ .name = "snapshot_05", .path = "cases/snapshot_05.zig" },
    .{ .name = "snapshot_06", .path = "cases/snapshot_06.zig" },
    .{ .name = "snapshot_07", .path = "cases/snapshot_07.zig" },
    .{ .name = "snapshot_08", .path = "cases/snapshot_08.zig" },
    .{ .name = "snapshot_09", .path = "cases/snapshot_09.zig" },
    .{ .name = "snapshot_10", .path = "cases/snapshot_10.zig" },
    .{ .name = "snapshot_11", .path = "cases/snapshot_11.zig" },
    .{ .name = "suspend_01", .path = "cases/suspend_01.zig" },
    .{ .name = "suspend_02", .path = "cases/suspend_02.zig" },
    .{ .name = "suspend_03", .path = "cases/suspend_03.zig" },
    .{ .name = "suspend_04", .path = "cases/suspend_04.zig" },
    .{ .name = "suspend_05", .path = "cases/suspend_05.zig" },
    .{ .name = "suspend_06", .path = "cases/suspend_06.zig" },
    .{ .name = "suspend_07", .path = "cases/suspend_07.zig" },
    .{ .name = "suspend_08", .path = "cases/suspend_08.zig" },
    .{ .name = "suspend_09", .path = "cases/suspend_09.zig" },
    .{ .name = "suspend_10", .path = "cases/suspend_10.zig" },
    .{ .name = "suspend_11", .path = "cases/suspend_11.zig" },
    .{ .name = "suspend_12", .path = "cases/suspend_12.zig" },
    .{ .name = "sync_01", .path = "cases/sync_01.zig" },
    .{ .name = "sync_02", .path = "cases/sync_02.zig" },
    .{ .name = "sync_03", .path = "cases/sync_03.zig" },
    .{ .name = "system_info_01", .path = "cases/system_info_01.zig" },
    .{ .name = "system_info_02", .path = "cases/system_info_02.zig" },
    .{ .name = "system_info_03", .path = "cases/system_info_03.zig" },
    .{ .name = "system_info_04", .path = "cases/system_info_04.zig" },
    .{ .name = "system_info_05", .path = "cases/system_info_05.zig" },
    .{ .name = "system_info_06", .path = "cases/system_info_06.zig" },
    .{ .name = "terminate_01", .path = "cases/terminate_01.zig" },
    .{ .name = "terminate_02", .path = "cases/terminate_02.zig" },
    .{ .name = "terminate_03", .path = "cases/terminate_03.zig" },
    .{ .name = "terminate_04", .path = "cases/terminate_04.zig" },
    .{ .name = "terminate_05", .path = "cases/terminate_05.zig" },
    .{ .name = "terminate_06", .path = "cases/terminate_06.zig" },
    .{ .name = "terminate_07", .path = "cases/terminate_07.zig" },
    .{ .name = "terminate_08", .path = "cases/terminate_08.zig" },
    .{ .name = "time_01", .path = "cases/time_01.zig" },
    .{ .name = "time_02", .path = "cases/time_02.zig" },
    .{ .name = "time_03", .path = "cases/time_03.zig" },
    .{ .name = "time_04", .path = "cases/time_04.zig" },
    .{ .name = "time_05", .path = "cases/time_05.zig" },
    .{ .name = "timer_arm_01", .path = "cases/timer_arm_01.zig" },
    .{ .name = "timer_arm_02", .path = "cases/timer_arm_02.zig" },
    .{ .name = "timer_arm_03", .path = "cases/timer_arm_03.zig" },
    .{ .name = "timer_arm_04", .path = "cases/timer_arm_04.zig" },
    .{ .name = "timer_arm_05", .path = "cases/timer_arm_05.zig" },
    .{ .name = "timer_arm_06", .path = "cases/timer_arm_06.zig" },
    .{ .name = "timer_arm_07", .path = "cases/timer_arm_07.zig" },
    .{ .name = "timer_arm_08", .path = "cases/timer_arm_08.zig" },
    .{ .name = "timer_arm_09", .path = "cases/timer_arm_09.zig" },
    .{ .name = "timer_arm_10", .path = "cases/timer_arm_10.zig" },
    .{ .name = "timer_cancel_01", .path = "cases/timer_cancel_01.zig" },
    .{ .name = "timer_cancel_02", .path = "cases/timer_cancel_02.zig" },
    .{ .name = "timer_cancel_03", .path = "cases/timer_cancel_03.zig" },
    .{ .name = "timer_cancel_04", .path = "cases/timer_cancel_04.zig" },
    .{ .name = "timer_cancel_05", .path = "cases/timer_cancel_05.zig" },
    .{ .name = "timer_cancel_06", .path = "cases/timer_cancel_06.zig" },
    .{ .name = "timer_cancel_07", .path = "cases/timer_cancel_07.zig" },
    .{ .name = "timer_cancel_08", .path = "cases/timer_cancel_08.zig" },
    .{ .name = "timer_cancel_09", .path = "cases/timer_cancel_09.zig" },
    .{ .name = "timer_rearm_01", .path = "cases/timer_rearm_01.zig" },
    .{ .name = "timer_rearm_02", .path = "cases/timer_rearm_02.zig" },
    .{ .name = "timer_rearm_03", .path = "cases/timer_rearm_03.zig" },
    .{ .name = "timer_rearm_04", .path = "cases/timer_rearm_04.zig" },
    .{ .name = "timer_rearm_05", .path = "cases/timer_rearm_05.zig" },
    .{ .name = "timer_rearm_06", .path = "cases/timer_rearm_06.zig" },
    .{ .name = "timer_rearm_07", .path = "cases/timer_rearm_07.zig" },
    .{ .name = "timer_rearm_08", .path = "cases/timer_rearm_08.zig" },
    .{ .name = "timer_rearm_09", .path = "cases/timer_rearm_09.zig" },
    .{ .name = "timer_rearm_10", .path = "cases/timer_rearm_10.zig" },
    .{ .name = "unmap_01", .path = "cases/unmap_01.zig" },
    .{ .name = "unmap_02", .path = "cases/unmap_02.zig" },
    .{ .name = "unmap_03", .path = "cases/unmap_03.zig" },
    .{ .name = "unmap_04", .path = "cases/unmap_04.zig" },
    .{ .name = "unmap_05", .path = "cases/unmap_05.zig" },
    .{ .name = "unmap_06", .path = "cases/unmap_06.zig" },
    .{ .name = "unmap_07", .path = "cases/unmap_07.zig" },
    .{ .name = "unmap_08", .path = "cases/unmap_08.zig" },
    .{ .name = "unmap_09", .path = "cases/unmap_09.zig" },
    .{ .name = "unmap_10", .path = "cases/unmap_10.zig" },
    .{ .name = "unmap_11", .path = "cases/unmap_11.zig" },
    .{ .name = "unmap_12", .path = "cases/unmap_12.zig" },
    .{ .name = "unmap_guest_01", .path = "cases/unmap_guest_01.zig" },
    .{ .name = "unmap_guest_02", .path = "cases/unmap_guest_02.zig" },
    .{ .name = "unmap_guest_03", .path = "cases/unmap_guest_03.zig" },
    .{ .name = "unmap_guest_04", .path = "cases/unmap_guest_04.zig" },
    .{ .name = "unmap_guest_05", .path = "cases/unmap_guest_05.zig" },
    .{ .name = "vm_inject_irq_01", .path = "cases/vm_inject_irq_01.zig" },
    .{ .name = "vm_inject_irq_02", .path = "cases/vm_inject_irq_02.zig" },
    .{ .name = "vm_inject_irq_03", .path = "cases/vm_inject_irq_03.zig" },
    .{ .name = "vm_inject_irq_04", .path = "cases/vm_inject_irq_04.zig" },
    .{ .name = "vm_inject_irq_05", .path = "cases/vm_inject_irq_05.zig" },
    .{ .name = "vm_set_policy_01", .path = "cases/vm_set_policy_01.zig" },
    .{ .name = "vm_set_policy_02", .path = "cases/vm_set_policy_02.zig" },
    .{ .name = "vm_set_policy_03", .path = "cases/vm_set_policy_03.zig" },
    .{ .name = "vm_set_policy_04", .path = "cases/vm_set_policy_04.zig" },
    .{ .name = "vm_set_policy_05", .path = "cases/vm_set_policy_05.zig" },
    .{ .name = "vm_set_policy_06", .path = "cases/vm_set_policy_06.zig" },
    .{ .name = "vm_set_policy_07", .path = "cases/vm_set_policy_07.zig" },
    .{ .name = "vm_set_policy_08", .path = "cases/vm_set_policy_08.zig" },
    .{ .name = "vm_set_policy_09", .path = "cases/vm_set_policy_09.zig" },
    .{ .name = "yield_01", .path = "cases/yield_01.zig" },
    .{ .name = "yield_02", .path = "cases/yield_02.zig" },
    .{ .name = "yield_03", .path = "cases/yield_03.zig" },
    .{ .name = "yield_04", .path = "cases/yield_04.zig" },
};

// Build libz.elf — kernel-shipped userspace shared library. Test ELFs
// `linkLibrary` against it and end up with DT_NEEDED libz.so +
// JUMP_SLOT relocs that libz_loader.relocateSelf patches at runtime.
// Zig refuses dynamic linkage on .freestanding, so we tag .linux/.none
// — purely the gate; libz links zero Linux runtime and the kernel ELF
// loader (not Linux ld.so) loads it. The C-ABI shape used internally
// by libz/abi.zig is invisible to consumers — exported dynsym names
// match the Zig-native API in libz/syscall.zig.
fn addLibz(
    b: *std.Build,
    arch: std.Target.Cpu.Arch,
) *std.Build.Step.Compile {
    const cpu_features_sub: std.Target.Cpu.Feature.Set = blk: {
        var s = std.Target.Cpu.Feature.Set.empty;
        if (arch == .x86_64) {
            const F = std.Target.x86.Feature;
            s.addFeature(@intFromEnum(F.mmx));
            s.addFeature(@intFromEnum(F.sse));
            s.addFeature(@intFromEnum(F.sse2));
            s.addFeature(@intFromEnum(F.avx));
            s.addFeature(@intFromEnum(F.avx2));
        }
        break :blk s;
    };
    const cpu_features_add: std.Target.Cpu.Feature.Set = blk: {
        var s = std.Target.Cpu.Feature.Set.empty;
        if (arch == .x86_64) {
            s.addFeature(@intFromEnum(std.Target.x86.Feature.soft_float));
        }
        break :blk s;
    };
    const linux_target = b.resolveTargetQuery(.{
        .cpu_arch = arch,
        .os_tag = .linux,
        .abi = .none,
        .ofmt = .elf,
        .cpu_features_sub = cpu_features_sub,
        .cpu_features_add = cpu_features_add,
    });

    // libz/abi.zig imports syscall.zig directly (same-dir), so no
    // module-graph dep wiring is needed. The build module's source-
    // file dir resolves @import("syscall.zig") relative to abi.zig,
    // which lands on libz/syscall.zig as expected.
    //
    // .Debug is mandatory: ReleaseSmall / ReleaseFast / ReleaseSafe
    // all trip LLVM's register allocator on the >13-output-operand
    // inline asm in libz/syscall_x64.zig (replyTransferAsm and the
    // capture-word path). LLVM can't satisfy the tied register
    // constraints alongside its internal scratch needs at -O > 0.
    // Building libz at .Debug is fine: it's a single shared object
    // mapped once across all test ELFs, so size cost is paid once,
    // and the inline-asm syscall wrappers are the entire .text body.
    const abi_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "../../libz/abi.zig" },
        .target = linux_target,
        .optimize = .Debug,
        .pic = true,
        .single_threaded = true,
    });

    const libz = b.addLibrary(.{
        .name = "z",
        .linkage = .dynamic,
        .root_module = abi_mod,
    });
    libz.root_module.red_zone = false;
    libz.root_module.omit_frame_pointer = false;
    libz.use_llvm = true;
    libz.use_lld = true;

    return libz;
}

const TestBuildCtx = struct {
    target_freestanding: std.Build.ResolvedTarget,
    target_dynlink: std.Build.ResolvedTarget,
    libz: *std.Build.Step.Compile,
    libz_loader_src: std.Build.LazyPath,
    caps_mod: *std.Build.Module,
    errors_mod: *std.Build.Module,
    syscall_extern_mod: *std.Build.Module,
};

fn buildTestElf(
    b: *std.Build,
    ctx: TestBuildCtx,
    tag_wf: *std.Build.Step.WriteFile,
    name: []const u8,
    src_path: []const u8,
    tag: u16,
) std.Build.LazyPath {
    // Per-test tag module embedded into the test ELF so it can stamp
    // its identity into every result event without depending on
    // completion order in the runner.
    const tag_src = b.fmt("pub const TAG: u16 = {d};\n", .{tag});
    const tag_path = tag_wf.add(b.fmt("test_tag_{s}.zig", .{name}), tag_src);
    const tag_mod = b.createModule(.{
        .root_source_file = tag_path,
        .target = ctx.target_dynlink,
        .optimize = .ReleaseSmall,
    });

    // Per-test libz clone. Required because runner/testing.zig statically
    // imports test_tag and we need each test to see its own. The clone
    // shares source with runner/lib.zig but rewires test_tag.
    const test_lib_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "runner/lib.zig" },
        .target = ctx.target_dynlink,
        .optimize = .ReleaseSmall,
        .pic = true,
        .omit_frame_pointer = true,
        .single_threaded = true,
    });
    test_lib_mod.addImport("lib", test_lib_mod);
    test_lib_mod.addImport("test_tag", tag_mod);
    test_lib_mod.addImport("caps", ctx.caps_mod);
    test_lib_mod.addImport("errors", ctx.errors_mod);
    test_lib_mod.addImport("syscall", ctx.syscall_extern_mod);

    const libz_loader_mod = b.createModule(.{
        .root_source_file = ctx.libz_loader_src,
        .target = ctx.target_dynlink,
        .optimize = .ReleaseSmall,
        .pic = true,
        .single_threaded = true,
    });

    const app_mod = b.createModule(.{
        .root_source_file = b.path(src_path),
        .target = ctx.target_dynlink,
        .optimize = .ReleaseSmall,
        .pic = true,
        .omit_frame_pointer = true,
        .single_threaded = true,
    });
    app_mod.addImport("lib", test_lib_mod);
    app_mod.addImport("test_tag", tag_mod);

    const start_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "runner/start.zig" },
        .target = ctx.target_dynlink,
        .optimize = .ReleaseSmall,
        .pic = true,
        .omit_frame_pointer = true,
        .single_threaded = true,
    });
    start_mod.addImport("lib", test_lib_mod);
    start_mod.addImport("app", app_mod);
    start_mod.addImport("libz_loader", libz_loader_mod);

    const exe = b.addExecutable(.{
        .name = name,
        .root_module = start_mod,
        .linkage = .dynamic,
    });
    exe.pie = true;
    exe.entry = .{ .symbol_name = "_start" };
    // Drop the static linker.ld — dynamic test ELFs need .dynamic /
    // .dynsym / .dynstr / .rela.dyn / .rela.plt preserved so
    // libz_loader.relocateSelf finds them at runtime. The standard
    // ld.lld layout (4-PT_LOAD per-perm split, contiguous .dyn*) is
    // exactly what kernel/boot/userspace_init.zig expects for both
    // test ELFs and the libz_c image.
    exe.linkLibrary(ctx.libz);
    // Force LLVM + LLD: same reason as libz_c — Zig 0.15's self-hosted
    // x86_64 backend chokes on the inline-asm syscall wrappers in
    // libz/syscall_x64.zig (replyTransferAsm "ran out of registers")
    // and on naked-callconv functions pulled in transitively by .linux.
    exe.use_llvm = true;
    exe.use_lld = true;

    return exe.getEmittedBin();
}

/// Returns true if `name` matches `pattern`, where `*` in `pattern`
/// matches any (possibly empty) substring of `name`. Match is anchored
/// at both ends. No other glob metacharacters are recognized — this is
/// a developer-convenience filter, not a full glob implementation.
fn patternMatches(pattern: []const u8, name: []const u8) bool {
    // Fast path: no wildcards → exact compare.
    if (std.mem.indexOfScalar(u8, pattern, '*') == null) {
        return std.mem.eql(u8, pattern, name);
    }
    // Split pattern on '*'. The first piece must prefix-match `name`,
    // the last piece must suffix-match the remainder, and each interior
    // piece must occur in order in between.
    var pieces = std.mem.splitScalar(u8, pattern, '*');
    const first = pieces.next() orelse return true;
    if (!std.mem.startsWith(u8, name, first)) return false;
    var cursor: usize = first.len;
    var pending: ?[]const u8 = pieces.next();
    while (pending) |piece| {
        const next = pieces.next();
        if (next == null) {
            // Last piece: anchor at the end of `name`.
            if (piece.len > name.len - cursor) return false;
            const tail_start = name.len - piece.len;
            if (tail_start < cursor) return false;
            if (!std.mem.eql(u8, name[tail_start..], piece)) return false;
            return true;
        }
        // Interior piece: must appear at or after cursor.
        if (piece.len == 0) {
            pending = next;
            continue;
        }
        const idx = std.mem.indexOfPos(u8, name, cursor, piece) orelse return false;
        cursor = idx + piece.len;
        pending = next;
    }
    return true;
}

pub fn build(b: *std.Build) void {
    const target_arch_str = b.option([]const u8, "arch", "Target architecture (x64 or arm)") orelse "x64";
    const cpu_arch: std.Target.Cpu.Arch = blk: {
        if (std.mem.eql(u8, target_arch_str, "x64")) break :blk .x86_64;
        if (std.mem.eql(u8, target_arch_str, "arm")) break :blk .aarch64;
        @panic("-Darch must be one of: x64, arm");
    };

    const target_freestanding = b.resolveTargetQuery(.{
        .cpu_arch = cpu_arch,
        .os_tag = .freestanding,
    });
    // Test ELFs need .linux/.none so Zig allows `linkage = .dynamic`.
    // Purely a linker gate — we don't actually link any Linux runtime.
    const target_dynlink = b.resolveTargetQuery(.{
        .cpu_arch = cpu_arch,
        .os_tag = .linux,
        .abi = .none,
        .ofmt = .elf,
    });

    const tests_filter = b.option(
        []const u8,
        "tests",
        "Comma-separated list of test names or glob-style patterns (e.g. recv_01,recv_*) to embed in the runner manifest. Omit to embed all tests.",
    );

    // Number of times the runner replays the embedded test list per
    // boot. With N>1 the runner iterates the manifest N times back-
    // to-back, clearing its result table between runs and printing a
    // per-run summary plus a final aggregate (`pass / fail / miss`
    // totals across runs). Used to flush out flaky tests at high
    // iteration counts without paying kernel-build / boot cost per rep.
    const repeat = b.option(u32, "repeat", "Number of times to replay the test manifest per boot (default 1)") orelse 1;

    // Build the filtered list of test entries up front. The same
    // selection drives both per-test ELF builds and the manifest the
    // primary runner iterates.
    var selected = std.array_list.Managed(TestEntry).init(b.allocator);
    defer selected.deinit();
    if (tests_filter) |raw| {
        if (raw.len == 0) {
            @panic("-Dtests requires at least one test name or pattern");
        }
        var patterns = std.array_list.Managed([]const u8).init(b.allocator);
        defer patterns.deinit();
        var it = std.mem.splitScalar(u8, raw, ',');
        while (it.next()) |piece| {
            const trimmed = std.mem.trim(u8, piece, " \t");
            if (trimmed.len == 0) {
                @panic("-Dtests contains an empty entry (check for stray commas)");
            }
            patterns.append(trimmed) catch @panic("OOM building -Dtests pattern list");
        }
        for (test_entries) |t| {
            for (patterns.items) |pat| {
                if (patternMatches(pat, t.name)) {
                    selected.append(t) catch @panic("OOM appending selected test");
                    break;
                }
            }
        }
        if (selected.items.len == 0) {
            const msg = std.fmt.allocPrint(
                b.allocator,
                "-Dtests={s}: zero tests matched the supplied patterns",
                .{raw},
            ) catch "-Dtests: zero tests matched the supplied patterns";
            @panic(msg);
        }
    } else {
        selected.appendSlice(&test_entries) catch @panic("OOM seeding default test list");
    }
    const selected_entries = selected.items;

    // Sentinel `test_tag` module for non-test consumers of the runner
    // libz wrapper (the primary runner). The runner never calls
    // `lib.testing.report`, but runner/testing.zig statically
    // `@import`s `test_tag`, so something must satisfy the import.
    // Sentinel TAG = 0xFFFF is reserved.
    const sentinel_tag_wf = b.addWriteFiles();
    const sentinel_tag_path = sentinel_tag_wf.add(
        "test_tag_sentinel.zig",
        "pub const TAG: u16 = 0xFFFF;\n",
    );
    const sentinel_tag_mod = b.createModule(.{
        .root_source_file = sentinel_tag_path,
        .target = target_freestanding,
        .optimize = .ReleaseSmall,
    });

    // Shared caps/errors modules — pure spec types, both target flavors.
    const caps_runner_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "../../libz/caps.zig" },
        .target = target_freestanding,
        .optimize = .ReleaseSmall,
        .pic = true,
        .omit_frame_pointer = true,
    });
    const errors_runner_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "../../libz/errors.zig" },
        .target = target_freestanding,
        .optimize = .ReleaseSmall,
        .pic = true,
        .omit_frame_pointer = true,
    });
    const caps_dynlink_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "../../libz/caps.zig" },
        .target = target_dynlink,
        .optimize = .ReleaseSmall,
        .pic = true,
        .omit_frame_pointer = true,
        .single_threaded = true,
    });
    const errors_dynlink_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "../../libz/errors.zig" },
        .target = target_dynlink,
        .optimize = .ReleaseSmall,
        .pic = true,
        .omit_frame_pointer = true,
        .single_threaded = true,
    });

    // Runner libz: statically linked, wired to lib_static.zig — `syscall`
    // points at the top-level libz/syscall.zig (full inline-asm bodies,
    // no externs). The runner is the framework's bootstrap layer and
    // cannot itself depend on libz.elf — it's the one that stages
    // libz.elf into a page_frame for children.
    const runner_syscall_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "../../libz/syscall.zig" },
        .target = target_freestanding,
        .optimize = .ReleaseSmall,
        .pic = true,
        .omit_frame_pointer = true,
    });
    const lib_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "runner/lib_static.zig" },
        .target = target_freestanding,
        .optimize = .ReleaseSmall,
        .pic = true,
        .omit_frame_pointer = true,
    });
    lib_mod.addImport("lib", lib_mod);
    lib_mod.addImport("test_tag", sentinel_tag_mod);
    lib_mod.addImport("caps", caps_runner_mod);
    lib_mod.addImport("errors", errors_runner_mod);
    lib_mod.addImport("syscall", runner_syscall_mod);

    // Test ELF flavor of syscall — extern decls + bootstrap raw asm.
    const syscall_extern_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "../../libz/syscall_extern.zig" },
        .target = target_dynlink,
        .optimize = .ReleaseSmall,
        .pic = true,
        .omit_frame_pointer = true,
        .single_threaded = true,
    });

    const libz = addLibz(b, cpu_arch);
    const libz_loader_src: std.Build.LazyPath = .{ .cwd_relative = "../../libz/loader.zig" };

    const ctx = TestBuildCtx{
        .target_freestanding = target_freestanding,
        .target_dynlink = target_dynlink,
        .libz = libz,
        .libz_loader_src = libz_loader_src,
        .caps_mod = caps_dynlink_mod,
        .errors_mod = errors_dynlink_mod,
        .syscall_extern_mod = syscall_extern_mod,
    };

    const embedded_wf = b.addWriteFiles();
    const tag_wf = b.addWriteFiles();
    const test_elfs = b.allocator.alloc(std.Build.LazyPath, selected_entries.len) catch
        @panic("OOM allocating test_elfs");
    // Each tag is namespaced under TAG_MAGIC (high u16 bit) so that the
    // runner can discriminate genuine `testing.report` events from
    // incidental suspensions that happen to land on the result port
    // with rsi=0 (or other small accidental values). A test with
    // manifest index `i` gets `tag = TAG_MAGIC | i`. Sentinel TAG =
    // 0xFFFF (used by libz consumers that aren't tests) also has the
    // high bit set but maps to an out-of-range index, so it is dropped
    // by the runner's bounds check just like before. Total test count
    // is bounded by 0x7FFF (32767) so the index never collides with
    // the magic bit.
    const tag_magic: u16 = 0x8000;
    for (selected_entries, 0..) |t, i| {
        const tag: u16 = @intCast(@as(u16, @intCast(i)) | tag_magic);
        test_elfs[i] = buildTestElf(b, ctx, tag_wf, t.name, t.path, tag);
        _ = embedded_wf.addCopyFile(test_elfs[i], b.fmt("{s}.elf", .{t.name}));
    }

    // Stage libz.elf into the runner's @embedFile namespace alongside
    // the test ELFs. The runner @embedFile's it and stages it into a
    // page_frame at startup via libz_loader.layoutAndPrelink.
    _ = embedded_wf.addCopyFile(libz.getEmittedBin(), "libz.elf");

    // Generate a manifest module surfacing the embedded ELFs as a
    // slice the primary iterates. Manifest order = spawn order = tag
    // index. Each entry's `tag` matches the value baked into that
    // ELF's libz/test_tag at build time, so the runner can decode the
    // suspend-event vreg into a manifest index in O(1).
    var manifest = std.array_list.Managed(u8).init(b.allocator);
    defer manifest.deinit();
    manifest.writer().print(
        "pub const TOTAL_TEST_COUNT: u16 = {d};\n\n",
        .{selected_entries.len},
    ) catch unreachable;
    manifest.appendSlice(
        \\pub const Entry = struct {
        \\    name: []const u8,
        \\    bytes: []const u8,
        \\    tag: u16,
        \\};
        \\
        \\pub const manifest = [_]Entry{
        \\
    ) catch unreachable;
    for (selected_entries, 0..) |t, i| {
        const manifest_tag: u16 = @intCast(@as(u16, @intCast(i)) | tag_magic);
        manifest.writer().print(
            "    .{{ .name = \"{s}\", .bytes = @embedFile(\"{s}.elf\"), .tag = {d} }},\n",
            .{ t.name, t.name, manifest_tag },
        ) catch unreachable;
    }
    manifest.appendSlice("};\n\n") catch unreachable;
    // Surface libz.elf to the runner via the same @embedFile root.
    manifest.appendSlice("pub const libz_elf = @embedFile(\"libz.elf\");\n") catch unreachable;
    // Comptime repeat count. Runner reads this to wrap its batch loop.
    manifest.writer().print(
        "pub const repeat: u32 = {d};\n",
        .{repeat},
    ) catch unreachable;
    const manifest_src = embedded_wf.add("embedded_tests.zig", manifest.items);

    const embedded_tests_mod = b.createModule(.{
        .root_source_file = manifest_src,
        .target = target_freestanding,
        .optimize = .ReleaseSmall,
    });

    const runner_libz_loader_mod = b.createModule(.{
        .root_source_file = libz_loader_src,
        .target = target_freestanding,
        .optimize = .ReleaseSmall,
        .pic = true,
        .single_threaded = true,
    });

    const app_mod = b.createModule(.{
        .root_source_file = b.path("runner/primary.zig"),
        .target = target_freestanding,
        .optimize = .ReleaseSmall,
        .pic = true,
        .omit_frame_pointer = true,
    });
    app_mod.addImport("lib", lib_mod);
    app_mod.addImport("embedded_tests", embedded_tests_mod);
    app_mod.addImport("libz_loader", runner_libz_loader_mod);

    const start_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "runner/start.zig" },
        .target = target_freestanding,
        .optimize = .ReleaseSmall,
        .pic = true,
        .omit_frame_pointer = true,
    });
    start_mod.addImport("lib", lib_mod);
    start_mod.addImport("app", app_mod);
    // Runner's start.zig sees the same libz_loader module, but its
    // bootstrap path is gated on a comptime check that's true only
    // for the dynamic-test ELFs (linkage != .static at compile time
    // is not directly observable, so runner/start.zig keys off whether
    // app declares RUNNER_STATIC; see that file's comment).
    start_mod.addImport("libz_loader", runner_libz_loader_mod);

    const exe = b.addExecutable(.{
        .name = "root_service",
        .root_module = start_mod,
        .linkage = .static,
    });
    exe.pie = true;
    exe.entry = .{ .symbol_name = "_start" };

    const install = b.addInstallFile(exe.getEmittedBin(), "../bin/root_service.elf");
    b.getInstallStep().dependOn(&install.step);

    // Install the individual test ELFs alongside for inspection.
    for (selected_entries, 0..) |t, i| {
        const path = b.fmt("../bin/{s}.elf", .{t.name});
        const inst = b.addInstallFile(test_elfs[i], path);
        b.getInstallStep().dependOn(&inst.step);
    }
    const inst_libz = b.addInstallFile(libz.getEmittedBin(), "../bin/libz.elf");
    b.getInstallStep().dependOn(&inst_libz.step);
}
