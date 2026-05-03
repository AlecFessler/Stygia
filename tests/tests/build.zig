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
    .{ .name = "ack_01", .path = "tests/ack_01.zig" },
    .{ .name = "ack_02", .path = "tests/ack_02.zig" },
    .{ .name = "ack_03", .path = "tests/ack_03.zig" },
    .{ .name = "ack_04", .path = "tests/ack_04.zig" },
    .{ .name = "ack_05", .path = "tests/ack_05.zig" },
    .{ .name = "ack_06", .path = "tests/ack_06.zig" },
    .{ .name = "ack_07", .path = "tests/ack_07.zig" },
    .{ .name = "ack_08", .path = "tests/ack_08.zig" },
    .{ .name = "acquire_ecs_01", .path = "tests/acquire_ecs_01.zig" },
    .{ .name = "acquire_ecs_02", .path = "tests/acquire_ecs_02.zig" },
    .{ .name = "acquire_ecs_03", .path = "tests/acquire_ecs_03.zig" },
    .{ .name = "acquire_ecs_04", .path = "tests/acquire_ecs_04.zig" },
    .{ .name = "acquire_ecs_05", .path = "tests/acquire_ecs_05.zig" },
    .{ .name = "acquire_ecs_06", .path = "tests/acquire_ecs_06.zig" },
    .{ .name = "acquire_ecs_07", .path = "tests/acquire_ecs_07.zig" },
    .{ .name = "acquire_vars_01", .path = "tests/acquire_vars_01.zig" },
    .{ .name = "acquire_vars_02", .path = "tests/acquire_vars_02.zig" },
    .{ .name = "acquire_vars_03", .path = "tests/acquire_vars_03.zig" },
    .{ .name = "acquire_vars_04", .path = "tests/acquire_vars_04.zig" },
    .{ .name = "acquire_vars_05", .path = "tests/acquire_vars_05.zig" },
    .{ .name = "acquire_vars_06", .path = "tests/acquire_vars_06.zig" },
    .{ .name = "acquire_vars_07", .path = "tests/acquire_vars_07.zig" },
    .{ .name = "affinity_01", .path = "tests/affinity_01.zig" },
    .{ .name = "affinity_02", .path = "tests/affinity_02.zig" },
    .{ .name = "affinity_03", .path = "tests/affinity_03.zig" },
    .{ .name = "affinity_04", .path = "tests/affinity_04.zig" },
    .{ .name = "affinity_05", .path = "tests/affinity_05.zig" },
    .{ .name = "affinity_06", .path = "tests/affinity_06.zig" },
    .{ .name = "bind_event_route_01", .path = "tests/bind_event_route_01.zig" },
    .{ .name = "bind_event_route_02", .path = "tests/bind_event_route_02.zig" },
    .{ .name = "bind_event_route_03", .path = "tests/bind_event_route_03.zig" },
    .{ .name = "bind_event_route_04", .path = "tests/bind_event_route_04.zig" },
    .{ .name = "bind_event_route_05", .path = "tests/bind_event_route_05.zig" },
    .{ .name = "bind_event_route_06", .path = "tests/bind_event_route_06.zig" },
    .{ .name = "bind_event_route_07", .path = "tests/bind_event_route_07.zig" },
    .{ .name = "bind_event_route_08", .path = "tests/bind_event_route_08.zig" },
    .{ .name = "bind_event_route_09", .path = "tests/bind_event_route_09.zig" },
    .{ .name = "bind_event_route_10", .path = "tests/bind_event_route_10.zig" },
    .{ .name = "clear_event_route_01", .path = "tests/clear_event_route_01.zig" },
    .{ .name = "clear_event_route_02", .path = "tests/clear_event_route_02.zig" },
    .{ .name = "clear_event_route_03", .path = "tests/clear_event_route_03.zig" },
    .{ .name = "clear_event_route_04", .path = "tests/clear_event_route_04.zig" },
    .{ .name = "clear_event_route_05", .path = "tests/clear_event_route_05.zig" },
    .{ .name = "clear_event_route_06", .path = "tests/clear_event_route_06.zig" },
    .{ .name = "clear_event_route_07", .path = "tests/clear_event_route_07.zig" },
    .{ .name = "create_capability_domain_01", .path = "tests/create_capability_domain_01.zig" },
    .{ .name = "create_capability_domain_02", .path = "tests/create_capability_domain_02.zig" },
    .{ .name = "create_capability_domain_03", .path = "tests/create_capability_domain_03.zig" },
    .{ .name = "create_capability_domain_04", .path = "tests/create_capability_domain_04.zig" },
    .{ .name = "create_capability_domain_05", .path = "tests/create_capability_domain_05.zig" },
    .{ .name = "create_capability_domain_06", .path = "tests/create_capability_domain_06.zig" },
    .{ .name = "create_capability_domain_07", .path = "tests/create_capability_domain_07.zig" },
    .{ .name = "create_capability_domain_08", .path = "tests/create_capability_domain_08.zig" },
    .{ .name = "create_capability_domain_09", .path = "tests/create_capability_domain_09.zig" },
    .{ .name = "create_capability_domain_10", .path = "tests/create_capability_domain_10.zig" },
    .{ .name = "create_capability_domain_11", .path = "tests/create_capability_domain_11.zig" },
    .{ .name = "create_capability_domain_12", .path = "tests/create_capability_domain_12.zig" },
    .{ .name = "create_capability_domain_13", .path = "tests/create_capability_domain_13.zig" },
    .{ .name = "create_capability_domain_14", .path = "tests/create_capability_domain_14.zig" },
    .{ .name = "create_capability_domain_15", .path = "tests/create_capability_domain_15.zig" },
    .{ .name = "create_capability_domain_16", .path = "tests/create_capability_domain_16.zig" },
    .{ .name = "create_capability_domain_17", .path = "tests/create_capability_domain_17.zig" },
    .{ .name = "create_capability_domain_18", .path = "tests/create_capability_domain_18.zig" },
    .{ .name = "create_capability_domain_19", .path = "tests/create_capability_domain_19.zig" },
    .{ .name = "create_capability_domain_20", .path = "tests/create_capability_domain_20.zig" },
    .{ .name = "create_capability_domain_21", .path = "tests/create_capability_domain_21.zig" },
    .{ .name = "create_capability_domain_22", .path = "tests/create_capability_domain_22.zig" },
    .{ .name = "create_capability_domain_23", .path = "tests/create_capability_domain_23.zig" },
    .{ .name = "create_capability_domain_24", .path = "tests/create_capability_domain_24.zig" },
    .{ .name = "create_capability_domain_25", .path = "tests/create_capability_domain_25.zig" },
    .{ .name = "create_capability_domain_26", .path = "tests/create_capability_domain_26.zig" },
    .{ .name = "create_capability_domain_27", .path = "tests/create_capability_domain_27.zig" },
    .{ .name = "create_capability_domain_28", .path = "tests/create_capability_domain_28.zig" },
    .{ .name = "create_capability_domain_29", .path = "tests/create_capability_domain_29.zig" },
    .{ .name = "create_capability_domain_16a", .path = "tests/create_capability_domain_16a.zig" },
    .{ .name = "create_capability_domain_30", .path = "tests/create_capability_domain_30.zig" },
    .{ .name = "create_capability_domain_31", .path = "tests/create_capability_domain_31.zig" },
    .{ .name = "create_capability_domain_32", .path = "tests/create_capability_domain_32.zig" },
    .{ .name = "create_execution_context_01", .path = "tests/create_execution_context_01.zig" },
    .{ .name = "create_execution_context_02", .path = "tests/create_execution_context_02.zig" },
    .{ .name = "create_execution_context_03", .path = "tests/create_execution_context_03.zig" },
    .{ .name = "create_execution_context_04", .path = "tests/create_execution_context_04.zig" },
    .{ .name = "create_execution_context_05", .path = "tests/create_execution_context_05.zig" },
    .{ .name = "create_execution_context_06", .path = "tests/create_execution_context_06.zig" },
    .{ .name = "create_execution_context_07", .path = "tests/create_execution_context_07.zig" },
    .{ .name = "create_execution_context_08", .path = "tests/create_execution_context_08.zig" },
    .{ .name = "create_execution_context_09", .path = "tests/create_execution_context_09.zig" },
    .{ .name = "create_execution_context_10", .path = "tests/create_execution_context_10.zig" },
    .{ .name = "create_execution_context_11", .path = "tests/create_execution_context_11.zig" },
    .{ .name = "create_execution_context_12", .path = "tests/create_execution_context_12.zig" },
    .{ .name = "create_execution_context_13", .path = "tests/create_execution_context_13.zig" },
    .{ .name = "create_execution_context_14", .path = "tests/create_execution_context_14.zig" },
    .{ .name = "create_execution_context_15", .path = "tests/create_execution_context_15.zig" },
    .{ .name = "create_page_frame_01", .path = "tests/create_page_frame_01.zig" },
    .{ .name = "create_page_frame_02", .path = "tests/create_page_frame_02.zig" },
    .{ .name = "create_page_frame_03", .path = "tests/create_page_frame_03.zig" },
    .{ .name = "create_page_frame_04", .path = "tests/create_page_frame_04.zig" },
    .{ .name = "create_page_frame_05", .path = "tests/create_page_frame_05.zig" },
    .{ .name = "create_page_frame_06", .path = "tests/create_page_frame_06.zig" },
    .{ .name = "create_page_frame_07", .path = "tests/create_page_frame_07.zig" },
    .{ .name = "create_page_frame_08", .path = "tests/create_page_frame_08.zig" },
    .{ .name = "create_page_frame_09", .path = "tests/create_page_frame_09.zig" },
    .{ .name = "create_page_frame_10", .path = "tests/create_page_frame_10.zig" },
    .{ .name = "create_port_01", .path = "tests/create_port_01.zig" },
    .{ .name = "create_port_02", .path = "tests/create_port_02.zig" },
    .{ .name = "create_port_03", .path = "tests/create_port_03.zig" },
    .{ .name = "create_port_04", .path = "tests/create_port_04.zig" },
    .{ .name = "create_var_01", .path = "tests/create_var_01.zig" },
    .{ .name = "create_var_02", .path = "tests/create_var_02.zig" },
    .{ .name = "create_var_03", .path = "tests/create_var_03.zig" },
    .{ .name = "create_var_04", .path = "tests/create_var_04.zig" },
    .{ .name = "create_var_05", .path = "tests/create_var_05.zig" },
    .{ .name = "create_var_06", .path = "tests/create_var_06.zig" },
    .{ .name = "create_var_07", .path = "tests/create_var_07.zig" },
    .{ .name = "create_var_08", .path = "tests/create_var_08.zig" },
    .{ .name = "create_var_09", .path = "tests/create_var_09.zig" },
    .{ .name = "create_var_10", .path = "tests/create_var_10.zig" },
    .{ .name = "create_var_11", .path = "tests/create_var_11.zig" },
    .{ .name = "create_var_12", .path = "tests/create_var_12.zig" },
    .{ .name = "create_var_13", .path = "tests/create_var_13.zig" },
    .{ .name = "create_var_14", .path = "tests/create_var_14.zig" },
    .{ .name = "create_var_15", .path = "tests/create_var_15.zig" },
    .{ .name = "create_var_16", .path = "tests/create_var_16.zig" },
    .{ .name = "create_var_17", .path = "tests/create_var_17.zig" },
    .{ .name = "create_var_18", .path = "tests/create_var_18.zig" },
    .{ .name = "create_var_19", .path = "tests/create_var_19.zig" },
    .{ .name = "create_var_20", .path = "tests/create_var_20.zig" },
    .{ .name = "create_var_21", .path = "tests/create_var_21.zig" },
    .{ .name = "create_var_22", .path = "tests/create_var_22.zig" },
    .{ .name = "create_var_23", .path = "tests/create_var_23.zig" },
    .{ .name = "create_var_24", .path = "tests/create_var_24.zig" },
    .{ .name = "create_vcpu_01", .path = "tests/create_vcpu_01.zig" },
    .{ .name = "create_vcpu_02", .path = "tests/create_vcpu_02.zig" },
    .{ .name = "create_vcpu_03", .path = "tests/create_vcpu_03.zig" },
    .{ .name = "create_vcpu_04", .path = "tests/create_vcpu_04.zig" },
    .{ .name = "create_vcpu_05", .path = "tests/create_vcpu_05.zig" },
    .{ .name = "create_vcpu_06", .path = "tests/create_vcpu_06.zig" },
    .{ .name = "create_vcpu_07", .path = "tests/create_vcpu_07.zig" },
    .{ .name = "create_vcpu_08", .path = "tests/create_vcpu_08.zig" },
    .{ .name = "create_vcpu_09", .path = "tests/create_vcpu_09.zig" },
    .{ .name = "create_vcpu_10", .path = "tests/create_vcpu_10.zig" },
    .{ .name = "create_vcpu_11", .path = "tests/create_vcpu_11.zig" },
    .{ .name = "create_vcpu_12", .path = "tests/create_vcpu_12.zig" },
    .{ .name = "create_virtual_machine_01", .path = "tests/create_virtual_machine_01.zig" },
    .{ .name = "create_virtual_machine_02", .path = "tests/create_virtual_machine_02.zig" },
    .{ .name = "create_virtual_machine_03", .path = "tests/create_virtual_machine_03.zig" },
    .{ .name = "create_virtual_machine_04", .path = "tests/create_virtual_machine_04.zig" },
    .{ .name = "create_virtual_machine_05", .path = "tests/create_virtual_machine_05.zig" },
    .{ .name = "create_virtual_machine_06", .path = "tests/create_virtual_machine_06.zig" },
    .{ .name = "create_virtual_machine_07", .path = "tests/create_virtual_machine_07.zig" },
    .{ .name = "create_virtual_machine_08", .path = "tests/create_virtual_machine_08.zig" },
    .{ .name = "create_virtual_machine_09", .path = "tests/create_virtual_machine_09.zig" },
    .{ .name = "delete_01", .path = "tests/delete_01.zig" },
    .{ .name = "delete_02", .path = "tests/delete_02.zig" },
    .{ .name = "delete_03", .path = "tests/delete_03.zig" },
    .{ .name = "device_irq_01", .path = "tests/device_irq_01.zig" },
    .{ .name = "device_irq_02", .path = "tests/device_irq_02.zig" },
    .{ .name = "device_irq_03", .path = "tests/device_irq_03.zig" },
    .{ .name = "device_irq_04", .path = "tests/device_irq_04.zig" },
    .{ .name = "futex_wait_change_01", .path = "tests/futex_wait_change_01.zig" },
    .{ .name = "futex_wait_change_02", .path = "tests/futex_wait_change_02.zig" },
    .{ .name = "futex_wait_change_03", .path = "tests/futex_wait_change_03.zig" },
    .{ .name = "futex_wait_change_04", .path = "tests/futex_wait_change_04.zig" },
    .{ .name = "futex_wait_change_05", .path = "tests/futex_wait_change_05.zig" },
    .{ .name = "futex_wait_change_06", .path = "tests/futex_wait_change_06.zig" },
    .{ .name = "futex_wait_change_07", .path = "tests/futex_wait_change_07.zig" },
    .{ .name = "futex_wait_change_08", .path = "tests/futex_wait_change_08.zig" },
    .{ .name = "futex_wait_val_01", .path = "tests/futex_wait_val_01.zig" },
    .{ .name = "futex_wait_val_02", .path = "tests/futex_wait_val_02.zig" },
    .{ .name = "futex_wait_val_03", .path = "tests/futex_wait_val_03.zig" },
    .{ .name = "futex_wait_val_04", .path = "tests/futex_wait_val_04.zig" },
    .{ .name = "futex_wait_val_05", .path = "tests/futex_wait_val_05.zig" },
    .{ .name = "futex_wait_val_06", .path = "tests/futex_wait_val_06.zig" },
    .{ .name = "futex_wait_val_07", .path = "tests/futex_wait_val_07.zig" },
    .{ .name = "futex_wait_val_08", .path = "tests/futex_wait_val_08.zig" },
    .{ .name = "futex_wake_01", .path = "tests/futex_wake_01.zig" },
    .{ .name = "futex_wake_02", .path = "tests/futex_wake_02.zig" },
    .{ .name = "futex_wake_03", .path = "tests/futex_wake_03.zig" },
    .{ .name = "futex_wake_04", .path = "tests/futex_wake_04.zig" },
    .{ .name = "handle_attachments_01", .path = "tests/handle_attachments_01.zig" },
    .{ .name = "handle_attachments_02", .path = "tests/handle_attachments_02.zig" },
    .{ .name = "handle_attachments_03", .path = "tests/handle_attachments_03.zig" },
    .{ .name = "handle_attachments_04", .path = "tests/handle_attachments_04.zig" },
    .{ .name = "handle_attachments_05", .path = "tests/handle_attachments_05.zig" },
    .{ .name = "handle_attachments_06", .path = "tests/handle_attachments_06.zig" },
    .{ .name = "handle_attachments_07", .path = "tests/handle_attachments_07.zig" },
    .{ .name = "handle_attachments_08", .path = "tests/handle_attachments_08.zig" },
    .{ .name = "handle_attachments_09", .path = "tests/handle_attachments_09.zig" },
    .{ .name = "handle_attachments_10", .path = "tests/handle_attachments_10.zig" },
    .{ .name = "idc_read_01", .path = "tests/idc_read_01.zig" },
    .{ .name = "idc_read_02", .path = "tests/idc_read_02.zig" },
    .{ .name = "idc_read_03", .path = "tests/idc_read_03.zig" },
    .{ .name = "idc_read_04", .path = "tests/idc_read_04.zig" },
    .{ .name = "idc_read_05", .path = "tests/idc_read_05.zig" },
    .{ .name = "idc_read_06", .path = "tests/idc_read_06.zig" },
    .{ .name = "idc_read_07", .path = "tests/idc_read_07.zig" },
    .{ .name = "idc_read_08", .path = "tests/idc_read_08.zig" },
    .{ .name = "idc_write_01", .path = "tests/idc_write_01.zig" },
    .{ .name = "idc_write_02", .path = "tests/idc_write_02.zig" },
    .{ .name = "idc_write_03", .path = "tests/idc_write_03.zig" },
    .{ .name = "idc_write_04", .path = "tests/idc_write_04.zig" },
    .{ .name = "idc_write_05", .path = "tests/idc_write_05.zig" },
    .{ .name = "idc_write_06", .path = "tests/idc_write_06.zig" },
    .{ .name = "idc_write_07", .path = "tests/idc_write_07.zig" },
    .{ .name = "idc_write_08", .path = "tests/idc_write_08.zig" },
    .{ .name = "map_guest_01", .path = "tests/map_guest_01.zig" },
    .{ .name = "map_guest_02", .path = "tests/map_guest_02.zig" },
    .{ .name = "map_guest_03", .path = "tests/map_guest_03.zig" },
    .{ .name = "map_guest_04", .path = "tests/map_guest_04.zig" },
    .{ .name = "map_guest_05", .path = "tests/map_guest_05.zig" },
    .{ .name = "map_guest_06", .path = "tests/map_guest_06.zig" },
    .{ .name = "map_guest_07", .path = "tests/map_guest_07.zig" },
    .{ .name = "map_mmio_01", .path = "tests/map_mmio_01.zig" },
    .{ .name = "map_mmio_02", .path = "tests/map_mmio_02.zig" },
    .{ .name = "map_mmio_03", .path = "tests/map_mmio_03.zig" },
    .{ .name = "map_mmio_04", .path = "tests/map_mmio_04.zig" },
    .{ .name = "map_mmio_05", .path = "tests/map_mmio_05.zig" },
    .{ .name = "map_mmio_06", .path = "tests/map_mmio_06.zig" },
    .{ .name = "map_mmio_07", .path = "tests/map_mmio_07.zig" },
    .{ .name = "map_mmio_08", .path = "tests/map_mmio_08.zig" },
    .{ .name = "map_mmio_09", .path = "tests/map_mmio_09.zig" },
    .{ .name = "map_pf_01", .path = "tests/map_pf_01.zig" },
    .{ .name = "map_pf_02", .path = "tests/map_pf_02.zig" },
    .{ .name = "map_pf_03", .path = "tests/map_pf_03.zig" },
    .{ .name = "map_pf_04", .path = "tests/map_pf_04.zig" },
    .{ .name = "map_pf_05", .path = "tests/map_pf_05.zig" },
    .{ .name = "map_pf_06", .path = "tests/map_pf_06.zig" },
    .{ .name = "map_pf_07", .path = "tests/map_pf_07.zig" },
    .{ .name = "map_pf_08", .path = "tests/map_pf_08.zig" },
    .{ .name = "map_pf_09", .path = "tests/map_pf_09.zig" },
    .{ .name = "map_pf_10", .path = "tests/map_pf_10.zig" },
    .{ .name = "map_pf_11", .path = "tests/map_pf_11.zig" },
    .{ .name = "map_pf_12", .path = "tests/map_pf_12.zig" },
    .{ .name = "map_pf_13", .path = "tests/map_pf_13.zig" },
    .{ .name = "map_pf_14", .path = "tests/map_pf_14.zig" },
    .{ .name = "perfmon_info_01", .path = "tests/perfmon_info_01.zig" },
    .{ .name = "perfmon_info_02", .path = "tests/perfmon_info_02.zig" },
    .{ .name = "perfmon_info_03", .path = "tests/perfmon_info_03.zig" },
    .{ .name = "perfmon_info_04", .path = "tests/perfmon_info_04.zig" },
    .{ .name = "perfmon_read_01", .path = "tests/perfmon_read_01.zig" },
    .{ .name = "perfmon_read_02", .path = "tests/perfmon_read_02.zig" },
    .{ .name = "perfmon_read_03", .path = "tests/perfmon_read_03.zig" },
    .{ .name = "perfmon_read_04", .path = "tests/perfmon_read_04.zig" },
    .{ .name = "perfmon_read_05", .path = "tests/perfmon_read_05.zig" },
    .{ .name = "perfmon_read_06", .path = "tests/perfmon_read_06.zig" },
    .{ .name = "perfmon_read_07", .path = "tests/perfmon_read_07.zig" },
    .{ .name = "perfmon_start_01", .path = "tests/perfmon_start_01.zig" },
    .{ .name = "perfmon_start_02", .path = "tests/perfmon_start_02.zig" },
    .{ .name = "perfmon_start_03", .path = "tests/perfmon_start_03.zig" },
    .{ .name = "perfmon_start_04", .path = "tests/perfmon_start_04.zig" },
    .{ .name = "perfmon_start_05", .path = "tests/perfmon_start_05.zig" },
    .{ .name = "perfmon_start_06", .path = "tests/perfmon_start_06.zig" },
    .{ .name = "perfmon_start_07", .path = "tests/perfmon_start_07.zig" },
    .{ .name = "perfmon_start_08", .path = "tests/perfmon_start_08.zig" },
    .{ .name = "perfmon_start_09", .path = "tests/perfmon_start_09.zig" },
    .{ .name = "perfmon_stop_01", .path = "tests/perfmon_stop_01.zig" },
    .{ .name = "perfmon_stop_02", .path = "tests/perfmon_stop_02.zig" },
    .{ .name = "perfmon_stop_03", .path = "tests/perfmon_stop_03.zig" },
    .{ .name = "perfmon_stop_04", .path = "tests/perfmon_stop_04.zig" },
    .{ .name = "perfmon_stop_05", .path = "tests/perfmon_stop_05.zig" },
    .{ .name = "perfmon_stop_06", .path = "tests/perfmon_stop_06.zig" },
    .{ .name = "port_io_virtualization_01", .path = "tests/port_io_virtualization_01.zig" },
    .{ .name = "port_io_virtualization_02", .path = "tests/port_io_virtualization_02.zig" },
    .{ .name = "port_io_virtualization_03", .path = "tests/port_io_virtualization_03.zig" },
    .{ .name = "port_io_virtualization_04", .path = "tests/port_io_virtualization_04.zig" },
    .{ .name = "port_io_virtualization_05", .path = "tests/port_io_virtualization_05.zig" },
    .{ .name = "port_io_virtualization_06", .path = "tests/port_io_virtualization_06.zig" },
    .{ .name = "port_io_virtualization_07", .path = "tests/port_io_virtualization_07.zig" },
    .{ .name = "port_io_virtualization_08", .path = "tests/port_io_virtualization_08.zig" },
    .{ .name = "port_io_virtualization_09", .path = "tests/port_io_virtualization_09.zig" },
    .{ .name = "port_io_virtualization_10", .path = "tests/port_io_virtualization_10.zig" },
    .{ .name = "port_io_virtualization_11", .path = "tests/port_io_virtualization_11.zig" },
    .{ .name = "power_01", .path = "tests/power_01.zig" },
    .{ .name = "power_02", .path = "tests/power_02.zig" },
    .{ .name = "power_03", .path = "tests/power_03.zig" },
    .{ .name = "power_04", .path = "tests/power_04.zig" },
    .{ .name = "power_05", .path = "tests/power_05.zig" },
    .{ .name = "power_06", .path = "tests/power_06.zig" },
    .{ .name = "power_07", .path = "tests/power_07.zig" },
    .{ .name = "power_08", .path = "tests/power_08.zig" },
    .{ .name = "power_09", .path = "tests/power_09.zig" },
    .{ .name = "power_10", .path = "tests/power_10.zig" },
    .{ .name = "power_11", .path = "tests/power_11.zig" },
    .{ .name = "power_12", .path = "tests/power_12.zig" },
    .{ .name = "power_13", .path = "tests/power_13.zig" },
    .{ .name = "power_14", .path = "tests/power_14.zig" },
    .{ .name = "power_15", .path = "tests/power_15.zig" },
    .{ .name = "priority_01", .path = "tests/priority_01.zig" },
    .{ .name = "priority_02", .path = "tests/priority_02.zig" },
    .{ .name = "priority_03", .path = "tests/priority_03.zig" },
    .{ .name = "priority_04", .path = "tests/priority_04.zig" },
    .{ .name = "priority_05", .path = "tests/priority_05.zig" },
    .{ .name = "priority_06", .path = "tests/priority_06.zig" },
    .{ .name = "priority_07", .path = "tests/priority_07.zig" },
    .{ .name = "priority_08", .path = "tests/priority_08.zig" },
    .{ .name = "recv_01", .path = "tests/recv_01.zig" },
    .{ .name = "recv_02", .path = "tests/recv_02.zig" },
    .{ .name = "recv_03", .path = "tests/recv_03.zig" },
    .{ .name = "recv_04", .path = "tests/recv_04.zig" },
    .{ .name = "recv_05", .path = "tests/recv_05.zig" },
    .{ .name = "recv_06", .path = "tests/recv_06.zig" },
    .{ .name = "recv_07", .path = "tests/recv_07.zig" },
    .{ .name = "recv_08", .path = "tests/recv_08.zig" },
    .{ .name = "recv_09", .path = "tests/recv_09.zig" },
    .{ .name = "recv_10", .path = "tests/recv_10.zig" },
    .{ .name = "recv_11", .path = "tests/recv_11.zig" },
    .{ .name = "recv_12", .path = "tests/recv_12.zig" },
    .{ .name = "recv_13", .path = "tests/recv_13.zig" },
    .{ .name = "recv_14", .path = "tests/recv_14.zig" },
    .{ .name = "recv_15", .path = "tests/recv_15.zig" },
    .{ .name = "recv_16", .path = "tests/recv_16.zig" },
    .{ .name = "remap_01", .path = "tests/remap_01.zig" },
    .{ .name = "remap_02", .path = "tests/remap_02.zig" },
    .{ .name = "remap_03", .path = "tests/remap_03.zig" },
    .{ .name = "remap_04", .path = "tests/remap_04.zig" },
    .{ .name = "remap_05", .path = "tests/remap_05.zig" },
    .{ .name = "remap_06", .path = "tests/remap_06.zig" },
    .{ .name = "remap_07", .path = "tests/remap_07.zig" },
    .{ .name = "remap_08", .path = "tests/remap_08.zig" },
    .{ .name = "remap_09", .path = "tests/remap_09.zig" },
    .{ .name = "reply_01", .path = "tests/reply_01.zig" },
    .{ .name = "reply_02", .path = "tests/reply_02.zig" },
    .{ .name = "reply_03", .path = "tests/reply_03.zig" },
    .{ .name = "reply_04", .path = "tests/reply_04.zig" },
    .{ .name = "reply_05", .path = "tests/reply_05.zig" },
    .{ .name = "reply_06", .path = "tests/reply_06.zig" },
    .{ .name = "reply_07", .path = "tests/reply_07.zig" },
    .{ .name = "reply_transfer_01", .path = "tests/reply_transfer_01.zig" },
    .{ .name = "reply_transfer_02", .path = "tests/reply_transfer_02.zig" },
    .{ .name = "reply_transfer_03", .path = "tests/reply_transfer_03.zig" },
    .{ .name = "reply_transfer_04", .path = "tests/reply_transfer_04.zig" },
    .{ .name = "reply_transfer_05", .path = "tests/reply_transfer_05.zig" },
    .{ .name = "reply_transfer_06", .path = "tests/reply_transfer_06.zig" },
    .{ .name = "reply_transfer_07", .path = "tests/reply_transfer_07.zig" },
    .{ .name = "reply_transfer_08", .path = "tests/reply_transfer_08.zig" },
    .{ .name = "reply_transfer_09", .path = "tests/reply_transfer_09.zig" },
    .{ .name = "reply_transfer_10", .path = "tests/reply_transfer_10.zig" },
    .{ .name = "reply_transfer_11", .path = "tests/reply_transfer_11.zig" },
    .{ .name = "reply_transfer_12", .path = "tests/reply_transfer_12.zig" },
    .{ .name = "reply_transfer_13", .path = "tests/reply_transfer_13.zig" },
    .{ .name = "reply_transfer_14", .path = "tests/reply_transfer_14.zig" },
    .{ .name = "reply_transfer_15", .path = "tests/reply_transfer_15.zig" },
    .{ .name = "restart_semantics_01", .path = "tests/restart_semantics_01.zig" },
    .{ .name = "restart_semantics_02", .path = "tests/restart_semantics_02.zig" },
    .{ .name = "restart_semantics_03", .path = "tests/restart_semantics_03.zig" },
    .{ .name = "restart_semantics_04", .path = "tests/restart_semantics_04.zig" },
    .{ .name = "restart_semantics_05", .path = "tests/restart_semantics_05.zig" },
    .{ .name = "restart_semantics_06", .path = "tests/restart_semantics_06.zig" },
    .{ .name = "restart_semantics_07", .path = "tests/restart_semantics_07.zig" },
    .{ .name = "restart_semantics_08", .path = "tests/restart_semantics_08.zig" },
    .{ .name = "restrict_01", .path = "tests/restrict_01.zig" },
    .{ .name = "restrict_02", .path = "tests/restrict_02.zig" },
    .{ .name = "restrict_03", .path = "tests/restrict_03.zig" },
    .{ .name = "restrict_04", .path = "tests/restrict_04.zig" },
    .{ .name = "restrict_05", .path = "tests/restrict_05.zig" },
    .{ .name = "restrict_06", .path = "tests/restrict_06.zig" },
    .{ .name = "restrict_07", .path = "tests/restrict_07.zig" },
    .{ .name = "revoke_01", .path = "tests/revoke_01.zig" },
    .{ .name = "revoke_02", .path = "tests/revoke_02.zig" },
    .{ .name = "revoke_03", .path = "tests/revoke_03.zig" },
    .{ .name = "revoke_04", .path = "tests/revoke_04.zig" },
    .{ .name = "revoke_05", .path = "tests/revoke_05.zig" },
    .{ .name = "revoke_06", .path = "tests/revoke_06.zig" },
    .{ .name = "rng_01", .path = "tests/rng_01.zig" },
    .{ .name = "rng_02", .path = "tests/rng_02.zig" },
    .{ .name = "self_01", .path = "tests/self_01.zig" },
    .{ .name = "self_02", .path = "tests/self_02.zig" },
    .{ .name = "self_handle_01", .path = "tests/self_handle_01.zig" },
    .{ .name = "snapshot_01", .path = "tests/snapshot_01.zig" },
    .{ .name = "snapshot_02", .path = "tests/snapshot_02.zig" },
    .{ .name = "snapshot_03", .path = "tests/snapshot_03.zig" },
    .{ .name = "snapshot_04", .path = "tests/snapshot_04.zig" },
    .{ .name = "snapshot_05", .path = "tests/snapshot_05.zig" },
    .{ .name = "snapshot_06", .path = "tests/snapshot_06.zig" },
    .{ .name = "snapshot_07", .path = "tests/snapshot_07.zig" },
    .{ .name = "snapshot_08", .path = "tests/snapshot_08.zig" },
    .{ .name = "snapshot_09", .path = "tests/snapshot_09.zig" },
    .{ .name = "snapshot_10", .path = "tests/snapshot_10.zig" },
    .{ .name = "snapshot_11", .path = "tests/snapshot_11.zig" },
    .{ .name = "suspend_01", .path = "tests/suspend_01.zig" },
    .{ .name = "suspend_02", .path = "tests/suspend_02.zig" },
    .{ .name = "suspend_03", .path = "tests/suspend_03.zig" },
    .{ .name = "suspend_04", .path = "tests/suspend_04.zig" },
    .{ .name = "suspend_05", .path = "tests/suspend_05.zig" },
    .{ .name = "suspend_06", .path = "tests/suspend_06.zig" },
    .{ .name = "suspend_07", .path = "tests/suspend_07.zig" },
    .{ .name = "suspend_08", .path = "tests/suspend_08.zig" },
    .{ .name = "suspend_09", .path = "tests/suspend_09.zig" },
    .{ .name = "suspend_10", .path = "tests/suspend_10.zig" },
    .{ .name = "suspend_11", .path = "tests/suspend_11.zig" },
    .{ .name = "suspend_12", .path = "tests/suspend_12.zig" },
    .{ .name = "sync_01", .path = "tests/sync_01.zig" },
    .{ .name = "sync_02", .path = "tests/sync_02.zig" },
    .{ .name = "sync_03", .path = "tests/sync_03.zig" },
    .{ .name = "system_info_01", .path = "tests/system_info_01.zig" },
    .{ .name = "system_info_02", .path = "tests/system_info_02.zig" },
    .{ .name = "system_info_03", .path = "tests/system_info_03.zig" },
    .{ .name = "system_info_04", .path = "tests/system_info_04.zig" },
    .{ .name = "system_info_05", .path = "tests/system_info_05.zig" },
    .{ .name = "system_info_06", .path = "tests/system_info_06.zig" },
    .{ .name = "terminate_01", .path = "tests/terminate_01.zig" },
    .{ .name = "terminate_02", .path = "tests/terminate_02.zig" },
    .{ .name = "terminate_03", .path = "tests/terminate_03.zig" },
    .{ .name = "terminate_04", .path = "tests/terminate_04.zig" },
    .{ .name = "terminate_05", .path = "tests/terminate_05.zig" },
    .{ .name = "terminate_06", .path = "tests/terminate_06.zig" },
    .{ .name = "terminate_07", .path = "tests/terminate_07.zig" },
    .{ .name = "terminate_08", .path = "tests/terminate_08.zig" },
    .{ .name = "time_01", .path = "tests/time_01.zig" },
    .{ .name = "time_02", .path = "tests/time_02.zig" },
    .{ .name = "time_03", .path = "tests/time_03.zig" },
    .{ .name = "time_04", .path = "tests/time_04.zig" },
    .{ .name = "time_05", .path = "tests/time_05.zig" },
    .{ .name = "timer_arm_01", .path = "tests/timer_arm_01.zig" },
    .{ .name = "timer_arm_02", .path = "tests/timer_arm_02.zig" },
    .{ .name = "timer_arm_03", .path = "tests/timer_arm_03.zig" },
    .{ .name = "timer_arm_04", .path = "tests/timer_arm_04.zig" },
    .{ .name = "timer_arm_05", .path = "tests/timer_arm_05.zig" },
    .{ .name = "timer_arm_06", .path = "tests/timer_arm_06.zig" },
    .{ .name = "timer_arm_07", .path = "tests/timer_arm_07.zig" },
    .{ .name = "timer_arm_08", .path = "tests/timer_arm_08.zig" },
    .{ .name = "timer_arm_09", .path = "tests/timer_arm_09.zig" },
    .{ .name = "timer_arm_10", .path = "tests/timer_arm_10.zig" },
    .{ .name = "timer_cancel_01", .path = "tests/timer_cancel_01.zig" },
    .{ .name = "timer_cancel_02", .path = "tests/timer_cancel_02.zig" },
    .{ .name = "timer_cancel_03", .path = "tests/timer_cancel_03.zig" },
    .{ .name = "timer_cancel_04", .path = "tests/timer_cancel_04.zig" },
    .{ .name = "timer_cancel_05", .path = "tests/timer_cancel_05.zig" },
    .{ .name = "timer_cancel_06", .path = "tests/timer_cancel_06.zig" },
    .{ .name = "timer_cancel_07", .path = "tests/timer_cancel_07.zig" },
    .{ .name = "timer_cancel_08", .path = "tests/timer_cancel_08.zig" },
    .{ .name = "timer_cancel_09", .path = "tests/timer_cancel_09.zig" },
    .{ .name = "timer_rearm_01", .path = "tests/timer_rearm_01.zig" },
    .{ .name = "timer_rearm_02", .path = "tests/timer_rearm_02.zig" },
    .{ .name = "timer_rearm_03", .path = "tests/timer_rearm_03.zig" },
    .{ .name = "timer_rearm_04", .path = "tests/timer_rearm_04.zig" },
    .{ .name = "timer_rearm_05", .path = "tests/timer_rearm_05.zig" },
    .{ .name = "timer_rearm_06", .path = "tests/timer_rearm_06.zig" },
    .{ .name = "timer_rearm_07", .path = "tests/timer_rearm_07.zig" },
    .{ .name = "timer_rearm_08", .path = "tests/timer_rearm_08.zig" },
    .{ .name = "timer_rearm_09", .path = "tests/timer_rearm_09.zig" },
    .{ .name = "timer_rearm_10", .path = "tests/timer_rearm_10.zig" },
    .{ .name = "unmap_01", .path = "tests/unmap_01.zig" },
    .{ .name = "unmap_02", .path = "tests/unmap_02.zig" },
    .{ .name = "unmap_03", .path = "tests/unmap_03.zig" },
    .{ .name = "unmap_04", .path = "tests/unmap_04.zig" },
    .{ .name = "unmap_05", .path = "tests/unmap_05.zig" },
    .{ .name = "unmap_06", .path = "tests/unmap_06.zig" },
    .{ .name = "unmap_07", .path = "tests/unmap_07.zig" },
    .{ .name = "unmap_08", .path = "tests/unmap_08.zig" },
    .{ .name = "unmap_09", .path = "tests/unmap_09.zig" },
    .{ .name = "unmap_10", .path = "tests/unmap_10.zig" },
    .{ .name = "unmap_11", .path = "tests/unmap_11.zig" },
    .{ .name = "unmap_12", .path = "tests/unmap_12.zig" },
    .{ .name = "unmap_guest_01", .path = "tests/unmap_guest_01.zig" },
    .{ .name = "unmap_guest_02", .path = "tests/unmap_guest_02.zig" },
    .{ .name = "unmap_guest_03", .path = "tests/unmap_guest_03.zig" },
    .{ .name = "unmap_guest_04", .path = "tests/unmap_guest_04.zig" },
    .{ .name = "unmap_guest_05", .path = "tests/unmap_guest_05.zig" },
    .{ .name = "vm_inject_irq_01", .path = "tests/vm_inject_irq_01.zig" },
    .{ .name = "vm_inject_irq_02", .path = "tests/vm_inject_irq_02.zig" },
    .{ .name = "vm_inject_irq_03", .path = "tests/vm_inject_irq_03.zig" },
    .{ .name = "vm_inject_irq_04", .path = "tests/vm_inject_irq_04.zig" },
    .{ .name = "vm_inject_irq_05", .path = "tests/vm_inject_irq_05.zig" },
    .{ .name = "vm_set_policy_01", .path = "tests/vm_set_policy_01.zig" },
    .{ .name = "vm_set_policy_02", .path = "tests/vm_set_policy_02.zig" },
    .{ .name = "vm_set_policy_03", .path = "tests/vm_set_policy_03.zig" },
    .{ .name = "vm_set_policy_04", .path = "tests/vm_set_policy_04.zig" },
    .{ .name = "vm_set_policy_05", .path = "tests/vm_set_policy_05.zig" },
    .{ .name = "vm_set_policy_06", .path = "tests/vm_set_policy_06.zig" },
    .{ .name = "vm_set_policy_07", .path = "tests/vm_set_policy_07.zig" },
    .{ .name = "vm_set_policy_08", .path = "tests/vm_set_policy_08.zig" },
    .{ .name = "vm_set_policy_09", .path = "tests/vm_set_policy_09.zig" },
    .{ .name = "yield_01", .path = "tests/yield_01.zig" },
    .{ .name = "yield_02", .path = "tests/yield_02.zig" },
    .{ .name = "yield_03", .path = "tests/yield_03.zig" },
    .{ .name = "yield_04", .path = "tests/yield_04.zig" },
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

    // Per-test libz clone. Required because libz/testing.zig statically
    // imports test_tag and we need each test to see its own. The clone
    // shares source with libz/lib.zig but rewires test_tag.
    const test_lib_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "libz/lib.zig" },
        .target = ctx.target_dynlink,
        .optimize = .ReleaseSmall,
        .pic = true,
        .omit_frame_pointer = true,
        .single_threaded = true,
    });
    test_lib_mod.addImport("lib", test_lib_mod);
    test_lib_mod.addImport("test_tag", tag_mod);

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
        .root_source_file = .{ .cwd_relative = "libz/start.zig" },
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

    // Sentinel `test_tag` module for non-test consumers of libz (the
    // primary runner). The runner never calls `lib.testing.report`, but
    // libz/testing.zig statically `@import`s `test_tag`, so something
    // must satisfy the import. Sentinel TAG = 0xFFFF is reserved.
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

    // Runner libz: statically linked, wired to lib_static.zig — its
    // `syscall` namespace points at the top-level libz/syscall.zig
    // (full inline-asm bodies, no externs) via the `static_syscall`
    // module dep. The runner is the framework's bootstrap layer and
    // cannot itself depend on libz.elf — it's the one that stages
    // libz.elf into a page_frame for children.
    const static_syscall_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "../../libz/syscall.zig" },
        .target = target_freestanding,
        .optimize = .ReleaseSmall,
        .pic = true,
        .omit_frame_pointer = true,
    });
    const lib_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "libz/lib_static.zig" },
        .target = target_freestanding,
        .optimize = .ReleaseSmall,
        .pic = true,
        .omit_frame_pointer = true,
    });
    lib_mod.addImport("lib", lib_mod);
    lib_mod.addImport("test_tag", sentinel_tag_mod);
    lib_mod.addImport("static_syscall", static_syscall_mod);

    const libz = addLibz(b, cpu_arch);
    const libz_loader_src: std.Build.LazyPath = .{ .cwd_relative = "../../libz_loader/lib.zig" };

    const ctx = TestBuildCtx{
        .target_freestanding = target_freestanding,
        .target_dynlink = target_dynlink,
        .libz = libz,
        .libz_loader_src = libz_loader_src,
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
        .root_source_file = .{ .cwd_relative = "libz/start.zig" },
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
    // is not directly observable, so libz/start.zig keys off whether
    // app == primary; see that file's comment).
    start_mod.addImport("libz_loader", runner_libz_loader_mod);

    const exe = b.addExecutable(.{
        .name = "root_service",
        .root_module = start_mod,
        .linkage = .static,
    });
    exe.pie = true;
    exe.entry = .{ .symbol_name = "_start" };
    exe.setLinkerScript(b.path("linker.ld"));

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
