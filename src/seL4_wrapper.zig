const c = @import("cImports.zig");

pub const seL4Errors = error{
    NoError,
    InvalidArgument,
    InvalidCapability,
    IllegalOperation,
    RangeError,
    AlignmentError,
    FailedLookup,
    TruncatedMessage,
    DeleteFirst,
    RevokeFirst,
    NotEnoughMemory,
};

pub fn handle_error(err: c.seL4_Error) !void {
    switch (err) {
        c.seL4_NoError => return,
        c.seL4_InvalidArgument => return seL4Errors.InvalidArgument,
        c.seL4_InvalidCapability => return seL4Errors.InvalidCapability,
        c.seL4_IllegalOperation => return seL4Errors.IllegalOperation,
        c.seL4_RangeError => return seL4Errors.RangeError,
        c.seL4_AlignmentError => return seL4Errors.AlignmentError,
        c.seL4_FailedLookup => return seL4Errors.FailedLookup,
        c.seL4_TruncatedMessage => return seL4Errors.TruncatedMessage,
        c.seL4_DeleteFirst => return seL4Errors.DeleteFirst,
        c.seL4_RevokeFirst => return seL4Errors.RevokeFirst,
        c.seL4_NotEnoughMemory => return seL4Errors.NotEnoughMemory,
        else => return error.InvalidSeL4Error,
    }
}

pub fn X86_PDPT_Map(_service: c.seL4_X86_PDPT, pml4: c.seL4_X64_PML4, vaddr: c.seL4_Word, attr: c.seL4_X86_VMAttributes) !void {
    const res = c.zig_seL4_X86_PDPT_MAP(_service, pml4, vaddr, attr);
    try handle_error(res);
}
pub fn X86_PDPT_Unmap(_service: c.seL4_X86_PDPT) !void {
    const res = c.zig_seL4_X86_PDPT_Unmap(_service);
    try handle_error(res);
}
pub fn X86_PageDirectory_Map(_service: c.seL4_X86_PageDirectory, vspace: c.seL4_CPtr, vaddr: c.seL4_Word, attr: c.seL4_X86_VMAttributes) !void {
    const res = c.zig_seL4_X86_PageDirectory_Map(_service, vspace, vaddr, attr);
    try handle_error(res);
}
pub fn X86_PageDirectory_Unmap(_service: c.seL4_X86_PageDirectory) !void {
    const res = c.zig_seL4_X86_PageDirectory_Unmap(_service);
    try handle_error(res);
}
pub fn X86_PageTable_Map(_service: c.seL4_X86_PageTable, vspace: c.seL4_CPtr, vaddr: c.seL4_Word, attr: c.seL4_X86_VMAttributes) !void {
    const res = c.zig_seL4_X86_PageTable_Map(_service, vspace, vaddr, attr);
    try handle_error(res);
}
pub fn X86_PageTable_Unmap(_service: c.seL4_X86_PageTable) !void {
    const res = c.zig_seL4_X86_PageTable_Unmap(_service);
    try handle_error(res);
}
pub fn X86_Page_Map(_service: c.seL4_X86_Page, vspace: c.seL4_CPtr, vaddr: c.seL4_Word, rights: c.seL4_CapRights_t, attr: c.seL4_X86_VMAttributes) !void {
    const new_rights = .{ .caprights = rights, .dummy = .{0} ** 3 };
    const res = c.zig_seL4_X86_Page_Map(_service, vspace, vaddr, new_rights, attr);
    try handle_error(res);
}
pub fn X86_Page_Unmap(_service: c.seL4_X86_Page) !void {
    const res = c.zig_seL4_X86_Page_Unmap(_service);
    try handle_error(res);
}
pub fn X86_Page_GetAddress(_service: c.seL4_X86_Page) !c.seL4_Word {
    const res = c.zig_seL4_X86_Page_GetAddress(_service);
    try handle_error(res.@"error");
    return res.paddr;
}
pub fn X86_ASIDControl_MakePool(_service: c.seL4_X86_ASIDControl, untyped: c.seL4_Untyped, root: c.seL4_CNode, index: c.seL4_Word, depth: c.seL4_Uint8) !void {
    const res = c.zig_seL4_X86_ASIDControl_MakePool(_service, untyped, root, index, depth);
    try handle_error(res);
}
pub fn X86_ASIDPool_Assign(_service: c.seL4_X86_ASIDPool, vspace: c.seL4_CPtr) !void {
    const res = c.zig_seL4_X86_ASIDPool_Assign(_service, vspace);
    try handle_error(res);
}
pub fn X86_IOPortControl_Issue(_service: c.seL4_X86_IOPortControl, first_port: c.seL4_Word, last_port: c.seL4_Word, root: c.seL4_CNode, index: c.seL4_Word, depth: c.seL4_Uint8) !void {
    const res = c.zig_seL4_X86_IOPortControl_Issue(_service, first_port, last_port, root, index, depth);
    try handle_error(res);
}
pub fn X86_IOPort_In8(_service: c.seL4_X86_IOPort, port: c.seL4_Uint16) !c.seL4_Uint8 {
    const res = c.zig_seL4_X86_IOPort_In8(_service, port);
    try handle_error(res.@"error");
    return res.result;
}
pub fn X86_IOPort_In16(_service: c.seL4_X86_IOPort, port: c.seL4_Uint16) !c.seL4_Uint16 {
    const res = c.zig_seL4_X86_IOPort_In16(_service, port);
    try handle_error(res.@"error");
    return res.result;
}
pub fn X86_IOPort_In32(_service: c.seL4_X86_IOPort, port: c.seL4_Uint16) !c.seL4_Uint32 {
    const res = c.zig_seL4_X86_IOPort_In16(_service, port);
    try handle_error(res.@"error");
    return res.result;
}
pub fn X86_IOPort_Out8(_service: c.seL4_X86_IOPort, port: c.seL4_Word, data: c.seL4_Word) !void {
    const res = c.zig_seL4_X86_IOPort_Out8(_service, port, data);
    try handle_error(res);
}
pub fn X86_IOPort_Out16(_service: c.seL4_X86_IOPort, port: c.seL4_Word, data: c.seL4_Word) !void {
    const res = c.zig_seL4_X86_IOPort_Out16(_service, port, data);
    try handle_error(res);
}
pub fn X86_IOPort_Out32(_service: c.seL4_X86_IOPort, port: c.seL4_Word, data: c.seL4_Word) !void {
    const res = c.zig_seL4_X86_IOPort_Out32(_service, port, data);
    try handle_error(res);
}
pub fn IRQControl_GetIOAPIC(_service: c.seL4_IRQControl, root: c.seL4_CNode, index: c.seL4_Word, depth: c.seL4_Uint8, ioapic: c.seL4_Word, pin: c.seL4_Word, level: c.seL4_Word, polarity: c.seL4_Word, vector: c.seL4_Word) !void {
    const res = c.zig_seL4_IRQControl_GetIOAPIC(_service, root, index, depth, ioapic, pin, level, polarity, vector);
    try handle_error(res);
}
pub fn IRQControl_GetMSI(_service: c.seL4_IRQControl, root: c.seL4_CNode, index: c.seL4_Word, depth: c.seL4_Uint8, pci_bus: c.seL4_Word, pci_dev: c.seL4_Word, pci_func: c.seL4_Word, handle: c.seL4_Word, vector: c.seL4_Word) !void {
    const res = c.zig_seL4_IRQControl_GetMSI(_service, root, index, depth, pci_bus, pci_dev, pci_func, handle, vector);
    try handle_error(res);
}
pub fn Untyped_Retype(_service: c.seL4_Untyped, @"type": c.seL4_Word, size_bits: c.seL4_Word, root: c.seL4_CNode, node_index: c.seL4_Word, node_depth: c.seL4_Word, node_offset: c.seL4_Word, num_objects: c.seL4_Word) !void {
    const res = c.zig_seL4_Untyped_Retype(_service, @"type", size_bits, root, node_index, node_depth, node_offset, num_objects);
    try handle_error(res);
}
pub fn TCB_ReadRegisters(_service: c.seL4_TCB, suspend_source: c.seL4_Bool, arch_flags: c.seL4_Uint8, count: c.seL4_Word, regs: [*c]c.seL4_UserContext) !void {
    const res = c.zig_seL4_TCB_ReadRegisters(_service, suspend_source, arch_flags, count, regs);
    try handle_error(res);
}
pub fn TCB_WriteRegisters(_service: c.seL4_TCB, resume_target: c.seL4_Bool, arch_flags: c.seL4_Uint8, count: c.seL4_Word, regs: [*c]c.seL4_UserContext) !void {
    const res = c.zig_seL4_TCB_WriteRegisters(_service, resume_target, arch_flags, count, regs);
    try handle_error(res);
}
pub fn TCB_CopyRegisters(_service: c.seL4_TCB, source: c.seL4_TCB, suspend_source: c.seL4_Bool, resume_target: c.seL4_Bool, transfer_frame: c.seL4_Bool, transfer_integer: c.seL4_Bool, arch_flags: c.seL4_Uint8) !void {
    const res = c.zig_seL4_TCB_CopyRegisters(_service, source, suspend_source, resume_target, transfer_frame, transfer_integer, arch_flags);
    try handle_error(res);
}
pub fn TCB_Configure(_service: c.seL4_TCB, fault_ep: c.seL4_Word, cspace_root: c.seL4_CNode, cspace_root_data: c.seL4_Word, vspace_root: c.seL4_CPtr, vspace_root_data: c.seL4_Word, buffer: c.seL4_Word, bufferFrame: c.seL4_CPtr) !void {
    const res = c.zig_seL4_TCB_Configure(_service, fault_ep, cspace_root, cspace_root_data, vspace_root, vspace_root_data, buffer, bufferFrame);
    try handle_error(res);
}
pub fn TCB_SetPriority(_service: c.seL4_TCB, authority: c.seL4_TCB, priority: c.seL4_Word) !void {
    const res = c.zig_seL4_TCB_SetPriority(_service, authority, priority);
    try handle_error(res);
}
pub fn TCB_SetMCPriority(_service: c.seL4_TCB, authority: c.seL4_TCB, mcp: c.seL4_Word) !void {
    const res = c.zig_seL4_TCB_SetMCPriority(_service, authority, mcp);
    try handle_error(res);
}
pub fn TCB_SetSchedParams(_service: c.seL4_TCB, authority: c.seL4_TCB, mcp: c.seL4_Word, priority: c.seL4_Word) !void {
    const res = c.zig_seL4_TCB_SetSchedParams(_service, authority, mcp, priority);
    try handle_error(res);
}
pub fn TCB_SetIPCBuffer(_service: c.seL4_TCB, buffer: c.seL4_Word, bufferFrame: c.seL4_CPtr) !void {
    const res = c.zig_seL4_TCB_SetIPCBuffer(_service, buffer, bufferFrame);
    try handle_error(res);
}
pub fn TCB_SetSpace(_service: c.seL4_TCB, fault_ep: c.seL4_Word, cspace_root: c.seL4_CNode, cspace_root_data: c.seL4_Word, vspace_root: c.seL4_CPtr, vspace_root_data: c.seL4_Word) !void {
    const res = c.zig_seL4_TCB_SetSpace(_service, fault_ep, cspace_root, cspace_root_data, vspace_root, vspace_root_data);
    try handle_error(res);
}
pub fn TCB_Suspend(_service: c.seL4_TCB) !void {
    const res = c.zig_seL4_TCB_Suspend(_service);
    try handle_error(res);
}
pub fn TCB_Resume(_service: c.seL4_TCB) !void {
    const res = c.zig_seL4_TCB_Resume(_service);
    try handle_error(res);
}
pub fn TCB_BindNotification(_service: c.seL4_TCB, notification: c.seL4_CPtr) !void {
    const res = c.zig_seL4_TCB_BindNotification(_service, notification);
    try handle_error(res);
}
pub fn TCB_UnbindNotification(_service: c.seL4_TCB) !void {
    const res = c.zig_seL4_TCB_UnbindNotification(_service);
    try handle_error(res);
}
pub fn TCB_SetTLSBase(_service: c.seL4_TCB, tls_base: c.seL4_Word) !void {
    const res = c.zig_seL4_TCB_SetTLSBase(_service, tls_base);
    try handle_error(res);
}
pub fn CNode_Revoke(_service: c.seL4_CNode, index: c.seL4_Word, depth: c.seL4_Uint8) !void {
    const res = c.zig_seL4_CNode_Revoke(_service, index, depth);
    try handle_error(res);
}
pub fn CNode_Delete(_service: c.seL4_CNode, index: c.seL4_Word, depth: c.seL4_Uint8) !void {
    const res = c.zig_seL4_CNode_Delete(_service, index, depth);
    try handle_error(res);
}
pub fn CNode_CancelBadgedSends(_service: c.seL4_CNode, index: c.seL4_Word, depth: c.seL4_Uint8) !void {
    const res = c.zig_seL4_CNode_CancelBadgedSends(_service, index, depth);
    try handle_error(res);
}
pub fn CNode_Copy(_service: c.seL4_CNode, dest_index: c.seL4_Word, dest_depth: c.seL4_Uint8, src_root: c.seL4_CNode, src_index: c.seL4_Word, src_depth: c.seL4_Uint8, rights: c.seL4_CapRights_t) !void {
    const new_caprights = .{ .caprights = rights, .dummy = .{0} ** 3 };
    const res = c.zig_seL4_CNode_Copy(_service, dest_index, dest_depth, src_root, src_index, src_depth, new_caprights);
    try handle_error(res);
}
pub fn CNode_Mint(_service: c.seL4_CNode, dest_index: c.seL4_Word, dest_depth: c.seL4_Uint8, src_root: c.seL4_CNode, src_index: c.seL4_Word, src_depth: c.seL4_Uint8, rights: c.seL4_CapRights_t, badge: c.seL4_Word) !void {
    const new_caprights = .{ .caprights = rights, .dummy = .{0} ** 3 };
    const res = c.zig_seL4_CNode_Mint(_service, dest_index, dest_depth, src_root, src_index, src_depth, new_caprights, badge);
    try handle_error(res);
}
pub fn CNode_Move(_service: c.seL4_CNode, dest_index: c.seL4_Word, dest_depth: c.seL4_Uint8, src_root: c.seL4_CNode, src_index: c.seL4_Word, src_depth: c.seL4_Uint8) !void {
    const res = c.zig_seL4_CNode_Move(_service, dest_index, dest_depth, src_root, src_index, src_depth);
    try handle_error(res);
}
pub fn CNode_Mutate(_service: c.seL4_CNode, dest_index: c.seL4_Word, dest_depth: c.seL4_Uint8, src_root: c.seL4_CNode, src_index: c.seL4_Word, src_depth: c.seL4_Uint8, badge: c.seL4_Word) !void {
    const res = c.zig_seL4_CNode_Mutate(_service, dest_index, dest_depth, src_root, src_index, src_depth, badge);
    try handle_error(res);
}
pub fn CNode_Rotate(_service: c.seL4_CNode, dest_index: c.seL4_Word, dest_depth: c.seL4_Uint8, dest_badge: c.seL4_Word, pivot_root: c.seL4_CNode, pivot_index: c.seL4_Word, pivot_depth: c.seL4_Uint8, pivot_badge: c.seL4_Word, src_root: c.seL4_CNode, src_index: c.seL4_Word, src_depth: c.seL4_Uint8) !void {
    const res = c.zig_seL4_CNode_Rotate(_service, dest_index, dest_depth, dest_badge, pivot_root, pivot_index, pivot_depth, pivot_badge, src_root, src_index, src_depth);
    try handle_error(res);
}
pub fn CNode_SaveCaller(_service: c.seL4_CNode, index: c.seL4_Word, depth: c.seL4_Uint8) !void {
    const res = c.zig_seL4_CNode_SaveCaller(_service, index, depth);
    try handle_error(res);
}
pub fn IRQControl_Get(_service: c.seL4_IRQControl, irq: c.seL4_Word, root: c.seL4_CNode, index: c.seL4_Word, depth: c.seL4_Uint8) !void {
    const res = c.zig_seL4_IRQControl_Get(_service, irq, root, index, depth);
    try handle_error(res);
}
pub fn IRQHandler_Ack(_service: c.seL4_IRQHandler) !void {
    const res = c.zig_seL4_IRQHandler_Ack(_service);
    try handle_error(res);
}
pub fn IRQHandler_SetNotification(_service: c.seL4_IRQHandler, notification: c.seL4_CPtr) !void {
    const res = c.zig_seL4_IRQHandler_SetNotification(_service, notification);
    try handle_error(res);
}
pub fn IRQHandler_Clear(_service: c.seL4_IRQHandler) !void {
    const res = c.zig_seL4_IRQHandler_Clear(_service);
    try handle_error(res);
}
pub fn DomainSet_Set(_service: c.seL4_DomainSet, domain: c.seL4_Uint8, thread: c.seL4_TCB) !void {
    const res = c.zig_seL4_DomainSet_Set(_service, domain, thread);
    try handle_error(res);
}
pub fn DebugCapIdentify(cap: c.seL4_CPtr) c.seL4_Uint32 {
    return c.zig_seL4_DebugCapIdentify(cap);
}
pub fn DebugDumpScheduler() void {
    c.zig_seL4_DebugCapIdentify();
}
pub fn Reply(info: c.seL4_MessageInfo_t) void {
    const new_msginfo = .{ .msginfo = info, .dummy = .{0} ** 3 };
    c.zig_seL4_Reply(new_msginfo);
}
pub fn Recv(w: c.seL4_CPtr, sender: [*c]c.seL4_Word) c.seL4_MessageInfo_t {
    const res = c.zig_seL4_Recv(w, sender);
    return res.msginfo;
}
pub fn MessageInfo_get_length(arg: c.seL4_MessageInfo_t) c.seL4_Uint64 {
    const new_msginfo = .{ .msginfo = arg, .dummy = .{0} ** 3 };
    return c.zig_seL4_MessageInfo_get_length(new_msginfo);
}
pub fn Send(slot: c.seL4_CPtr, info: c.seL4_MessageInfo_t) void {
    const new_msginfo = .{ .msginfo = info, .dummy = .{0} ** 3 };
    c.zig_seL4_Send(slot, new_msginfo);
}
pub fn ReplyRecv(dest: c.seL4_CPtr, info: c.seL4_MessageInfo_t, sender: [*c]c.seL4_Word) c.seL4_MessageInfo_t {
    const new_info = .{ .msginfo = info, .dummy = .{0} ** 3 };
    const res = c.zig_seL4_ReplyRecv(dest, new_info, sender);
    return res.msginfo;
}
pub fn Wait(src: c.seL4_CPtr, sender: [*c]c.seL4_Word) void {
    c.zig_seL4_Wait(src, sender);
}
pub fn Signal(dest: c.seL4_CPtr) void {
    c.zig_seL4_Signal(dest);
}
