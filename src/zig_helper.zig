const std = @import("std");
const builtin = std.builtin;
const elf = std.elf;
const mem = std.mem;
const math = std.math;
const io = std.io;
const fstddbg = @import("freestanding_debug.zig");
const serial = @import("serial.zig");
const c = @import("cImports.zig");
const dwarf = @import("self_dwarf.zig");

var io_port_cap: c.seL4_CPtr = 0;

extern var _cpio_archive: []u8;
extern var _cpio_archive_end: []u8;

pub fn panic(msg: []const u8, error_return_trace: ?*builtin.StackTrace) noreturn {
    _ = serial.writer().print("err msg: {s}\n", .{msg}) catch unreachable;
    _ = c.printf("address impacted: %u\n", error_return_trace);
    const size: u64 = @ptrToInt(&_cpio_archive_end) - @ptrToInt(&_cpio_archive);
    _ = c.printf("CPIO_ARCHIVE ADDRESS: %d\n", size);
    var elf_size: u64 = 0;
    const file: ?*const c_void = c.cpio_get_file(&_cpio_archive, size, "hello-world-image", &elf_size);
    if (file == null) _ = c.printf("file is null\n");
    var debugInfo: dwarf.DwarfInfo = undefined;
    if (file) |value| {
        debugInfo = returnDebugInfoFromMappedELF(value) catch |err| {
            _ = serial.writer().print("unable to get debug info: {s}\n", .{@errorName(err)}) catch unreachable;
            hang();
        };
    }
    //}
    _ = serial.writeText("panice() triggers\n") catch unreachable;

    const first_trace_addr = @returnAddress();
    var it = std.debug.StackIterator.init(first_trace_addr, null);
    while (it.next()) |return_address| {
        fstddbg.printSourceAtAddress(@ptrCast(*std.dwarf.DwarfInfo, &debugInfo), serial.writer(), return_address, .no_color, printLineFromMappedFile) catch hang();
    }

    while (true) {}
}

fn hang() noreturn {
    while (true) {}
}

fn chopSlice(ptr: [*]align(8) const u8, offset: u64, size: u64) ![]const u8 {
    const start = try math.cast(usize, offset);
    const end = start + try math.cast(usize, size);
    return ptr[start..end];
}

const source_files = [_][]const u8{ "zig_helper.zig", "freestanding_debug.zig", "serial.zig" };

fn printLineFromMappedFile(out_stream: anytype, line_info: std.debug.LineInfo) anyerror!void {
    inline for (source_files) |src_path| {
        if (std.mem.endsWith(u8, line_info.file_name, src_path)) {
            const contents = @embedFile("./" ++ src_path);
            try printLineFromBuffer(out_stream, contents[0..], line_info);
            return;
        }
    }
    try out_stream.print("(source file {s} not added in std/debug.zig)\n", .{line_info.file_name});
}

fn printLineFromBuffer(out_stream: anytype, contents: []const u8, line_info: std.debug.LineInfo) anyerror!void {
    var line: usize = 1;
    var column: usize = 1;
    for (contents) |byte| {
        if (line == line_info.line) {
            try out_stream.writeByte(byte);
            if (byte == '\n') {
                return;
            }
        }
        if (byte == '\n') {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    return error.EndOfFile;
}

var kernel_panic_allocator_bytes: [4096 * 1024]u8 = undefined;
var kernel_panic_allocator_state = std.heap.FixedBufferAllocator.init(kernel_panic_allocator_bytes[0..]);
const allocator = &kernel_panic_allocator_state.allocator;

fn returnDebugInfoFromMappedELF(mapped_elf: *const c_void) !dwarf.DwarfInfo {
    const mapped_mem = @ptrCast([*]const u8, @alignCast(8, mapped_elf));
    const hdr = @ptrCast(*const elf.Ehdr, mapped_mem);
    if (!mem.eql(u8, hdr.e_ident[0..4], "\x7fELF")) return error.InvalidElfMagic;
    if (hdr.e_ident[elf.EI_VERSION] != 1) return error.InvalidElfVersion;

    const endian: builtin.Endian = switch (hdr.e_ident[elf.EI_DATA]) {
        elf.ELFDATA2LSB => .Little,
        elf.ELFDATA2MSB => .Big,
        else => return error.InvalidElfEndian,
    };

    const shoff = hdr.e_shoff;
    const str_section_off = shoff + @as(u64, hdr.e_shentsize) * @as(u64, hdr.e_shstrndx);
    const str_shdr = @ptrCast(*const elf.Shdr, @alignCast(@alignOf(elf.Shdr), &mapped_mem[try math.cast(usize, str_section_off)]));
    const header_strings = mapped_mem[str_shdr.sh_offset .. str_shdr.sh_offset + str_shdr.sh_size];
    const shdrs = @ptrCast(
        [*]const elf.Shdr,
        @alignCast(@alignOf(elf.Shdr), &mapped_mem[shoff]),
    )[0..hdr.e_shnum];
    var opt_debug_info: ?[]const u8 = null;
    var opt_debug_abbrev: ?[]const u8 = null;
    var opt_debug_str: ?[]const u8 = null;
    var opt_debug_line: ?[]const u8 = null;
    var opt_debug_ranges: ?[]const u8 = null;

    for (shdrs) |*shdr| {
        if (shdr.sh_type == elf.SHT_NULL) continue;

        const name = std.mem.span(std.meta.assumeSentinel(header_strings[shdr.sh_name..].ptr, 0));
        if (mem.eql(u8, name, ".debug_info")) {
            opt_debug_info = try chopSlice(mapped_mem, shdr.sh_offset, shdr.sh_size);
        } else if (mem.eql(u8, name, ".debug_abbrev")) {
            opt_debug_abbrev = try chopSlice(mapped_mem, shdr.sh_offset, shdr.sh_size);
        } else if (mem.eql(u8, name, ".debug_str")) {
            opt_debug_str = try chopSlice(mapped_mem, shdr.sh_offset, shdr.sh_size);
        } else if (mem.eql(u8, name, ".debug_line")) {
            opt_debug_line = try chopSlice(mapped_mem, shdr.sh_offset, shdr.sh_size);
        } else if (mem.eql(u8, name, ".debug_ranges")) {
            opt_debug_ranges = try chopSlice(mapped_mem, shdr.sh_offset, shdr.sh_size);
        }
    }
    var di = dwarf.DwarfInfo{
        .endian = endian,
        .debug_info = opt_debug_info orelse return error.MissingDebugInfo,
        .debug_abbrev = opt_debug_abbrev orelse return error.MissingDebugInfo,
        .debug_str = opt_debug_str orelse return error.MissingDebugInfo,
        .debug_line = opt_debug_line orelse return error.MissingDebugInfo,
        .debug_ranges = opt_debug_ranges,
    };
    try dwarf.openDwarfDebugInfo(&di, allocator);
    return di;
}

//extern var __debug_info_start: u8;
//extern var __debug_info_end: u8;
//extern var __debug_abbrev_start: u8;
//extern var __debug_abbrev_end: u8;
//extern var __debug_str_start: u8;
//extern var __debug_str_end: u8;
//extern var __debug_line_start: u8;
//extern var __debug_line_end: u8;
//extern var __debug_ranges_start: u8;
//extern var __debug_ranges_end: u8;
//fn getSelfDebugInfo() !*dwarf.DwarfInfo {
//    const debug_mem_size = @ptrToInt(&__debug_ranges_end) - @ptrToInt(&__debug_info_start);
//    const debug_mem = @ptrCast([*]const u8, &__debug_info_start)[0..debug_mem_size];
//    const debug_mem_start = @ptrToInt(&__debug_info_start);
//    _ = try serial.writer().print("Debug_mem length: {}\n", .{debug_mem.len});
//
//    const info_offset = @ptrToInt(&__debug_info_start) - debug_mem_start;
//    const info_size = @ptrToInt(&__debug_info_end) - @ptrToInt(&__debug_info_start);
//
//    const abbrev_offset = @ptrToInt(&__debug_abbrev_start) - debug_mem_start;
//    const abbrev_size = @ptrToInt(&__debug_abbrev_end) - @ptrToInt(&__debug_abbrev_start);
//
//    const str_offset = @ptrToInt(&__debug_str_start) - debug_mem_start;
//    const str_size = @ptrToInt(&__debug_str_end) - @ptrToInt(&__debug_str_start);
//
//    const line_offset = @ptrToInt(&__debug_line_start) - debug_mem_start;
//    const line_size = @ptrToInt(&__debug_line_end) - @ptrToInt(&__debug_line_start);
//
//    const ranges_offset = @ptrToInt(&__debug_ranges_start) - debug_mem_start;
//    const ranges_size = @ptrToInt(&__debug_ranges_end) - @ptrToInt(&__debug_ranges_start);
//
//    var di: dwarf.DwarfInfo = dwarf.DwarfInfo{
//        .endian = builtin.Endian.Little,
//        .debug_info = try chopSlice(debug_mem, info_offset, info_size),
//        .debug_abbrev = try chopSlice(debug_mem, abbrev_offset, abbrev_size),
//        .debug_str = try chopSlice(debug_mem, str_offset, str_size),
//        .debug_line = try chopSlice(debug_mem, line_offset, line_size),
//        .debug_ranges = try chopSlice(debug_mem, ranges_offset, ranges_size),
//    };
//    _ = try serial.writer().print("Debug_mem_address: {} {}\n", .{ @ptrToInt(&__debug_info_start), @ptrToInt(&(debug_mem[0..3])[0]) });
//    _ = try serial.writer().print("Debug_info length: {} {}\n", .{ info_size, di.debug_info.len });
//    _ = try serial.writer().print("Debug_abbrev length: {} {}\n", .{ abbrev_size, di.debug_abbrev.len });
//    _ = try serial.writer().print("Debug_str length: {} {}\n", .{ str_size, di.debug_str.len });
//    _ = try serial.writer().print("Debug_line length: {} {}\n", .{ line_size, di.debug_line.len });
//    _ = try serial.writer().print("Debug_ranges length: {} {}\n", .{ ranges_size, di.debug_ranges.?.len });
//    var stream = io.fixedBufferStream(di.debug_abbrev);
//    const in = &stream.reader();
//    const byte = in.readByte();
//    _ = try serial.writer().print("Byte read: {}\n", .{byte});
//    try dwarf.openDwarfDebugInfo(&di, allocator);
//    return &di;
//}

export fn main() i64 {
    const info = c.platsupport_get_bootinfo();
    var err: c.seL4_Error = undefined;
    // Setup keyboard
    io_port_cap = info.*.empty.start;
    _ = serial.init() catch unreachable;
    //_ = serial.writer().print("RESULT {}\n", .{@ptrToInt(&__debug_info_end) - @ptrToInt(&__debug_info_start)}) catch unreachable;
    // _ = serial.writer().print("DEBUG POINTERS:\n {}\n {}\n {}\n {}\n {}\n {}\n {}\n {}\n {}\n {} \n", .{
    //     @ptrToInt(&__debug_info_start),
    //     @ptrToInt(&__debug_info_end),
    //     @ptrToInt(&__debug_abbrev_start),
    //     @ptrToInt(&__debug_abbrev_end),
    //     @ptrToInt(&__debug_str_start),
    //     @ptrToInt(&__debug_str_end),
    //     @ptrToInt(&__debug_line_start),
    //     @ptrToInt(&__debug_line_end),
    //     @ptrToInt(&__debug_ranges_start),
    //     @ptrToInt(&__debug_ranges_end),
    // }) catch unreachable;
    // Show errors as first class values:
    // Use defer: de-/allocating resource that lasts until the end of the scope
    // Use errdefer: de-/allocating resources that last longer than the scope
    const free_slot = io_port_cap + 1;
    err = fail_allocate_resources(free_slot) catch 1;
    if (err != 0) _ = c.printf("Failed allocating resources \n");

    //const allrights = .{ .caprights = c.seL4_AllRights, .dummy = .{0} ** 3 };
    //const res = c.zig_seL4_CNode_Copy(c.seL4_CapInitThreadCNode, free_slot, c.seL4_WordBits, c.seL4_CapInitThreadCNode, c.seL4_CapInitThreadTCB, c.seL4_WordBits, allrights);
    //if (res != c.seL4_NoError) _ = c.printf("Can't copy: %u\n", res);

    // Use bufferoverread or bufferoverflow crash example
    var len: u32 = 11;
    var buffer: [10]u8 = .{0} ** 10;
    var dest: [11]u8 = .{0} ** 11;
    do_buffer_overread(len, &buffer, &dest);
    _ = c.printf("Success\n");
    return 0;
}
// A reduced version of the heartbleed vulnerability
fn do_buffer_overread(len: usize, buffer: []u8, dest: []u8) void {
    // copy from one buffer to the next
    var i: u32 = 0;
    while (i < len) : (i += 1) {
        dest[i] = buffer[i];
    }
}

// I want to init a server with its cap and the IOPortCOntrol issue fails so there's a rollback.
// Allocate twice, ensuring it fails the second time.
fn fail_allocate_resources(cap_slot: c.seL4_Word) !c.seL4_Error {
    // allocate caps
    const allrights = .{ .caprights = c.seL4_AllRights, .dummy = .{0} ** 3 };
    _ = c.zig_seL4_CNode_Copy(c.seL4_CapInitThreadCNode, cap_slot, c.seL4_WordBits, c.seL4_CapInitThreadCNode, c.seL4_CapInitThreadTCB, c.seL4_WordBits, allrights);
    errdefer {
        const res = c.zig_seL4_CNode_Delete(c.seL4_CapInitThreadCNode, cap_slot, c.seL4_WordBits);
        _ = c.printf("Errdefer: %d\n", res);
    }

    // return error with the IOPortControl_Issue
    var err: c.seL4_Error = try X86_IOPort_Control_Issue(cap_slot);
    return err;
}

const seL4Errors = error{
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
// Errors as first class in zig
// TODO: write wrapper for future work to add errors
fn X86_IOPort_Control_Issue(port_cap: c.seL4_Word) !c.seL4_Error {
    var res: c.seL4_Error = c.seL4_NoError;
    res = c.zig_seL4_X86_IOPortControl_Issue(c.seL4_CapIOPortControl, 0x3f8, 0x3ff, c.seL4_CapInitThreadCNode, port_cap, c.seL4_WordBits);
    return return_seL4_Error(res);
}

fn return_seL4_Error(err: c.seL4_Error) !c.seL4_Error {
    if (err == c.seL4_InvalidArgument) return seL4Errors.InvalidArgument;
    if (err == c.seL4_InvalidCapability) return seL4Errors.InvalidCapability;
    if (err == c.seL4_IllegalOperation) return seL4Errors.IllegalOperation;
    if (err == c.seL4_RangeError) return seL4Errors.RangeError;
    if (err == c.seL4_AlignmentError) return seL4Errors.AlignmentError;
    if (err == c.seL4_FailedLookup) return seL4Errors.FailedLookup;
    if (err == c.seL4_TruncatedMessage) return seL4Errors.TruncatedMessage;
    if (err == c.seL4_DeleteFirst) return seL4Errors.DeleteFirst;
    if (err == c.seL4_RevokeFirst) return seL4Errors.RevokeFirst;
    if (err == c.seL4_NotEnoughMemory) return seL4Errors.NotEnoughMemory;
    return c.seL4_NoError;
}

// Write the 2 callback functions
fn in8(port: u16) callconv(.C) u8 {
    return c.zig_seL4_X86_IOPort_In8(io_port_cap, port).result;
}

fn out8(port: u16, value: u8) callconv(.C) void {
    _ = c.zig_seL4_X86_IOPort_Out8(io_port_cap, port, value);
}
