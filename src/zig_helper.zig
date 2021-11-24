const std = @import("std");
const builtin = std.builtin;
const elf = std.elf;
const mem = std.mem;
const math = std.math;
const io = std.io;
const fstddbg = @import("freestanding_debug.zig");
const serial = @import("serial.zig");
const c = @import("cImports.zig");
const seL4_api = @import("seL4_wrapper.zig");
const dwarf = std.dwarf;
//const dwarf = @import("self_dwarf.zig");

var io_port_cap: c.seL4_CPtr = 0;

// source files to include for debugging
const source_files = [_][]const u8{
    "zig_helper.zig",
    "freestanding_debug.zig",
    "serial.zig",
    "seL4_wrapper.zig",
};
extern var _cpio_archive: []u8;
extern var _cpio_archive_end: []u8;

pub fn panic(msg: []const u8, error_return_trace: ?*builtin.StackTrace) noreturn {
    _ = serial.writer().print("err msg: {s}\n", .{msg}) catch unreachable;
    _ = error_return_trace;
    const size: u64 = @ptrToInt(&_cpio_archive_end) - @ptrToInt(&_cpio_archive);
    var elf_size: u64 = 0;
    const file: ?*const c_void = c.cpio_get_file(&_cpio_archive, size, "elf-info", &elf_size);
    if (file == null) _ = c.printf("file is null\n");
    var debugInfo: dwarf.DwarfInfo = undefined;
    if (file) |value| {
        debugInfo = returnDebugInfoFromMappedELF(value) catch |err| {
            _ = serial.writer().print("unable to get debug info: {s}\n", .{@errorName(err)}) catch unreachable;
            hang();
        };
    }
    //_ = serial.writeText("TRIGGERED: panic()\n") catch unreachable;

    const first_trace_addr = @returnAddress();
    var it = std.debug.StackIterator.init(first_trace_addr, null);
    //var num: u32 = 0;
    while (it.next()) |return_address| {
        fstddbg.printSourceAtAddress(&debugInfo, serial.writer(), return_address, .no_color, printLineFromMappedFile) catch |err| (serial.writer().print("FAIL: printSourceAtAddress() {s}\n", .{@errorName(err)}) catch unreachable);
    }
    _ = serial.writer().print("Panic message finished.\n", .{}) catch unreachable;

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

var kernel_panic_allocator_bytes: [8192 * 1024]u8 = undefined;
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
    _ = try serial.writer().print("SUCCESS: returnDebugInfoFromMappedELF\n", .{});
    return di;
}

export fn main() i64 {
    const res = main_continued() catch unreachable;
    return res;
}

fn main_continued() !i64 {
    const info = c.platsupport_get_bootinfo();
    io_port_cap = info.*.empty.start;
    // Setup keyboard
    _ = serial.init() catch unreachable;
    // Use defer: de-/allocating resource that lasts until the end of the scope
    // Use errdefer: de-/allocating resources that last longer than the scope
    const free_slot = io_port_cap + 1;
    fail_allocate_resources(free_slot) catch unreachable;

    //var eg: ?u32 = null;
    //_ = eg.?;
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
fn fail_allocate_resources(cap_slot: c.seL4_Word) !void {
    _ = cap_slot;
    try seL4_api.TCB_Resume(200);
}
