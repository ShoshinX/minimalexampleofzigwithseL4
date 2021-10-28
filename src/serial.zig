const seL4 = @import("cImports.zig");
const std = @import("std");
pub const COM1 = 0x3F8;

var serial_seL4Cap: seL4.seL4_CPtr = undefined;
pub fn init() !void {
    const info = seL4.platsupport_get_bootinfo();
    serial_seL4Cap = info.*.empty.start;
    // TODO: implement error types into the zig sel4 interface
    _ = seL4.zig_seL4_X86_IOPortControl_Issue(seL4.seL4_CapIOPortControl, COM1, COM1 + 8, seL4.seL4_CapInitThreadCNode, serial_seL4Cap, seL4.seL4_WordBits);
}

pub fn readByte() ErrorSet!u8 {
    // TODO handle error
    const res = seL4.zig_seL4_X86_IOPort_In8(serial_seL4Cap, COM1);
    return res.result;
}

pub fn writeByte(byte: u8) ErrorSet!void {
    // TODO handle error
    _ = seL4.zig_seL4_X86_IOPort_Out8(serial_seL4Cap, COM1, byte);
}

pub fn write(buffer: []const u8) ErrorSet!void {
    for (buffer) |c|
        try writeByte(c);
}

pub fn writeText(buffer: []const u8) ErrorSet!void {
    for (buffer) |c| {
        switch (c) {
            '\n' => {
                try writeByte('\r');
                try writeByte('\n');
            },
            else => try writeByte(c),
        }
    }
}

fn writeFn(a: void, bytes: []const u8) ErrorSet!usize {
    _ = a;
    try writeText(bytes);
    return bytes.len;
}

const ErrorSet = error{NoError};

const Writer = std.io.Writer(void, ErrorSet, writeFn);

pub fn writer() Writer {
    return .{ .context = .{} };
}
