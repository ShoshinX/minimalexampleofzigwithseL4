const std = @import("std");
//const DW = @import("self_dwarf.zig");
const DW = std.dwarf;
const debug = std.debug;
const TTY = debug.TTY;
const serial = @import("serial.zig");

pub fn printSourceAtAddress(debug_info: *DW.DwarfInfo, out_stream: anytype, address: usize, tty_config: TTY.Config, comptime printLineFromMappedFile: anytype) !void {
    const symbol_info = try getSymbolFromDwarf(address, debug_info);
    // symbol_info.line_info is the problem
    return printLineInfo(out_stream, symbol_info.line_info, address, symbol_info.symbol_name, symbol_info.compile_unit_name, tty_config, printLineFromMappedFile);
}

fn printLineInfo(
    out_stream: anytype,
    line_info: ?debug.LineInfo,
    address: usize,
    symbol_name: []const u8,
    compile_unit_name: []const u8,
    tty_config: TTY.Config,
    comptime printLineFromFile: anytype,
) !void {
    nosuspend {
        tty_config.setColor(out_stream, .Bold);

        if (line_info) |*li| {
            try out_stream.print("{s}:{d}:{d}", .{ li.file_name, li.line, li.column });
        } else {
            try out_stream.writeAll("???:?:?");
        }

        tty_config.setColor(out_stream, .Reset);
        try out_stream.writeAll(": ");
        tty_config.setColor(out_stream, .Dim);
        try out_stream.print("0x{x} in {s} ({s})", .{ address, symbol_name, compile_unit_name });
        tty_config.setColor(out_stream, .Reset);
        try out_stream.writeAll("\n");

        // Show the matching source code line if possible
        // Error is line_info being null
        if (line_info) |li| {
            if (printLineFromFile(out_stream, li)) {
                if (li.column > 0) {
                    // The caret already takes one char
                    const space_needed = @intCast(usize, li.column - 1);

                    try out_stream.writeByteNTimes(' ', space_needed);
                    tty_config.setColor(out_stream, .Green);
                    try out_stream.writeAll("^");
                    tty_config.setColor(out_stream, .Reset);
                }
                try out_stream.writeAll("\n");
            } else |err| switch (err) {
                error.EndOfFile, error.FileNotFound => {},
                error.BadPathName => {},
                error.AccessDenied => {},
                else => return err,
            }
        }
    }
}

fn getSymbolFromDwarf(address: u64, di: *DW.DwarfInfo) !debug.SymbolInfo {
    if (nosuspend di.findCompileUnit(address)) |compile_unit| {
        return debug.SymbolInfo{
            .symbol_name = nosuspend di.getSymbolName(address) orelse "???",
            .compile_unit_name = compile_unit.die.getAttrString(di, DW.AT.name) catch |err| switch (err) {
                error.MissingDebugInfo, error.InvalidDebugInfo => "???",
                else => return err,
            },
            .line_info = nosuspend di.getLineNumberInfo(compile_unit.*, address) catch |err| switch (err) {
                error.MissingDebugInfo, error.InvalidDebugInfo => null,
                else => return err,
            },
        };
    } else |err| switch (err) {
        // TODO It's resulting in a MissingDebugInfo
        error.MissingDebugInfo, error.InvalidDebugInfo => {
            return debug.SymbolInfo{};
        },
        else => return err,
    }
}
