const std = @import("std");
const builtin = std.builtin;
const debug = std.debug;
const fs = std.fs;
const io = std.io;
const mem = std.mem;
const math = std.math;
const leb = @import("leb128.zig");
const serial = @import("serial.zig");

const ArrayList = std.ArrayList;

const PcRange = struct {
    start: u64,
    end: u64,
};

const Func = struct {
    pc_range: ?PcRange,
    name: ?[]const u8,
};

const CompileUnit = struct {
    version: u16,
    is_64: bool,
    die: *Die,
    pc_range: ?PcRange,
};

const AbbrevTable = ArrayList(AbbrevTableEntry);

const AbbrevTableHeader = struct {
    // offset from .debug_abbrev
    offset: u64,
    table: AbbrevTable,
};

const AbbrevTableEntry = struct {
    has_children: bool,
    abbrev_code: u64,
    tag_id: u64,
    attrs: ArrayList(AbbrevAttr),
};

const AbbrevAttr = struct {
    attr_id: u64,
    form_id: u64,
};

const FormValue = union(enum) {
    Address: u64,
    Block: []u8,
    Const: Constant,
    ExprLoc: []u8,
    Flag: bool,
    SecOffset: u64,
    Ref: u64,
    RefAddr: u64,
    String: []const u8,
    StrPtr: u64,
};

const Constant = struct {
    payload: u64,
    signed: bool,

    fn asUnsignedLe(self: *const Constant) !u64 {
        if (self.signed) return error.InvalidDebugInfo;
        return self.payload;
    }
};

const Die = struct {
    tag_id: u64,
    has_children: bool,
    attrs: ArrayList(Attr),

    const Attr = struct {
        id: u64,
        value: FormValue,
    };

    fn getAttr(self: *const Die, id: u64) ?*const FormValue {
        for (self.attrs.items) |*attr| {
            if (attr.id == id) return &attr.value;
        }
        return null;
    }

    fn getAttrAddr(self: *const Die, id: u64) !u64 {
        const form_value = self.getAttr(id) orelse return error.MissingDebugInfo;
        return switch (form_value.*) {
            FormValue.Address => |value| value,
            else => error.InvalidDebugInfo,
        };
    }

    fn getAttrSecOffset(self: *const Die, id: u64) !u64 {
        const form_value = self.getAttr(id) orelse return error.MissingDebugInfo;
        return switch (form_value.*) {
            FormValue.Const => |value| value.asUnsignedLe(),
            FormValue.SecOffset => |value| value,
            else => error.InvalidDebugInfo,
        };
    }

    fn getAttrUnsignedLe(self: *const Die, id: u64) !u64 {
        const form_value = self.getAttr(id) orelse return error.MissingDebugInfo;
        return switch (form_value.*) {
            FormValue.Const => |value| value.asUnsignedLe(),
            else => error.InvalidDebugInfo,
        };
    }

    fn getAttrRef(self: *const Die, id: u64) !u64 {
        const form_value = self.getAttr(id) orelse return error.MissingDebugInfo;
        return switch (form_value.*) {
            FormValue.Ref => |value| value,
            else => error.InvalidDebugInfo,
        };
    }

    pub fn getAttrString(self: *const Die, di: *DwarfInfo, id: u64) ![]const u8 {
        const form_value = self.getAttr(id) orelse return error.MissingDebugInfo;
        return switch (form_value.*) {
            FormValue.String => |value| value,
            FormValue.StrPtr => |offset| di.getString(offset),
            else => error.InvalidDebugInfo,
        };
    }
};

const FileEntry = struct {
    file_name: []const u8,
    dir_index: usize,
    mtime: usize,
    len_bytes: usize,
};

const LineNumberProgram = struct {
    address: u64,
    file: usize,
    line: i64,
    column: u64,
    is_stmt: bool,
    basic_block: bool,
    end_sequence: bool,

    default_is_stmt: bool,
    target_address: u64,
    include_dirs: []const []const u8,
    file_entries: *ArrayList(FileEntry),

    prev_valid: bool,
    prev_address: u64,
    prev_file: usize,
    prev_line: i64,
    prev_column: u64,
    prev_is_stmt: bool,
    prev_basic_block: bool,
    prev_end_sequence: bool,

    // Reset the state machine following the DWARF specification
    pub fn reset(self: *LineNumberProgram) void {
        self.address = 0;
        self.file = 1;
        self.line = 1;
        self.column = 0;
        self.is_stmt = self.default_is_stmt;
        self.basic_block = false;
        self.end_sequence = false;
        // Invalidate all the remaining fields
        self.prev_valid = false;
        self.prev_address = 0;
        self.prev_file = undefined;
        self.prev_line = undefined;
        self.prev_column = undefined;
        self.prev_is_stmt = undefined;
        self.prev_basic_block = undefined;
        self.prev_end_sequence = undefined;
    }

    pub fn init(is_stmt: bool, include_dirs: []const []const u8, file_entries: *ArrayList(FileEntry), target_address: u64) LineNumberProgram {
        return LineNumberProgram{
            .address = 0,
            .file = 1,
            .line = 1,
            .column = 0,
            .is_stmt = is_stmt,
            .basic_block = false,
            .end_sequence = false,
            .include_dirs = include_dirs,
            .file_entries = file_entries,
            .default_is_stmt = is_stmt,
            .target_address = target_address,
            .prev_valid = false,
            .prev_address = 0,
            .prev_file = undefined,
            .prev_line = undefined,
            .prev_column = undefined,
            .prev_is_stmt = undefined,
            .prev_basic_block = undefined,
            .prev_end_sequence = undefined,
        };
    }

    pub fn checkLineMatch(self: *LineNumberProgram) !?debug.LineInfo {
        if (self.prev_valid and self.target_address >= self.prev_address and self.target_address < self.address) {
            const file_entry = if (self.prev_file == 0) {
                return error.MissingDebugInfo;
            } else if (self.prev_file - 1 >= self.file_entries.items.len) {
                return error.InvalidDebugInfo;
            } else &self.file_entries.items[self.prev_file - 1];

            const dir_name = if (file_entry.dir_index >= self.include_dirs.len) {
                return error.InvalidDebugInfo;
            } else self.include_dirs[file_entry.dir_index];
            const file_name = try fs.path.join(self.file_entries.allocator, &[_][]const u8{ dir_name, file_entry.file_name });
            errdefer self.file_entries.allocator.free(file_name);
            return debug.LineInfo{
                .line = if (self.prev_line >= 0) @intCast(u64, self.prev_line) else 0,
                .column = self.prev_column,
                .file_name = file_name,
                .allocator = self.file_entries.allocator,
            };
        }

        self.prev_valid = true;
        self.prev_address = self.address;
        self.prev_file = self.file;
        self.prev_line = self.line;
        self.prev_column = self.column;
        self.prev_is_stmt = self.is_stmt;
        self.prev_basic_block = self.basic_block;
        self.prev_end_sequence = self.end_sequence;
        return null;
    }
};

fn readUnitLength(in_stream: anytype, endian: builtin.Endian, is_64: *bool) !u64 {
    const first_32_bits = try in_stream.readInt(u32, endian);
    is_64.* = (first_32_bits == 0xffffffff);
    if (is_64.*) {
        return in_stream.readInt(u64, endian);
    } else {
        if (first_32_bits >= 0xfffffff0) return error.InvalidDebugInfo;
        // TODO this cast should not be needed
        return @as(u64, first_32_bits);
    }
}

// TODO the nosuspends here are workarounds
fn readAllocBytes(allocator: *mem.Allocator, in_stream: anytype, size: usize) ![]u8 {
    const buf = try allocator.alloc(u8, size);
    errdefer allocator.free(buf);
    if ((try nosuspend in_stream.read(buf)) < size) return error.EndOfFile;
    return buf;
}

// TODO the nosuspends here are workarounds
fn readAddress(in_stream: anytype, endian: builtin.Endian, is_64: bool) !u64 {
    return nosuspend if (is_64)
        try in_stream.readInt(u64, endian)
    else
        @as(u64, try in_stream.readInt(u32, endian));
}

fn parseFormValueBlockLen(allocator: *mem.Allocator, in_stream: anytype, size: usize) !FormValue {
    const buf = try readAllocBytes(allocator, in_stream, size);
    return FormValue{ .Block = buf };
}

// TODO the nosuspends here are workarounds
fn parseFormValueBlock(allocator: *mem.Allocator, in_stream: anytype, endian: builtin.Endian, size: usize) !FormValue {
    const block_len = try nosuspend in_stream.readVarInt(usize, endian, size);
    return parseFormValueBlockLen(allocator, in_stream, block_len);
}

fn parseFormValueConstant(allocator: *mem.Allocator, in_stream: anytype, signed: bool, endian: builtin.Endian, comptime size: i32) !FormValue {
    _ = allocator;
    // TODO: Please forgive me, I've worked around zig not properly spilling some intermediate values here.
    // `nosuspend` should be removed from all the function calls once it is fixed.
    return FormValue{
        .Const = Constant{
            .signed = signed,
            .payload = switch (size) {
                1 => try nosuspend in_stream.readInt(u8, endian),
                2 => try nosuspend in_stream.readInt(u16, endian),
                4 => try nosuspend in_stream.readInt(u32, endian),
                8 => try nosuspend in_stream.readInt(u64, endian),
                -1 => blk: {
                    if (signed) {
                        const x = try nosuspend leb.readILEB128(i64, in_stream);
                        break :blk @bitCast(u64, x);
                    } else {
                        const x = try nosuspend leb.readULEB128(u64, in_stream);
                        break :blk x;
                    }
                },
                else => @compileError("Invalid size"),
            },
        },
    };
}

// TODO the nosuspends here are workarounds
fn parseFormValueRef(allocator: *mem.Allocator, in_stream: anytype, endian: builtin.Endian, size: i32) !FormValue {
    _ = allocator;
    return FormValue{
        .Ref = switch (size) {
            1 => try nosuspend in_stream.readInt(u8, endian),
            2 => try nosuspend in_stream.readInt(u16, endian),
            4 => try nosuspend in_stream.readInt(u32, endian),
            8 => try nosuspend in_stream.readInt(u64, endian),
            -1 => try nosuspend leb.readULEB128(u64, in_stream),
            else => unreachable,
        },
    };
}

// TODO the nosuspends here are workarounds
fn parseFormValue(allocator: *mem.Allocator, in_stream: anytype, form_id: u64, endian: builtin.Endian, is_64: bool) anyerror!FormValue {
    return switch (form_id) {
        FORM_addr => FormValue{ .Address = try readAddress(in_stream, endian, @sizeOf(usize) == 8) },
        FORM_block1 => parseFormValueBlock(allocator, in_stream, endian, 1),
        FORM_block2 => parseFormValueBlock(allocator, in_stream, endian, 2),
        FORM_block4 => parseFormValueBlock(allocator, in_stream, endian, 4),
        FORM_block => {
            const block_len = try nosuspend leb.readULEB128(usize, in_stream);
            return parseFormValueBlockLen(allocator, in_stream, block_len);
        },
        FORM_data1 => parseFormValueConstant(allocator, in_stream, false, endian, 1),
        FORM_data2 => parseFormValueConstant(allocator, in_stream, false, endian, 2),
        FORM_data4 => parseFormValueConstant(allocator, in_stream, false, endian, 4),
        FORM_data8 => parseFormValueConstant(allocator, in_stream, false, endian, 8),
        FORM_udata, FORM_sdata => {
            const signed = form_id == FORM_sdata;
            return parseFormValueConstant(allocator, in_stream, signed, endian, -1);
        },
        FORM_exprloc => {
            const size = try nosuspend leb.readULEB128(usize, in_stream);
            const buf = try readAllocBytes(allocator, in_stream, size);
            return FormValue{ .ExprLoc = buf };
        },
        FORM_flag => FormValue{ .Flag = (try nosuspend in_stream.readByte()) != 0 },
        FORM_flag_present => FormValue{ .Flag = true },
        FORM_sec_offset => FormValue{ .SecOffset = try readAddress(in_stream, endian, is_64) },

        FORM_ref1 => parseFormValueRef(allocator, in_stream, endian, 1),
        FORM_ref2 => parseFormValueRef(allocator, in_stream, endian, 2),
        FORM_ref4 => parseFormValueRef(allocator, in_stream, endian, 4),
        FORM_ref8 => parseFormValueRef(allocator, in_stream, endian, 8),
        FORM_ref_udata => parseFormValueRef(allocator, in_stream, endian, -1),

        FORM_ref_addr => FormValue{ .RefAddr = try readAddress(in_stream, endian, is_64) },
        FORM_ref_sig8 => FormValue{ .Ref = try nosuspend in_stream.readInt(u64, endian) },

        FORM_string => FormValue{ .String = try in_stream.readUntilDelimiterAlloc(allocator, 0, math.maxInt(usize)) },
        FORM_strp => FormValue{ .StrPtr = try readAddress(in_stream, endian, is_64) },
        FORM_indirect => {
            const child_form_id = try nosuspend leb.readULEB128(u64, in_stream);
            const F = @TypeOf(async parseFormValue(allocator, in_stream, child_form_id, endian, is_64));
            var frame = try allocator.create(F);
            defer allocator.destroy(frame);
            return await @asyncCall(frame, {}, parseFormValue, .{ allocator, in_stream, child_form_id, endian, is_64 });
        },
        else => error.InvalidDebugInfo,
    };
}

fn getAbbrevTableEntry(abbrev_table: *const AbbrevTable, abbrev_code: u64) ?*const AbbrevTableEntry {
    for (abbrev_table.items) |*table_entry| {
        if (table_entry.abbrev_code == abbrev_code) return table_entry;
    }
    return null;
}

pub const DwarfInfo = struct {
    endian: builtin.Endian,
    // No memory is owned by the DwarfInfo
    debug_info: []const u8,
    debug_abbrev: []const u8,
    debug_str: []const u8,
    debug_line: []const u8,
    debug_ranges: ?[]const u8,
    // Filled later by the initializer
    abbrev_table_list: ArrayList(AbbrevTableHeader) = undefined,
    compile_unit_list: ArrayList(CompileUnit) = undefined,
    func_list: ArrayList(Func) = undefined,

    pub fn allocator(self: DwarfInfo) *mem.Allocator {
        return self.abbrev_table_list.allocator;
    }

    pub fn getSymbolName(di: *DwarfInfo, address: u64) ?[]const u8 {
        for (di.func_list.items) |*func| {
            if (func.pc_range) |range| {
                if (address >= range.start and address < range.end) {
                    return func.name;
                }
            }
        }

        return null;
    }

    fn scanAllFunctions(di: *DwarfInfo) !void {
        var stream = io.fixedBufferStream(di.debug_info);
        const in = &stream.reader();
        const seekable = &stream.seekableStream();
        var this_unit_offset: u64 = 0;

        while (this_unit_offset < try seekable.getEndPos()) {
            try seekable.seekTo(this_unit_offset);

            var is_64: bool = undefined;
            const unit_length = try readUnitLength(in, di.endian, &is_64);
            if (unit_length == 0) return;
            const next_offset = unit_length + (if (is_64) @as(usize, 12) else @as(usize, 4));

            const version = try in.readInt(u16, di.endian);
            if (version < 2 or version > 5) return error.InvalidDebugInfo;
            //_ = try serial.writer().print("version: {}\n", .{version});

            // DEBUG: debug_abbrev_offset makes getAbbrevTable seek to the end of .debug_abbrev[]
            const debug_abbrev_offset = if (is_64) try in.readInt(u64, di.endian) else try in.readInt(u32, di.endian);
            //_ = try serial.writer().print("debug_abbrev_offset: {} {}\n", .{ debug_abbrev_offset, is_64 });

            const address_size = try in.readByte();
            if (address_size != @sizeOf(usize)) return error.InvalidDebugInfo;
            //_ = try serial.writer().print("address_size: {}\n", .{address_size});

            const compile_unit_pos = try seekable.getPos();
            // DEBUG: the abbreviation table here returns EndOfStream
            const abbrev_table = try di.getAbbrevTable(debug_abbrev_offset);

            try seekable.seekTo(compile_unit_pos);

            const next_unit_pos = this_unit_offset + next_offset;

            while ((try seekable.getPos()) < next_unit_pos) {
                const die_obj = (try di.parseDie(in, abbrev_table, is_64)) orelse continue;
                defer die_obj.attrs.deinit();

                const after_die_offset = try seekable.getPos();

                switch (die_obj.tag_id) {
                    TAG_subprogram, TAG_inlined_subroutine, TAG_subroutine, TAG_entry_point => {
                        const fn_name = x: {
                            var depth: i32 = 3;
                            var this_die_obj = die_obj;
                            // Prenvent endless loops
                            while (depth > 0) : (depth -= 1) {
                                if (this_die_obj.getAttr(AT_name)) |_| {
                                    const name = try this_die_obj.getAttrString(di, AT_name);
                                    break :x name;
                                } else if (this_die_obj.getAttr(AT_abstract_origin)) |_| {
                                    // Follow the DIE it points to and repeat
                                    const ref_offset = try this_die_obj.getAttrRef(AT_abstract_origin);
                                    if (ref_offset > next_offset) return error.InvalidDebugInfo;
                                    try seekable.seekTo(this_unit_offset + ref_offset);
                                    this_die_obj = (try di.parseDie(in, abbrev_table, is_64)) orelse return error.InvalidDebugInfo;
                                } else if (this_die_obj.getAttr(AT_specification)) |_| {
                                    // Follow the DIE it points to and repeat
                                    const ref_offset = try this_die_obj.getAttrRef(AT_specification);
                                    if (ref_offset > next_offset) return error.InvalidDebugInfo;
                                    try seekable.seekTo(this_unit_offset + ref_offset);
                                    this_die_obj = (try di.parseDie(in, abbrev_table, is_64)) orelse return error.InvalidDebugInfo;
                                } else {
                                    break :x null;
                                }
                            }

                            break :x null;
                        };

                        const pc_range = x: {
                            if (die_obj.getAttrAddr(AT_low_pc)) |low_pc| {
                                if (die_obj.getAttr(AT_high_pc)) |high_pc_value| {
                                    const pc_end = switch (high_pc_value.*) {
                                        FormValue.Address => |value| value,
                                        FormValue.Const => |value| b: {
                                            const offset = try value.asUnsignedLe();
                                            break :b (low_pc + offset);
                                        },
                                        else => return error.InvalidDebugInfo,
                                    };
                                    break :x PcRange{
                                        .start = low_pc,
                                        .end = pc_end,
                                    };
                                } else {
                                    break :x null;
                                }
                            } else |err| {
                                if (err != error.MissingDebugInfo) return err;
                                break :x null;
                            }
                        };

                        try di.func_list.append(Func{
                            .name = fn_name,
                            .pc_range = pc_range,
                        });
                    },
                    else => {},
                }

                try seekable.seekTo(after_die_offset);
            }

            this_unit_offset += next_offset;
        }
    }

    fn scanAllCompileUnits(di: *DwarfInfo) !void {
        var stream = io.fixedBufferStream(di.debug_info);
        const in = &stream.reader();
        const seekable = &stream.seekableStream();
        var this_unit_offset: u64 = 0;

        while (this_unit_offset < try seekable.getEndPos()) {
            try seekable.seekTo(this_unit_offset);

            var is_64: bool = undefined;
            const unit_length = try readUnitLength(in, di.endian, &is_64);
            if (unit_length == 0) return;
            const next_offset = unit_length + (if (is_64) @as(usize, 12) else @as(usize, 4));

            const version = try in.readInt(u16, di.endian);
            if (version < 2 or version > 5) return error.InvalidDebugInfo;

            const debug_abbrev_offset = if (is_64) try in.readInt(u64, di.endian) else try in.readInt(u32, di.endian);

            const address_size = try in.readByte();
            if (address_size != @sizeOf(usize)) return error.InvalidDebugInfo;

            const compile_unit_pos = try seekable.getPos();
            const abbrev_table = try di.getAbbrevTable(debug_abbrev_offset);

            try seekable.seekTo(compile_unit_pos);

            const compile_unit_die = try di.allocator().create(Die);
            compile_unit_die.* = (try di.parseDie(in, abbrev_table, is_64)) orelse return error.InvalidDebugInfo;

            if (compile_unit_die.tag_id != TAG_compile_unit) return error.InvalidDebugInfo;

            const pc_range = x: {
                if (compile_unit_die.getAttrAddr(AT_low_pc)) |low_pc| {
                    if (compile_unit_die.getAttr(AT_high_pc)) |high_pc_value| {
                        const pc_end = switch (high_pc_value.*) {
                            FormValue.Address => |value| value,
                            FormValue.Const => |value| b: {
                                const offset = try value.asUnsignedLe();
                                break :b (low_pc + offset);
                            },
                            else => return error.InvalidDebugInfo,
                        };
                        break :x PcRange{
                            .start = low_pc,
                            .end = pc_end,
                        };
                    } else {
                        break :x null;
                    }
                } else |err| {
                    if (err != error.MissingDebugInfo) return err;
                    break :x null;
                }
            };

            try di.compile_unit_list.append(CompileUnit{
                .version = version,
                .is_64 = is_64,
                .pc_range = pc_range,
                .die = compile_unit_die,
            });

            this_unit_offset += next_offset;
        }
    }

    pub fn findCompileUnit(di: *DwarfInfo, target_address: u64) !*const CompileUnit {
        for (di.compile_unit_list.items) |*compile_unit| {
            if (compile_unit.pc_range) |range| {
                if (target_address >= range.start and target_address < range.end) return compile_unit;
            }
            if (di.debug_ranges) |debug_ranges| {
                if (compile_unit.die.getAttrSecOffset(AT_ranges)) |ranges_offset| {
                    var stream = io.fixedBufferStream(debug_ranges);
                    const in = &stream.reader();
                    const seekable = &stream.seekableStream();

                    // All the addresses in the list are relative to the value
                    // specified by DW_AT_low_pc or to some other value encoded
                    // in the list itself.
                    // If no starting value is specified use zero.
                    var base_address = compile_unit.die.getAttrAddr(AT_low_pc) catch |err| switch (err) {
                        error.MissingDebugInfo => 0,
                        else => return err,
                    };

                    try seekable.seekTo(ranges_offset);

                    while (true) {
                        const begin_addr = try in.readInt(usize, di.endian);
                        const end_addr = try in.readInt(usize, di.endian);
                        if (begin_addr == 0 and end_addr == 0) {
                            break;
                        }
                        // This entry selects a new value for the base address
                        if (begin_addr == math.maxInt(usize)) {
                            base_address = end_addr;
                            continue;
                        }
                        if (target_address >= base_address + begin_addr and target_address < base_address + end_addr) {
                            return compile_unit;
                        }
                    }
                } else |err| {
                    if (err != error.MissingDebugInfo) return err;
                    continue;
                }
            }
        }
        return error.MissingDebugInfo;
    }

    /// Gets an already existing AbbrevTable given the abbrev_offset, or if not found,
    /// seeks in the stream and parses it.
    fn getAbbrevTable(di: *DwarfInfo, abbrev_offset: u64) !*const AbbrevTable {
        for (di.abbrev_table_list.items) |*header| {
            if (header.offset == abbrev_offset) {
                return &header.table;
            }
        }
        try di.abbrev_table_list.append(AbbrevTableHeader{
            .offset = abbrev_offset,
            // DEBUG: parseAbbrevTable returns EndOfStream
            .table = try di.parseAbbrevTable(abbrev_offset),
        });
        return &di.abbrev_table_list.items[di.abbrev_table_list.items.len - 1].table;
    }

    fn parseAbbrevTable(di: *DwarfInfo, offset: u64) !AbbrevTable {
        var stream = io.fixedBufferStream(di.debug_abbrev);
        const in = &stream.reader();
        const seekable = &stream.seekableStream();

        try seekable.seekTo(offset);
        var result = AbbrevTable.init(di.allocator());
        errdefer result.deinit();
        while (true) {
            // DEBUG: leb.readULEB128 is making this function return EndOfStream
            // Position is at the end of the position
            const abbrev_code = try leb.readULEB128(u64, in);
            if (abbrev_code == 0) return result;
            try result.append(AbbrevTableEntry{
                .abbrev_code = abbrev_code,
                .tag_id = try leb.readULEB128(u64, in),
                .has_children = (try in.readByte()) == CHILDREN_yes,
                .attrs = ArrayList(AbbrevAttr).init(di.allocator()),
            });
            const attrs = &result.items[result.items.len - 1].attrs;

            while (true) {
                const attr_id = try leb.readULEB128(u64, in);
                const form_id = try leb.readULEB128(u64, in);
                if (attr_id == 0 and form_id == 0) break;
                try attrs.append(AbbrevAttr{
                    .attr_id = attr_id,
                    .form_id = form_id,
                });
            }
        }
    }

    fn parseDie(di: *DwarfInfo, in_stream: anytype, abbrev_table: *const AbbrevTable, is_64: bool) !?Die {
        const abbrev_code = try leb.readULEB128(u64, in_stream);
        if (abbrev_code == 0) return null;
        const table_entry = getAbbrevTableEntry(abbrev_table, abbrev_code) orelse return error.InvalidDebugInfo;

        var result = Die{
            .tag_id = table_entry.tag_id,
            .has_children = table_entry.has_children,
            .attrs = ArrayList(Die.Attr).init(di.allocator()),
        };
        try result.attrs.resize(table_entry.attrs.items.len);
        for (table_entry.attrs.items) |attr, i| {
            result.attrs.items[i] = Die.Attr{
                .id = attr.attr_id,
                .value = try parseFormValue(di.allocator(), in_stream, attr.form_id, di.endian, is_64),
            };
        }
        return result;
    }

    pub fn getLineNumberInfo(di: *DwarfInfo, compile_unit: CompileUnit, target_address: u64) !debug.LineInfo {
        var stream = io.fixedBufferStream(di.debug_line);
        const in = &stream.reader();
        const seekable = &stream.seekableStream();

        const compile_unit_cwd = try compile_unit.die.getAttrString(di, AT_comp_dir);
        const line_info_offset = try compile_unit.die.getAttrSecOffset(AT_stmt_list);

        try seekable.seekTo(line_info_offset);

        var is_64: bool = undefined;
        const unit_length = try readUnitLength(in, di.endian, &is_64);
        if (unit_length == 0) {
            return error.MissingDebugInfo;
        }
        const next_offset = unit_length + (if (is_64) @as(usize, 12) else @as(usize, 4));

        const version = try in.readInt(u16, di.endian);
        if (version < 2 or version > 4) return error.InvalidDebugInfo;

        const prologue_length = if (is_64) try in.readInt(u64, di.endian) else try in.readInt(u32, di.endian);
        const prog_start_offset = (try seekable.getPos()) + prologue_length;

        const minimum_instruction_length = try in.readByte();
        if (minimum_instruction_length == 0) return error.InvalidDebugInfo;

        if (version >= 4) {
            // maximum_operations_per_instruction
            _ = try in.readByte();
        }

        const default_is_stmt = (try in.readByte()) != 0;
        const line_base = try in.readByteSigned();

        const line_range = try in.readByte();
        if (line_range == 0) return error.InvalidDebugInfo;

        const opcode_base = try in.readByte();

        const standard_opcode_lengths = try di.allocator().alloc(u8, opcode_base - 1);
        defer di.allocator().free(standard_opcode_lengths);

        {
            var i: usize = 0;
            while (i < opcode_base - 1) : (i += 1) {
                standard_opcode_lengths[i] = try in.readByte();
            }
        }

        var include_directories = ArrayList([]const u8).init(di.allocator());
        try include_directories.append(compile_unit_cwd);
        while (true) {
            const dir = try in.readUntilDelimiterAlloc(di.allocator(), 0, math.maxInt(usize));
            if (dir.len == 0) break;
            try include_directories.append(dir);
        }

        var file_entries = ArrayList(FileEntry).init(di.allocator());
        var prog = LineNumberProgram.init(default_is_stmt, include_directories.items, &file_entries, target_address);

        while (true) {
            const file_name = try in.readUntilDelimiterAlloc(di.allocator(), 0, math.maxInt(usize));
            if (file_name.len == 0) break;
            const dir_index = try leb.readULEB128(usize, in);
            const mtime = try leb.readULEB128(usize, in);
            const len_bytes = try leb.readULEB128(usize, in);
            try file_entries.append(FileEntry{
                .file_name = file_name,
                .dir_index = dir_index,
                .mtime = mtime,
                .len_bytes = len_bytes,
            });
        }

        try seekable.seekTo(prog_start_offset);

        const next_unit_pos = line_info_offset + next_offset;

        while ((try seekable.getPos()) < next_unit_pos) {
            const opcode = try in.readByte();

            if (opcode == LNS_extended_op) {
                const op_size = try leb.readULEB128(u64, in);
                if (op_size < 1) return error.InvalidDebugInfo;
                var sub_op = try in.readByte();
                switch (sub_op) {
                    LNE_end_sequence => {
                        prog.end_sequence = true;
                        if (try prog.checkLineMatch()) |info| return info;
                        prog.reset();
                    },
                    LNE_set_address => {
                        const addr = try in.readInt(usize, di.endian);
                        prog.address = addr;
                    },
                    LNE_define_file => {
                        const file_name = try in.readUntilDelimiterAlloc(di.allocator(), 0, math.maxInt(usize));
                        const dir_index = try leb.readULEB128(usize, in);
                        const mtime = try leb.readULEB128(usize, in);
                        const len_bytes = try leb.readULEB128(usize, in);
                        try file_entries.append(FileEntry{
                            .file_name = file_name,
                            .dir_index = dir_index,
                            .mtime = mtime,
                            .len_bytes = len_bytes,
                        });
                    },
                    else => {
                        const fwd_amt = math.cast(isize, op_size - 1) catch return error.InvalidDebugInfo;
                        try seekable.seekBy(fwd_amt);
                    },
                }
            } else if (opcode >= opcode_base) {
                // special opcodes
                const adjusted_opcode = opcode - opcode_base;
                const inc_addr = minimum_instruction_length * (adjusted_opcode / line_range);
                const inc_line = @as(i32, line_base) + @as(i32, adjusted_opcode % line_range);
                prog.line += inc_line;
                prog.address += inc_addr;
                if (try prog.checkLineMatch()) |info| return info;
                prog.basic_block = false;
            } else {
                switch (opcode) {
                    LNS_copy => {
                        if (try prog.checkLineMatch()) |info| return info;
                        prog.basic_block = false;
                    },
                    LNS_advance_pc => {
                        const arg = try leb.readULEB128(usize, in);
                        prog.address += arg * minimum_instruction_length;
                    },
                    LNS_advance_line => {
                        const arg = try leb.readILEB128(i64, in);
                        prog.line += arg;
                    },
                    LNS_set_file => {
                        const arg = try leb.readULEB128(usize, in);
                        prog.file = arg;
                    },
                    LNS_set_column => {
                        const arg = try leb.readULEB128(u64, in);
                        prog.column = arg;
                    },
                    LNS_negate_stmt => {
                        prog.is_stmt = !prog.is_stmt;
                    },
                    LNS_set_basic_block => {
                        prog.basic_block = true;
                    },
                    LNS_const_add_pc => {
                        const inc_addr = minimum_instruction_length * ((255 - opcode_base) / line_range);
                        prog.address += inc_addr;
                    },
                    LNS_fixed_advance_pc => {
                        const arg = try in.readInt(u16, di.endian);
                        prog.address += arg;
                    },
                    LNS_set_prologue_end => {},
                    else => {
                        if (opcode - 1 >= standard_opcode_lengths.len) return error.InvalidDebugInfo;
                        const len_bytes = standard_opcode_lengths[opcode - 1];
                        try seekable.seekBy(len_bytes);
                    },
                }
            }
        }

        return error.MissingDebugInfo;
    }

    fn getString(di: *DwarfInfo, offset: u64) ![]const u8 {
        if (offset > di.debug_str.len)
            return error.InvalidDebugInfo;
        const casted_offset = math.cast(usize, offset) catch
            return error.InvalidDebugInfo;

        // Valid strings always have a terminating zero byte
        if (mem.indexOfScalarPos(u8, di.debug_str, casted_offset, 0)) |last| {
            return di.debug_str[casted_offset..last];
        }

        return error.InvalidDebugInfo;
    }
};

/// Initialize DWARF info. The caller has the responsibility to initialize most
/// the DwarfInfo fields before calling. These fields can be left undefined:
/// * abbrev_table_list
/// * compile_unit_list
pub fn openDwarfDebugInfo(di: *DwarfInfo, allocator: *mem.Allocator) !void {
    di.abbrev_table_list = ArrayList(AbbrevTableHeader).init(allocator);
    di.compile_unit_list = ArrayList(CompileUnit).init(allocator);
    di.func_list = ArrayList(Func).init(allocator);
    //_ = try serial.writer().print("WORKS HERE\n", .{});
    try di.scanAllFunctions();
    try di.scanAllCompileUnits();
}

pub const TAG_padding = 0x00;
pub const TAG_array_type = 0x01;
pub const TAG_class_type = 0x02;
pub const TAG_entry_point = 0x03;
pub const TAG_enumeration_type = 0x04;
pub const TAG_formal_parameter = 0x05;
pub const TAG_imported_declaration = 0x08;
pub const TAG_label = 0x0a;
pub const TAG_lexical_block = 0x0b;
pub const TAG_member = 0x0d;
pub const TAG_pointer_type = 0x0f;
pub const TAG_reference_type = 0x10;
pub const TAG_compile_unit = 0x11;
pub const TAG_string_type = 0x12;
pub const TAG_structure_type = 0x13;
pub const TAG_subroutine = 0x14;
pub const TAG_subroutine_type = 0x15;
pub const TAG_typedef = 0x16;
pub const TAG_union_type = 0x17;
pub const TAG_unspecified_parameters = 0x18;
pub const TAG_variant = 0x19;
pub const TAG_common_block = 0x1a;
pub const TAG_common_inclusion = 0x1b;
pub const TAG_inheritance = 0x1c;
pub const TAG_inlined_subroutine = 0x1d;
pub const TAG_module = 0x1e;
pub const TAG_ptr_to_member_type = 0x1f;
pub const TAG_set_type = 0x20;
pub const TAG_subrange_type = 0x21;
pub const TAG_with_stmt = 0x22;
pub const TAG_access_declaration = 0x23;
pub const TAG_base_type = 0x24;
pub const TAG_catch_block = 0x25;
pub const TAG_const_type = 0x26;
pub const TAG_constant = 0x27;
pub const TAG_enumerator = 0x28;
pub const TAG_file_type = 0x29;
pub const TAG_friend = 0x2a;
pub const TAG_namelist = 0x2b;
pub const TAG_namelist_item = 0x2c;
pub const TAG_packed_type = 0x2d;
pub const TAG_subprogram = 0x2e;
pub const TAG_template_type_param = 0x2f;
pub const TAG_template_value_param = 0x30;
pub const TAG_thrown_type = 0x31;
pub const TAG_try_block = 0x32;
pub const TAG_variant_part = 0x33;
pub const TAG_variable = 0x34;
pub const TAG_volatile_type = 0x35;

// DWARF 3
pub const TAG_dwarf_procedure = 0x36;
pub const TAG_restrict_type = 0x37;
pub const TAG_interface_type = 0x38;
pub const TAG_namespace = 0x39;
pub const TAG_imported_module = 0x3a;
pub const TAG_unspecified_type = 0x3b;
pub const TAG_partial_unit = 0x3c;
pub const TAG_imported_unit = 0x3d;
pub const TAG_condition = 0x3f;
pub const TAG_shared_type = 0x40;

// DWARF 4
pub const TAG_type_unit = 0x41;
pub const TAG_rvalue_reference_type = 0x42;
pub const TAG_template_alias = 0x43;

pub const TAG_lo_user = 0x4080;
pub const TAG_hi_user = 0xffff;

// SGI/MIPS Extensions.
pub const TAG_MIPS_loop = 0x4081;

// HP extensions.  See: ftp://ftp.hp.com/pub/lang/tools/WDB/wdb-4.0.tar.gz .
pub const TAG_HP_array_descriptor = 0x4090;
pub const TAG_HP_Bliss_field = 0x4091;
pub const TAG_HP_Bliss_field_set = 0x4092;

// GNU extensions.
pub const TAG_format_label = 0x4101; // For FORTRAN 77 and Fortran 90.
pub const TAG_function_template = 0x4102; // For C++.
pub const TAG_class_template = 0x4103; //For C++.
pub const TAG_GNU_BINCL = 0x4104;
pub const TAG_GNU_EINCL = 0x4105;

// Template template parameter.
// See http://gcc.gnu.org/wiki/TemplateParmsDwarf .
pub const TAG_GNU_template_template_param = 0x4106;

// Template parameter pack extension = specified at
// http://wiki.dwarfstd.org/index.php?title=C%2B%2B0x:_Variadic_templates
// The values of these two TAGS are in the DW_TAG_GNU_* space until the tags
// are properly part of DWARF 5.
pub const TAG_GNU_template_parameter_pack = 0x4107;
pub const TAG_GNU_formal_parameter_pack = 0x4108;
// The GNU call site extension = specified at
// http://www.dwarfstd.org/ShowIssue.php?issue=100909.2&type=open .
// The values of these two TAGS are in the DW_TAG_GNU_* space until the tags
// are properly part of DWARF 5.
pub const TAG_GNU_call_site = 0x4109;
pub const TAG_GNU_call_site_parameter = 0x410a;
// Extensions for UPC.  See: http://dwarfstd.org/doc/DWARF4.pdf.
pub const TAG_upc_shared_type = 0x8765;
pub const TAG_upc_strict_type = 0x8766;
pub const TAG_upc_relaxed_type = 0x8767;
// PGI (STMicroelectronics; extensions.  No documentation available.
pub const TAG_PGI_kanji_type = 0xA000;
pub const TAG_PGI_interface_block = 0xA020;

pub const FORM_addr = 0x01;
pub const FORM_block2 = 0x03;
pub const FORM_block4 = 0x04;
pub const FORM_data2 = 0x05;
pub const FORM_data4 = 0x06;
pub const FORM_data8 = 0x07;
pub const FORM_string = 0x08;
pub const FORM_block = 0x09;
pub const FORM_block1 = 0x0a;
pub const FORM_data1 = 0x0b;
pub const FORM_flag = 0x0c;
pub const FORM_sdata = 0x0d;
pub const FORM_strp = 0x0e;
pub const FORM_udata = 0x0f;
pub const FORM_ref_addr = 0x10;
pub const FORM_ref1 = 0x11;
pub const FORM_ref2 = 0x12;
pub const FORM_ref4 = 0x13;
pub const FORM_ref8 = 0x14;
pub const FORM_ref_udata = 0x15;
pub const FORM_indirect = 0x16;
pub const FORM_sec_offset = 0x17;
pub const FORM_exprloc = 0x18;
pub const FORM_flag_present = 0x19;
pub const FORM_ref_sig8 = 0x20;

// Extensions for Fission.  See http://gcc.gnu.org/wiki/DebugFission.
pub const FORM_GNU_addr_index = 0x1f01;
pub const FORM_GNU_str_index = 0x1f02;

// Extensions for DWZ multifile.
// See http://www.dwarfstd.org/ShowIssue.php?issue=120604.1&type=open .
pub const FORM_GNU_ref_alt = 0x1f20;
pub const FORM_GNU_strp_alt = 0x1f21;

pub const AT_sibling = 0x01;
pub const AT_location = 0x02;
pub const AT_name = 0x03;
pub const AT_ordering = 0x09;
pub const AT_subscr_data = 0x0a;
pub const AT_byte_size = 0x0b;
pub const AT_bit_offset = 0x0c;
pub const AT_bit_size = 0x0d;
pub const AT_element_list = 0x0f;
pub const AT_stmt_list = 0x10;
pub const AT_low_pc = 0x11;
pub const AT_high_pc = 0x12;
pub const AT_language = 0x13;
pub const AT_member = 0x14;
pub const AT_discr = 0x15;
pub const AT_discr_value = 0x16;
pub const AT_visibility = 0x17;
pub const AT_import = 0x18;
pub const AT_string_length = 0x19;
pub const AT_common_reference = 0x1a;
pub const AT_comp_dir = 0x1b;
pub const AT_const_value = 0x1c;
pub const AT_containing_type = 0x1d;
pub const AT_default_value = 0x1e;
pub const AT_inline = 0x20;
pub const AT_is_optional = 0x21;
pub const AT_lower_bound = 0x22;
pub const AT_producer = 0x25;
pub const AT_prototyped = 0x27;
pub const AT_return_addr = 0x2a;
pub const AT_start_scope = 0x2c;
pub const AT_bit_stride = 0x2e;
pub const AT_upper_bound = 0x2f;
pub const AT_abstract_origin = 0x31;
pub const AT_accessibility = 0x32;
pub const AT_address_class = 0x33;
pub const AT_artificial = 0x34;
pub const AT_base_types = 0x35;
pub const AT_calling_convention = 0x36;
pub const AT_count = 0x37;
pub const AT_data_member_location = 0x38;
pub const AT_decl_column = 0x39;
pub const AT_decl_file = 0x3a;
pub const AT_decl_line = 0x3b;
pub const AT_declaration = 0x3c;
pub const AT_discr_list = 0x3d;
pub const AT_encoding = 0x3e;
pub const AT_external = 0x3f;
pub const AT_frame_base = 0x40;
pub const AT_friend = 0x41;
pub const AT_identifier_case = 0x42;
pub const AT_macro_info = 0x43;
pub const AT_namelist_items = 0x44;
pub const AT_priority = 0x45;
pub const AT_segment = 0x46;
pub const AT_specification = 0x47;
pub const AT_static_link = 0x48;
pub const AT_type = 0x49;
pub const AT_use_location = 0x4a;
pub const AT_variable_parameter = 0x4b;
pub const AT_virtuality = 0x4c;
pub const AT_vtable_elem_location = 0x4d;

// DWARF 3 values.
pub const AT_allocated = 0x4e;
pub const AT_associated = 0x4f;
pub const AT_data_location = 0x50;
pub const AT_byte_stride = 0x51;
pub const AT_entry_pc = 0x52;
pub const AT_use_UTF8 = 0x53;
pub const AT_extension = 0x54;
pub const AT_ranges = 0x55;
pub const AT_trampoline = 0x56;
pub const AT_call_column = 0x57;
pub const AT_call_file = 0x58;
pub const AT_call_line = 0x59;
pub const AT_description = 0x5a;
pub const AT_binary_scale = 0x5b;
pub const AT_decimal_scale = 0x5c;
pub const AT_small = 0x5d;
pub const AT_decimal_sign = 0x5e;
pub const AT_digit_count = 0x5f;
pub const AT_picture_string = 0x60;
pub const AT_mutable = 0x61;
pub const AT_threads_scaled = 0x62;
pub const AT_explicit = 0x63;
pub const AT_object_pointer = 0x64;
pub const AT_endianity = 0x65;
pub const AT_elemental = 0x66;
pub const AT_pure = 0x67;
pub const AT_recursive = 0x68;

// DWARF 4.
pub const AT_signature = 0x69;
pub const AT_main_subprogram = 0x6a;
pub const AT_data_bit_offset = 0x6b;
pub const AT_const_expr = 0x6c;
pub const AT_enum_class = 0x6d;
pub const AT_linkage_name = 0x6e;

// DWARF 5
pub const AT_alignment = 0x88;

pub const AT_lo_user = 0x2000; // Implementation-defined range start.
pub const AT_hi_user = 0x3fff; // Implementation-defined range end.

// SGI/MIPS extensions.
pub const AT_MIPS_fde = 0x2001;
pub const AT_MIPS_loop_begin = 0x2002;
pub const AT_MIPS_tail_loop_begin = 0x2003;
pub const AT_MIPS_epilog_begin = 0x2004;
pub const AT_MIPS_loop_unroll_factor = 0x2005;
pub const AT_MIPS_software_pipeline_depth = 0x2006;
pub const AT_MIPS_linkage_name = 0x2007;
pub const AT_MIPS_stride = 0x2008;
pub const AT_MIPS_abstract_name = 0x2009;
pub const AT_MIPS_clone_origin = 0x200a;
pub const AT_MIPS_has_inlines = 0x200b;

// HP extensions.
pub const AT_HP_block_index = 0x2000;
pub const AT_HP_unmodifiable = 0x2001; // Same as AT_MIPS_fde.
pub const AT_HP_prologue = 0x2005; // Same as AT_MIPS_loop_unroll.
pub const AT_HP_epilogue = 0x2008; // Same as AT_MIPS_stride.
pub const AT_HP_actuals_stmt_list = 0x2010;
pub const AT_HP_proc_per_section = 0x2011;
pub const AT_HP_raw_data_ptr = 0x2012;
pub const AT_HP_pass_by_reference = 0x2013;
pub const AT_HP_opt_level = 0x2014;
pub const AT_HP_prof_version_id = 0x2015;
pub const AT_HP_opt_flags = 0x2016;
pub const AT_HP_cold_region_low_pc = 0x2017;
pub const AT_HP_cold_region_high_pc = 0x2018;
pub const AT_HP_all_variables_modifiable = 0x2019;
pub const AT_HP_linkage_name = 0x201a;
pub const AT_HP_prof_flags = 0x201b; // In comp unit of procs_info for -g.
pub const AT_HP_unit_name = 0x201f;
pub const AT_HP_unit_size = 0x2020;
pub const AT_HP_widened_byte_size = 0x2021;
pub const AT_HP_definition_points = 0x2022;
pub const AT_HP_default_location = 0x2023;
pub const AT_HP_is_result_param = 0x2029;

// GNU extensions.
pub const AT_sf_names = 0x2101;
pub const AT_src_info = 0x2102;
pub const AT_mac_info = 0x2103;
pub const AT_src_coords = 0x2104;
pub const AT_body_begin = 0x2105;
pub const AT_body_end = 0x2106;
pub const AT_GNU_vector = 0x2107;
// Thread-safety annotations.
// See http://gcc.gnu.org/wiki/ThreadSafetyAnnotation .
pub const AT_GNU_guarded_by = 0x2108;
pub const AT_GNU_pt_guarded_by = 0x2109;
pub const AT_GNU_guarded = 0x210a;
pub const AT_GNU_pt_guarded = 0x210b;
pub const AT_GNU_locks_excluded = 0x210c;
pub const AT_GNU_exclusive_locks_required = 0x210d;
pub const AT_GNU_shared_locks_required = 0x210e;
// One-definition rule violation detection.
// See http://gcc.gnu.org/wiki/DwarfSeparateTypeInfo .
pub const AT_GNU_odr_signature = 0x210f;
// Template template argument name.
// See http://gcc.gnu.org/wiki/TemplateParmsDwarf .
pub const AT_GNU_template_name = 0x2110;
// The GNU call site extension.
// See http://www.dwarfstd.org/ShowIssue.php?issue=100909.2&type=open .
pub const AT_GNU_call_site_value = 0x2111;
pub const AT_GNU_call_site_data_value = 0x2112;
pub const AT_GNU_call_site_target = 0x2113;
pub const AT_GNU_call_site_target_clobbered = 0x2114;
pub const AT_GNU_tail_call = 0x2115;
pub const AT_GNU_all_tail_call_sites = 0x2116;
pub const AT_GNU_all_call_sites = 0x2117;
pub const AT_GNU_all_source_call_sites = 0x2118;
// Section offset into .debug_macro section.
pub const AT_GNU_macros = 0x2119;
// Extensions for Fission.  See http://gcc.gnu.org/wiki/DebugFission.
pub const AT_GNU_dwo_name = 0x2130;
pub const AT_GNU_dwo_id = 0x2131;
pub const AT_GNU_ranges_base = 0x2132;
pub const AT_GNU_addr_base = 0x2133;
pub const AT_GNU_pubnames = 0x2134;
pub const AT_GNU_pubtypes = 0x2135;
// VMS extensions.
pub const AT_VMS_rtnbeg_pd_address = 0x2201;
// GNAT extensions.
// GNAT descriptive type.
// See http://gcc.gnu.org/wiki/DW_AT_GNAT_descriptive_type .
pub const AT_use_GNAT_descriptive_type = 0x2301;
pub const AT_GNAT_descriptive_type = 0x2302;
// UPC extension.
pub const AT_upc_threads_scaled = 0x3210;
// PGI (STMicroelectronics) extensions.
pub const AT_PGI_lbase = 0x3a00;
pub const AT_PGI_soffset = 0x3a01;
pub const AT_PGI_lstride = 0x3a02;

pub const OP_addr = 0x03;
pub const OP_deref = 0x06;
pub const OP_const1u = 0x08;
pub const OP_const1s = 0x09;
pub const OP_const2u = 0x0a;
pub const OP_const2s = 0x0b;
pub const OP_const4u = 0x0c;
pub const OP_const4s = 0x0d;
pub const OP_const8u = 0x0e;
pub const OP_const8s = 0x0f;
pub const OP_constu = 0x10;
pub const OP_consts = 0x11;
pub const OP_dup = 0x12;
pub const OP_drop = 0x13;
pub const OP_over = 0x14;
pub const OP_pick = 0x15;
pub const OP_swap = 0x16;
pub const OP_rot = 0x17;
pub const OP_xderef = 0x18;
pub const OP_abs = 0x19;
pub const OP_and = 0x1a;
pub const OP_div = 0x1b;
pub const OP_minus = 0x1c;
pub const OP_mod = 0x1d;
pub const OP_mul = 0x1e;
pub const OP_neg = 0x1f;
pub const OP_not = 0x20;
pub const OP_or = 0x21;
pub const OP_plus = 0x22;
pub const OP_plus_uconst = 0x23;
pub const OP_shl = 0x24;
pub const OP_shr = 0x25;
pub const OP_shra = 0x26;
pub const OP_xor = 0x27;
pub const OP_bra = 0x28;
pub const OP_eq = 0x29;
pub const OP_ge = 0x2a;
pub const OP_gt = 0x2b;
pub const OP_le = 0x2c;
pub const OP_lt = 0x2d;
pub const OP_ne = 0x2e;
pub const OP_skip = 0x2f;
pub const OP_lit0 = 0x30;
pub const OP_lit1 = 0x31;
pub const OP_lit2 = 0x32;
pub const OP_lit3 = 0x33;
pub const OP_lit4 = 0x34;
pub const OP_lit5 = 0x35;
pub const OP_lit6 = 0x36;
pub const OP_lit7 = 0x37;
pub const OP_lit8 = 0x38;
pub const OP_lit9 = 0x39;
pub const OP_lit10 = 0x3a;
pub const OP_lit11 = 0x3b;
pub const OP_lit12 = 0x3c;
pub const OP_lit13 = 0x3d;
pub const OP_lit14 = 0x3e;
pub const OP_lit15 = 0x3f;
pub const OP_lit16 = 0x40;
pub const OP_lit17 = 0x41;
pub const OP_lit18 = 0x42;
pub const OP_lit19 = 0x43;
pub const OP_lit20 = 0x44;
pub const OP_lit21 = 0x45;
pub const OP_lit22 = 0x46;
pub const OP_lit23 = 0x47;
pub const OP_lit24 = 0x48;
pub const OP_lit25 = 0x49;
pub const OP_lit26 = 0x4a;
pub const OP_lit27 = 0x4b;
pub const OP_lit28 = 0x4c;
pub const OP_lit29 = 0x4d;
pub const OP_lit30 = 0x4e;
pub const OP_lit31 = 0x4f;
pub const OP_reg0 = 0x50;
pub const OP_reg1 = 0x51;
pub const OP_reg2 = 0x52;
pub const OP_reg3 = 0x53;
pub const OP_reg4 = 0x54;
pub const OP_reg5 = 0x55;
pub const OP_reg6 = 0x56;
pub const OP_reg7 = 0x57;
pub const OP_reg8 = 0x58;
pub const OP_reg9 = 0x59;
pub const OP_reg10 = 0x5a;
pub const OP_reg11 = 0x5b;
pub const OP_reg12 = 0x5c;
pub const OP_reg13 = 0x5d;
pub const OP_reg14 = 0x5e;
pub const OP_reg15 = 0x5f;
pub const OP_reg16 = 0x60;
pub const OP_reg17 = 0x61;
pub const OP_reg18 = 0x62;
pub const OP_reg19 = 0x63;
pub const OP_reg20 = 0x64;
pub const OP_reg21 = 0x65;
pub const OP_reg22 = 0x66;
pub const OP_reg23 = 0x67;
pub const OP_reg24 = 0x68;
pub const OP_reg25 = 0x69;
pub const OP_reg26 = 0x6a;
pub const OP_reg27 = 0x6b;
pub const OP_reg28 = 0x6c;
pub const OP_reg29 = 0x6d;
pub const OP_reg30 = 0x6e;
pub const OP_reg31 = 0x6f;
pub const OP_breg0 = 0x70;
pub const OP_breg1 = 0x71;
pub const OP_breg2 = 0x72;
pub const OP_breg3 = 0x73;
pub const OP_breg4 = 0x74;
pub const OP_breg5 = 0x75;
pub const OP_breg6 = 0x76;
pub const OP_breg7 = 0x77;
pub const OP_breg8 = 0x78;
pub const OP_breg9 = 0x79;
pub const OP_breg10 = 0x7a;
pub const OP_breg11 = 0x7b;
pub const OP_breg12 = 0x7c;
pub const OP_breg13 = 0x7d;
pub const OP_breg14 = 0x7e;
pub const OP_breg15 = 0x7f;
pub const OP_breg16 = 0x80;
pub const OP_breg17 = 0x81;
pub const OP_breg18 = 0x82;
pub const OP_breg19 = 0x83;
pub const OP_breg20 = 0x84;
pub const OP_breg21 = 0x85;
pub const OP_breg22 = 0x86;
pub const OP_breg23 = 0x87;
pub const OP_breg24 = 0x88;
pub const OP_breg25 = 0x89;
pub const OP_breg26 = 0x8a;
pub const OP_breg27 = 0x8b;
pub const OP_breg28 = 0x8c;
pub const OP_breg29 = 0x8d;
pub const OP_breg30 = 0x8e;
pub const OP_breg31 = 0x8f;
pub const OP_regx = 0x90;
pub const OP_fbreg = 0x91;
pub const OP_bregx = 0x92;
pub const OP_piece = 0x93;
pub const OP_deref_size = 0x94;
pub const OP_xderef_size = 0x95;
pub const OP_nop = 0x96;

// DWARF 3 extensions.
pub const OP_push_object_address = 0x97;
pub const OP_call2 = 0x98;
pub const OP_call4 = 0x99;
pub const OP_call_ref = 0x9a;
pub const OP_form_tls_address = 0x9b;
pub const OP_call_frame_cfa = 0x9c;
pub const OP_bit_piece = 0x9d;

// DWARF 4 extensions.
pub const OP_implicit_value = 0x9e;
pub const OP_stack_value = 0x9f;

pub const OP_lo_user = 0xe0; // Implementation-defined range start.
pub const OP_hi_user = 0xff; // Implementation-defined range end.

// GNU extensions.
pub const OP_GNU_push_tls_address = 0xe0;
// The following is for marking variables that are uninitialized.
pub const OP_GNU_uninit = 0xf0;
pub const OP_GNU_encoded_addr = 0xf1;
// The GNU implicit pointer extension.
// See http://www.dwarfstd.org/ShowIssue.php?issue=100831.1&type=open .
pub const OP_GNU_implicit_pointer = 0xf2;
// The GNU entry value extension.
// See http://www.dwarfstd.org/ShowIssue.php?issue=100909.1&type=open .
pub const OP_GNU_entry_value = 0xf3;
// The GNU typed stack extension.
// See http://www.dwarfstd.org/doc/040408.1.html .
pub const OP_GNU_const_type = 0xf4;
pub const OP_GNU_regval_type = 0xf5;
pub const OP_GNU_deref_type = 0xf6;
pub const OP_GNU_convert = 0xf7;
pub const OP_GNU_reinterpret = 0xf9;
// The GNU parameter ref extension.
pub const OP_GNU_parameter_ref = 0xfa;
// Extension for Fission.  See http://gcc.gnu.org/wiki/DebugFission.
pub const OP_GNU_addr_index = 0xfb;
pub const OP_GNU_const_index = 0xfc;
// HP extensions.
pub const OP_HP_unknown = 0xe0; // Ouch, the same as GNU_push_tls_address.
pub const OP_HP_is_value = 0xe1;
pub const OP_HP_fltconst4 = 0xe2;
pub const OP_HP_fltconst8 = 0xe3;
pub const OP_HP_mod_range = 0xe4;
pub const OP_HP_unmod_range = 0xe5;
pub const OP_HP_tls = 0xe6;
// PGI (STMicroelectronics) extensions.
pub const OP_PGI_omp_thread_num = 0xf8;

pub const ATE_void = 0x0;
pub const ATE_address = 0x1;
pub const ATE_boolean = 0x2;
pub const ATE_complex_float = 0x3;
pub const ATE_float = 0x4;
pub const ATE_signed = 0x5;
pub const ATE_signed_char = 0x6;
pub const ATE_unsigned = 0x7;
pub const ATE_unsigned_char = 0x8;

// DWARF 3.
pub const ATE_imaginary_float = 0x9;
pub const ATE_packed_decimal = 0xa;
pub const ATE_numeric_string = 0xb;
pub const ATE_edited = 0xc;
pub const ATE_signed_fixed = 0xd;
pub const ATE_unsigned_fixed = 0xe;
pub const ATE_decimal_float = 0xf;

// DWARF 4.
pub const ATE_UTF = 0x10;

pub const ATE_lo_user = 0x80;
pub const ATE_hi_user = 0xff;

// HP extensions.
pub const ATE_HP_float80 = 0x80; // Floating-point (80 bit).
pub const ATE_HP_complex_float80 = 0x81; // Complex floating-point (80 bit).
pub const ATE_HP_float128 = 0x82; // Floating-point (128 bit).
pub const ATE_HP_complex_float128 = 0x83; // Complex fp (128 bit).
pub const ATE_HP_floathpintel = 0x84; // Floating-point (82 bit IA64).
pub const ATE_HP_imaginary_float80 = 0x85;
pub const ATE_HP_imaginary_float128 = 0x86;
pub const ATE_HP_VAX_float = 0x88; // F or G floating.
pub const ATE_HP_VAX_float_d = 0x89; // D floating.
pub const ATE_HP_packed_decimal = 0x8a; // Cobol.
pub const ATE_HP_zoned_decimal = 0x8b; // Cobol.
pub const ATE_HP_edited = 0x8c; // Cobol.
pub const ATE_HP_signed_fixed = 0x8d; // Cobol.
pub const ATE_HP_unsigned_fixed = 0x8e; // Cobol.
pub const ATE_HP_VAX_complex_float = 0x8f; // F or G floating complex.
pub const ATE_HP_VAX_complex_float_d = 0x90; // D floating complex.

pub const CFA_advance_loc = 0x40;
pub const CFA_offset = 0x80;
pub const CFA_restore = 0xc0;
pub const CFA_nop = 0x00;
pub const CFA_set_loc = 0x01;
pub const CFA_advance_loc1 = 0x02;
pub const CFA_advance_loc2 = 0x03;
pub const CFA_advance_loc4 = 0x04;
pub const CFA_offset_extended = 0x05;
pub const CFA_restore_extended = 0x06;
pub const CFA_undefined = 0x07;
pub const CFA_same_value = 0x08;
pub const CFA_register = 0x09;
pub const CFA_remember_state = 0x0a;
pub const CFA_restore_state = 0x0b;
pub const CFA_def_cfa = 0x0c;
pub const CFA_def_cfa_register = 0x0d;
pub const CFA_def_cfa_offset = 0x0e;

// DWARF 3.
pub const CFA_def_cfa_expression = 0x0f;
pub const CFA_expression = 0x10;
pub const CFA_offset_extended_sf = 0x11;
pub const CFA_def_cfa_sf = 0x12;
pub const CFA_def_cfa_offset_sf = 0x13;
pub const CFA_val_offset = 0x14;
pub const CFA_val_offset_sf = 0x15;
pub const CFA_val_expression = 0x16;

pub const CFA_lo_user = 0x1c;
pub const CFA_hi_user = 0x3f;

// SGI/MIPS specific.
pub const CFA_MIPS_advance_loc8 = 0x1d;

// GNU extensions.
pub const CFA_GNU_window_save = 0x2d;
pub const CFA_GNU_args_size = 0x2e;
pub const CFA_GNU_negative_offset_extended = 0x2f;

pub const CHILDREN_no = 0x00;
pub const CHILDREN_yes = 0x01;

pub const LNS_extended_op = 0x00;
pub const LNS_copy = 0x01;
pub const LNS_advance_pc = 0x02;
pub const LNS_advance_line = 0x03;
pub const LNS_set_file = 0x04;
pub const LNS_set_column = 0x05;
pub const LNS_negate_stmt = 0x06;
pub const LNS_set_basic_block = 0x07;
pub const LNS_const_add_pc = 0x08;
pub const LNS_fixed_advance_pc = 0x09;
pub const LNS_set_prologue_end = 0x0a;
pub const LNS_set_epilogue_begin = 0x0b;
pub const LNS_set_isa = 0x0c;

pub const LNE_end_sequence = 0x01;
pub const LNE_set_address = 0x02;
pub const LNE_define_file = 0x03;
pub const LNE_set_discriminator = 0x04;
pub const LNE_lo_user = 0x80;
pub const LNE_hi_user = 0xff;

pub const LANG_C89 = 0x0001;
pub const LANG_C = 0x0002;
pub const LANG_Ada83 = 0x0003;
pub const LANG_C_plus_plus = 0x0004;
pub const LANG_Cobol74 = 0x0005;
pub const LANG_Cobol85 = 0x0006;
pub const LANG_Fortran77 = 0x0007;
pub const LANG_Fortran90 = 0x0008;
pub const LANG_Pascal83 = 0x0009;
pub const LANG_Modula2 = 0x000a;
pub const LANG_Java = 0x000b;
pub const LANG_C99 = 0x000c;
pub const LANG_Ada95 = 0x000d;
pub const LANG_Fortran95 = 0x000e;
pub const LANG_PLI = 0x000f;
pub const LANG_ObjC = 0x0010;
pub const LANG_ObjC_plus_plus = 0x0011;
pub const LANG_UPC = 0x0012;
pub const LANG_D = 0x0013;
pub const LANG_Python = 0x0014;
pub const LANG_Go = 0x0016;
pub const LANG_C_plus_plus_11 = 0x001a;
pub const LANG_Rust = 0x001c;
pub const LANG_C11 = 0x001d;
pub const LANG_C_plus_plus_14 = 0x0021;
pub const LANG_Fortran03 = 0x0022;
pub const LANG_Fortran08 = 0x0023;
pub const LANG_lo_user = 0x8000;
pub const LANG_hi_user = 0xffff;
pub const LANG_Mips_Assembler = 0x8001;
pub const LANG_Upc = 0x8765;
pub const LANG_HP_Bliss = 0x8003;
pub const LANG_HP_Basic91 = 0x8004;
pub const LANG_HP_Pascal91 = 0x8005;
pub const LANG_HP_IMacro = 0x8006;
pub const LANG_HP_Assembler = 0x8007;

pub const UT_compile = 0x01;
pub const UT_type = 0x02;
pub const UT_partial = 0x03;
pub const UT_skeleton = 0x04;
pub const UT_split_compile = 0x05;
pub const UT_split_type = 0x06;
pub const UT_lo_user = 0x80;
pub const UT_hi_user = 0xff;

pub const LNCT_path = 0x1;
pub const LNCT_directory_index = 0x2;
pub const LNCT_timestamp = 0x3;
pub const LNCT_size = 0x4;
pub const LNCT_MD5 = 0x5;
pub const LNCT_lo_user = 0x2000;
pub const LNCT_hi_user = 0x3fff;
