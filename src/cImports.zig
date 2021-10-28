pub usingnamespace @cImport({
    @cInclude("stdio.h");
    @cInclude("fcntl.h");
    @cInclude("unistd.h");
    @cInclude("keyboard/keyboard.h");
    @cInclude("keyboard/codes.h");
    @cInclude("sel4/sel4.h");
    @cInclude("sel4platsupport/bootinfo.h");
    @cInclude("utils/util.h");
    @cInclude("libsel4_zig_wrapper.h");
    @cInclude("sel4tutorials/alloc.h");
    @cInclude("cpio/cpio.h");
    @cInclude("elf/elf.h");
});
