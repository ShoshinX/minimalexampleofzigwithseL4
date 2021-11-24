

SECTIONS{
    .text : ALIGN(4K) {
        *(.text)
        __debug_info_start = .;
        *(.debug_info)
        __debug_info_end = .;
        __debug_abbrev_start = .;
        *(.debug_abbrev)
        __debug_abbrev_end = .;
        __debug_str_start = .;
        *(.debug_str)
        __debug_str_end = .;
        __debug_line_start = .;
        *(.debug_line)
        __debug_line_end = .;
        __debug_ranges_start = .;
        *(.debug_ranges)
        __debug_ranges_end = .;
    }
}
INSERT AFTER .init;
