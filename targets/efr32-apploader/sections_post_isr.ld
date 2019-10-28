/*
 * Copyright (c) 2019 triaxis s.r.o.
 * Licensed under the MIT license. See LICENSE.txt file in the repository root
 * for full license information.
 *
 * efr32-apploader/sections_post_isr.ld
 *
 * Additional section inserted after the main ISR table, which adds
 * the Gecko Bootloader Application Properties table (and pointer to it)
 * at the appropriate places
 */

SECTIONS {
    .application_properties : {
        . = __app_start + 0x34; /* pointer must be at offset 0x34 */
        LONG(__app_properties);
        __app_properties = .;
        KEEP(*(.application_properties));
    } >FLASH
}
