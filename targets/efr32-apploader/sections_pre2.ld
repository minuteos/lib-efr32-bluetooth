SECTIONS {
    .bin.apploader :
    {
        KEEP(*(.binapploader*))
    } >FLASH

    .bin.apploader.sig :
    {
        . = ALIGN(2048);
    } >FLASH
}
