SECTIONS {
    .text_apploader :
    {
        KEEP(*(.binapploader*))
    } >FLASH

    .text_signature :
    {
        . = ALIGN(2048);
    } >FLASH
}
