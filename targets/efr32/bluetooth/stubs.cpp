/*
 * Copyright (c) 2019 triaxis s.r.o.
 * Licensed under the MIT license. See LICENSE.txt file in the repository root
 * for full license information.
 *
 * efr32/bluetooth/stubs.cpp
 *
 * Stubs for unused functions required by libbluetooth
 */

#include <kernel/kernel.h>

BEGIN_EXTERN_C

void EMU_IRQHandler()
{
    ASSERT(0);
}

void CRYPTO0_IRQHandler()
{
    ASSERT(0);
}

void sl_sleeptimer_init()
{
    // timer initialization is kernel's responsibility
    // however, libbluetooth 2.13+ uses PRORTC timer for some cases
    // and relies on it having an interrupt handler that just clears the flags
    EFM32_SetIRQClearingHandler(PRORTC_IRQn, *(volatile uint32_t*)0x40044010);
}

void sl_sleeptimer_restart_timer()
{
    // must not be called (used only by gecko_wait_event)
    ASSERT(0);
}

uint32_t sl_sleeptimer_get_tick_count()
{
    // the one true time source
    return MONO_CLOCKS;
}

uint32_t sl_sleeptimer_ms32_to_tick(uint32_t time_ms, uint32_t *tick)
{
    *tick = MonoFromMilliseconds(time_ms);
    return 0;
}

OPTIMIZE void* sl_malloc(size_t size) { return malloc(size); }
OPTIMIZE void* sl_calloc(size_t num, size_t size) { return calloc(num, size); }
OPTIMIZE void sl_free(void* ptr) { free(ptr); }

OPTIMIZE void bg_malloc_init() {}
OPTIMIZE void* bg_malloc(size_t size) { return calloc((size + 3) & ~3, 1); }
void* bg_calloc(size_t size) __attribute__((alias("sl_calloc")));
void* bg_zalloc(size_t size) __attribute__((alias("bg_malloc")));
void bg_free(void* ptr) __attribute__((alias("sl_free")));

END_EXTERN_C
