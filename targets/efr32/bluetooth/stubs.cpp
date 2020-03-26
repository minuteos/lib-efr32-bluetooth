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

void PRORTC_IRQHandler_X()
{
    // read PRORTC->IFC to clear it
    (void)*(volatile uint32_t*)0x40044010;
}

void sl_sleeptimer_init()
{
    // timer initialization is kernel's responsibility
    // however, libbluetooth 2.13+ uses PRORTC timer for some cases
    // and relies on it having an interrupt handler that just clears the flags
    Cortex_SetIRQHandler(PRORTC_IRQn, PRORTC_IRQHandler_X);
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

END_EXTERN_C
