/*
 * Copyright (c) 2019 triaxis s.r.o.
 * Licensed under the MIT license. See LICENSE.txt file in the repository root
 * for full license information.
 *
 * efr32/bluetooth/stubs.cpp
 *
 * Stubs for unused functions required by libbluetooth
 */

#include <base/base.h>

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

END_EXTERN_C
