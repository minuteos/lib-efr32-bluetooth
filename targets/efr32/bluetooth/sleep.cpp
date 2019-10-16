/*
 * Copyright (c) 2019 triaxis s.r.o.
 * Licensed under the MIT license. See LICENSE.txt file in the repository root
 * for full license information.
 *
 * efr32/bluetooth/sleep.cpp
 *
 * Alternate sleep implementation for libbluetooth compatible with our kernel
 */

#include <kernel/kernel.h>

#include <hw/SCB.h>

#include "Bluetooth.h"

uint32_t Bluetooth_NoDeepSleep;

// use libbluetooth sleep implementation
extern "C" void BG_Sleep(uint32_t ticks);

void Bluetooth_Sleep(uint32_t since, uint32_t ticks)
{
    if (bluetooth.Initialized())
    {
        BG_Sleep(ticks);
    }
    else
    {
        Cortex_Sleep(since + ticks);
    }
}

BEGIN_EXTERN_C

// the sleep function should never get called directly
void SLEEP_Sleep()
{
    if (Bluetooth_NoDeepSleep)
        SCB->Sleep();
    else
    {
#ifdef CORTEX_DEEP_SLEEP_PREPARE
        CORTEX_DEEP_SLEEP_PREPARE();
#endif
        SCB->DeepSleep();
#ifdef CORTEX_DEEP_SLEEP_RESTORE
        CORTEX_DEEP_SLEEP_RESTORE();
#endif
    }
}

END_EXTERN_C
