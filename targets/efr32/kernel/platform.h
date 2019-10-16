/*
 * Copyright (c) 2019 triaxis s.r.o.
 * Licensed under the MIT license. See LICENSE.txt file in the repository root
 * for full license information.
 *
 * efr32/kernel/platform.h
 */

// override sleep implementation

extern void Bluetooth_Sleep(uint32_t start, uint32_t ticks);

extern uint32_t Bluetooth_NoDeepSleep;

#define PLATFORM_SLEEP Bluetooth_Sleep
#define PLATFORM_DEEP_SLEEP_ENABLE()    (Bluetooth_NoDeepSleep--)
#define PLATFORM_DEEP_SLEEP_DISABLE()   (Bluetooth_NoDeepSleep++)
#define PLATFORM_DEEP_SLEEP_ENABLED()   (!Bluetooth_NoDeepSleep)

#include_next <kernel/platform.h>
