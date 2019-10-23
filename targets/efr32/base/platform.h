/*
 * Copyright (c) 2019 triaxis s.r.o.
 * Licensed under the MIT license. See LICENSE.txt file in the repository root
 * for full license information.
 *
 * efr32/base/platform.h
 *
 * Configures platform definitions required for libbluetooth to work
 */

#ifndef EFM32_HFXO_FREQUENCY
#define EFM32_HFXO_FREQUENCY    38400000
#endif

#ifndef EFM32_LFXO_FREQUENCY
#define EFM32_LFXO_FREQUENCY    32768
#endif

#ifndef EFM32_WAIT_FOR_LFXO
#define EFM32_WAIT_FOR_LFXO     1
#endif

#ifndef EFM32_WAIT_FOR_HFXO
#define EFM32_WAIT_FOR_HFXO     1
#endif

#ifndef EFR32_RAIL_SLEEP
#define EFR32_RAIL_SLEEP    1
#endif

#ifndef EFM32_USE_DCDC
#define EFM32_USE_DCDC      1
#endif

#include_next <base/platform.h>
