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

END_EXTERN_C
