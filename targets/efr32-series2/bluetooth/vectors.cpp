/*
 * Copyright (c) 2020 triaxis s.r.o.
 * Licensed under the MIT license. See LICENSE.txt file in the repository root
 * for full license information.
 *
 * efr32-series2/vectors.cpp
 *
 * Replace vectors_init implementation from libbluetooth,
 * it wastes RAM by reserving another ISR table and doesn't register all
 * required vectors anyway
 */

#include <base/base.h>

BEGIN_EXTERN_C

void vectors_register()
{
    // NOP
}

void vectors_init()
{
    Cortex_SetIRQHandler(AGC_IRQn,AGC_IRQHandler);
    Cortex_SetIRQHandler(BUFC_IRQn,BUFC_IRQHandler);
    Cortex_SetIRQHandler(FRC_PRI_IRQn,FRC_PRI_IRQHandler);
    Cortex_SetIRQHandler(FRC_IRQn,FRC_IRQHandler);
    Cortex_SetIRQHandler(MODEM_IRQn,MODEM_IRQHandler);
    Cortex_SetIRQHandler(PROTIMER_IRQn,PROTIMER_IRQHandler);
    Cortex_SetIRQHandler(RAC_RSM_IRQn,RAC_RSM_IRQHandler);
    Cortex_SetIRQHandler(RAC_SEQ_IRQn,RAC_SEQ_IRQHandler);
    Cortex_SetIRQHandler(RDMAILBOX_IRQn, RDMAILBOX_IRQHandler);
    Cortex_SetIRQHandler(RFSENSE_IRQn, RFSENSE_IRQHandler);
    Cortex_SetIRQHandler(PRORTC_IRQn,PRORTC_IRQHandler);
    Cortex_SetIRQHandler(SYNTH_IRQn,SYNTH_IRQHandler);
}

END_EXTERN_C
