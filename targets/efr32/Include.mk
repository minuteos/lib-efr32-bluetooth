#
# Copyright (c) 2019 triaxis s.r.o.
# Licensed under the MIT license. See LICENSE.txt file in the repository root
# for full license information.
#
# efr32/Include.mk
#

EFM32_BT_DEVICE ?= $(EFM32_DEVICE)
EFM32_SDK_ORIGIN_BT_DEV = $(EFM32_SDK_ORIGIN)protocol/bluetooth/lib/$(EFM32_BT_DEVICE)/
EFM32_SDK_ORIGIN_BT_STACK = $(EFM32_SDK_ORIGIN)protocol/bluetooth/ble_stack/
EFM32_SDK_ORIGIN_BT_BIN = $(EFM32_SDK_ORIGIN)protocol/bluetooth/bin/
EFM32_SDK_ORIGIN_RAIL = $(EFM32_SDK_ORIGIN)platform/radio/rail_lib/

EFM32_SDK_BT_DEV = $(OUTDIR)efr32-bt-device/
EFM32_SDK_BT_STACK = $(OUTDIR)efr32-bt-stack/
EFM32_SDK_BT_BIN = $(OUTDIR)efr32-bt-bin/
EFM32_SDK_RAIL = $(OUTDIR)efr32-rail/

EFM32_BT_INCLUDE = $(EFM32_SDK_BT_STACK)inc/
EFM32_RAIL_INCLUDE = $(EFM32_SDK_RAIL)

# the libs are compiled with soft FP ABI
CORTEX_FLOAT_ABI = softfp

BGBUILD = $(EFM32_SDK_BT_BIN)bgbuild

INCLUDE_DIRS += $(EFM32_BT_INCLUDE)common $(EFM32_BT_INCLUDE)soc $(EFM32_RAIL_INCLUDE)common $(EFM32_RAIL_INCLUDE)chip/efr32/$(EFM32_RAIL_CHIP)
DEFINES += EFM32_BT_DEVICE=$(EFM32_BT_DEVICE)

LIB_DIRS += $(EFM32_SDK_BT_DEV)GCC/
LIBS += bluetooth psstore rail mbedtls

GATT_DB = $(firstword $(wildcard $(foreach d,$(SOURCE_DIRS),$(d)gatt.xml)))
GATT_PREFIX = $(GATT_DB:.xml=)

.PHONY: efr32_bt_sdk

prebuild: efr32_bt_sdk

efr32_bt_sdk: efm32_sdk
	@$(LN) -snf $(EFM32_SDK_ORIGIN_BT_DEV) $(EFM32_SDK_BT_DEV:/=)
	@$(LN) -snf $(EFM32_SDK_ORIGIN_BT_STACK) $(EFM32_SDK_BT_STACK:/=)
	@$(LN) -snf $(EFM32_SDK_ORIGIN_BT_BIN) $(EFM32_SDK_BT_BIN:/=)
	@$(LN) -snf $(EFM32_SDK_ORIGIN_RAIL) $(EFM32_SDK_RAIL:/=)

$(GATT_DB:.xml=_db.h): $(GATT_DB:.xml=_db.c)
$(GATT_DB:.xml=_db.c): $(GATT_DB)
	$(BGBUILD) -g $<

prebuild: $(GATT_DB:.xml=_db.c)
