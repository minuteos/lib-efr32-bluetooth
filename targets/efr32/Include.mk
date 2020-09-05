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

EFM32_SDK_BT_DEV = $(OBJDIR)efr32-bt-device/
EFM32_SDK_BT_STACK = $(OBJDIR)efr32-bt-stack/
EFM32_SDK_BT_BIN = $(OBJDIR)efr32-bt-bin/
EFM32_SDK_RAIL = $(OBJDIR)efr32-rail/

EFM32_BT_INCLUDE = $(EFM32_SDK_BT_STACK)inc/
EFM32_RAIL_INCLUDE = $(EFM32_SDK_RAIL)

BGBUILD = $(EFM32_SDK_BT_BIN)bgbuild

INCLUDE_DIRS += $(EFM32_BT_INCLUDE)common $(EFM32_BT_INCLUDE)soc $(EFM32_RAIL_INCLUDE)common $(EFM32_RAIL_INCLUDE)chip/efr32/$(EFM32_RAIL_CHIP)
DEFINES += EFM32_BT_DEVICE=$(EFM32_BT_DEVICE)

LIB_DIRS += $(EFM32_SDK_BT_DEV)GCC/

ifndef BOOTLOADER_BUILD
LIBS += bluetooth psstore rail mbedtls
endif

GATT_DB = $(firstword $(wildcard $(foreach d,$(SOURCE_DIRS),$(d)gatt.xml)))
GATT_PREFIX = $(GATT_DB:.xml=)

.PHONY: efr32_bt_sdk

prebuild: efr32_bt_sdk

efr32_bt_sdk: $(EFM32_SDK_BT_DEV) $(EFM32_SDK_BT_STACK) $(EFM32_SDK_BT_BIN) $(EFM32_SDK_RAIL)

$(BGBUILD): $(EFM32_SDK_BT_BIN)

$(EFM32_SDK_BT_DEV): $(OBJDIR)
	@$(LN) -snf $(EFM32_SDK_ORIGIN_BT_DEV) $(EFM32_SDK_BT_DEV:/=)

$(EFM32_SDK_BT_STACK): $(OBJDIR)
	@$(LN) -snf $(EFM32_SDK_ORIGIN_BT_STACK) $(EFM32_SDK_BT_STACK:/=)

$(EFM32_SDK_BT_BIN): $(OBJDIR)
	@$(LN) -snf $(EFM32_SDK_ORIGIN_BT_BIN) $(EFM32_SDK_BT_BIN:/=)

$(EFM32_SDK_RAIL): $(OBJDIR)
	@$(LN) -snf $(EFM32_SDK_ORIGIN_RAIL) $(EFM32_SDK_RAIL:/=)

$(GATT_DB:.xml=_db.h): $(GATT_DB:.xml=_db.c)
$(GATT_DB:.xml=_db.c): $(GATT_DB) $(BGBUILD)
	$(BGBUILD) -g $<
	$(RM) -f $(call parentdir, $(GATT_DB))constants

prebuild: $(GATT_DB:.xml=_db.c)
