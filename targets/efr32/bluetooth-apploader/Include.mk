#
# Copyright (c) 2019 triaxis s.r.o.
# Licensed under the MIT license. See LICENSE.txt file in the repository root
# for full license information.
#
# efr32/bluetooth-apploader/Include.mk
#

ADDITIONAL_BLOBS += $(EFM32_SDK_BT_DEV)GCC/binapploader.o

TARGETS += efr32-apploader

$(EFM32_SDK_BT_DEV)GCC/binapploader.o: $(EFM32_SDK_BT_DEV)
