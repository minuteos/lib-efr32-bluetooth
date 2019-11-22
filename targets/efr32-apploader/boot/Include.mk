#
# Copyright (c) 2019 triaxis s.r.o.
# Licensed under the MIT license. See LICENSE.txt file in the repository root
# for full license information.
#
# efr32-apploader/boot/Include.mk
#

ifeq (bootloader,$(NAME))

DEFINES += GECKO_BOOTLOADER_STORAGE_RESERVE=0xC000

endif
