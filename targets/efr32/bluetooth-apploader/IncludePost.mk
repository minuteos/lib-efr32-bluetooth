#
# Copyright (c) 2019 triaxis s.r.o.
# Licensed under the MIT license. See LICENSE.txt file in the repository root
# for full license information.
#
# efr32/bluetooth-apploader/IncludePost.mk
#

ifneq (,$(GECKO_SIGN_KEY))

# we must sign the apploader as well
GECKO_APPLOADER_SREC = $(OBJDIR)apploader.s37
GECKO_APPLOADER_SIGNED_SREC = $(OBJDIR)apploader-signed.s37
GECKO_APPLOADER_SIGNED = $(OBJDIR)apploader-signed.o

ADDITIONAL_BLOBS += $(GECKO_APPLOADER_SIGNED)

$(GECKO_APPLOADER_SREC): $(GECKO_APPLOADER)
	$(OBJCOPY) -O srec --srec-forceS3 $< $@

$(GECKO_APPLOADER_SIGNED_SREC): $(GECKO_APPLOADER_SREC)
	$(SI_COMMANDER) convert $< --secureboot --keyfile $(GECKO_SIGN_KEY) -o $@

$(GECKO_APPLOADER_SIGNED): $(GECKO_APPLOADER_SIGNED_SREC)
	$(OBJCOPY) -I srec -O elf32-littlearm -B arm --rename-section .sec1=.binapploader $< $@

else

ADDITIONAL_BLOBS += $(GECKO_APPLOADER)

endif


