ifeq (,$(SI_INSTALL))

# validate paths
ifeq (,$(wildcard $(EFM32_SDK_ORIGIN_BT_BIN)))
  $(error Failed to locate EFR32 Bluetooth SDK in $(EFM32_SDK_ORIGIN), use 'make si-install PACKAGE=com.silabs.stack.ble.v2.xx' to install it. \
Bluetooth SDK versions are typically Platform Version + 6 (e.g. for SDK v2.7 use v2.13))
endif

endif

