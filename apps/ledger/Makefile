# Kokuin Ledger App - Makefile

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif

include $(BOLOS_SDK)/Makefile.target

# Override git-based app dir detection (fails in Docker volume mounts)
APP_DIR := $(CURDIR)

APPNAME      = "Kokuin"
APPVERSION_M = 0
APPVERSION_N = 1
APPVERSION_P = 0
APPVERSION   = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)"

APP_SOURCE_PATH += src

# App icon (14x14) — the SDK generates the C_kokuin_app_14px glyph from it.
ICON_NANOX  = icons/kokuin_app_14px.gif
ICON_NANOSP = icons/kokuin_app_14px.gif

CURVE_APP_LOAD_PARAMS = ed25519
PATH_APP_LOAD_PARAMS  = "44'/876'"

VARIANT_PARAM  = COIN
VARIANT_VALUES = KOK

ENABLE_BLUETOOTH = 1

# The Nano UI uses NBGL (BAGL/ux_flow is unavailable on this SDK).
ENABLE_NBGL_FOR_NANO_DEVICES = 1

include $(BOLOS_SDK)/Makefile.standard_app
