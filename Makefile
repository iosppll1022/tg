# Theos 可选；无 Theos 请用 Makefile.clang / build.sh
TARGET := iphone:clang:latest:14.0
INSTALL_TARGET_PROCESSES = Telegram
ARCHS = arm64

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = TelegramAntiRecall
TelegramAntiRecall_FILES = src/AntiRecall.m
TelegramAntiRecall_CFLAGS = -fobjc-arc -Wno-unused-function
TelegramAntiRecall_FRAMEWORKS = Foundation

include $(THEOS_MAKE_PATH)/tweak.mk
