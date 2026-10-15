# Theos 编译（越狱设备注入用 .deb / 动态库）
# 用法：
#   export THEOS=/path/to/theos
#   make package
#
# 无 Theos 时见 README「clang 交叉编译」一节。

TARGET := iphone:clang:latest:14.0
ARCHS := arm64 arm64e
INSTALL_TARGET_PROCESSES = Telegram

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = TelegramAntiRecall

TelegramAntiRecall_FILES = src/AntiRecall.m vendor/fishhook/fishhook.c
TelegramAntiRecall_CFLAGS = -fobjc-arc -Ivendor/fishhook -Wno-unused-function
TelegramAntiRecall_FRAMEWORKS = Foundation
TelegramAntiRecall_LOGOS_DEFAULT_GENERATOR = internal

# 若 SDK / 工具链带 substrate：取消下一行注释并链入
# TelegramAntiRecall_LIBRARIES = substrate

include $(THEOS_MAKE_PATH)/tweak.mk

after-package::
	@echo "Built $(THEOS_PACKAGE_DIR)/$(THEOS_PACKAGE_NAME)*.deb"
