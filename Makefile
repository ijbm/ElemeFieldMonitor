TARGET := iphone:clang:latest:15.0
ARCHS = arm64
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = ElemeFieldMonitor

ElemeFieldMonitor_FILES = Tweak.x
ElemeFieldMonitor_CFLAGS = -fobjc-arc -Wno-deprecated-declarations -Wno-unused-variable -Wno-unused-function
ElemeFieldMonitor_FRAMEWORKS = UIKit Foundation Security
ElemeFieldMonitor_PRIVATE_FRAMEWORKS = 

include $(THEOS_MAKE_PATH)/tweak.mk
