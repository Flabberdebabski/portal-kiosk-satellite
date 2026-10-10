SDK ?= $(if $(ANDROID_SDK_ROOT),$(ANDROID_SDK_ROOT),/home/jxlarrea/android-sdk)
NDK ?= $(SDK)/ndk/28.2.13676358
TOOLCHAIN ?= $(NDK)/toolchains/llvm/prebuilt/linux-x86_64
CXX := $(TOOLCHAIN)/bin/aarch64-linux-android29-clang++
CC := $(TOOLCHAIN)/bin/aarch64-linux-android29-clang
OBJCOPY := $(TOOLCHAIN)/bin/llvm-objcopy
BUILD := build
WATCH := $(BUILD)/portal-camera-led-watch
HOOK_OBJECT := $(BUILD)/portal-uid1000-hook.o
HOOK := $(BUILD)/portal-uid1000-hook.bin

.PHONY: all clean
all: $(WATCH) $(HOOK)

$(WATCH): native/portal_camera_led_watch.cpp
	mkdir -p $(BUILD)
	$(CXX) --target=aarch64-linux-android29 -std=c++17 -O2 -fPIE -pie \
		-fvisibility=hidden -Wl,--gc-sections -static-libstdc++ \
		$< -o $@ -ldl -llog

$(HOOK_OBJECT): native/boot_hook.S
	mkdir -p $(BUILD)
	$(CC) --target=aarch64-linux-android29 -c $< -o $@

$(HOOK): $(HOOK_OBJECT)
	$(OBJCOPY) --only-section=.text -O binary $< $@
	test "$$(stat -c %s $@)" -le 316

clean:
	rm -rf $(BUILD)
