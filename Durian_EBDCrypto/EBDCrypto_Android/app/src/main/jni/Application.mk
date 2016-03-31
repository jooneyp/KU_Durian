APP_PROJECT_PATH := $(shell pwd)

APP_ABI := armeabi-v7a
APP_PLATFORM := android-19
APP_MODULES := EBDCrypto_JNI_android
APP_OPTIM := release
APP_BUILD_SCRIPT := $(APP_PROJECT_PATH)/jni/Android.mk
APP_CFLAGS := -O3

