LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := EBDCrypto_JNI_android

#LOCAL_ARM_MODE := thumb
LOCAL_SRC_FILES := NativeC.c source/aes.c source/BN.c source/ecdsa.c source/entropy.c source/GFP.c source/GFP_EC.c source/hash_drbg.c source/sha2.c source/ca_android.c

# common_CFLAGS := -I \home\ryuki\android-ndk-r10d\platforms\android-19\arch-arm\usr\include
LOCAL_LDLIBS := -llog
LOCAL_C_INCLUDES := $(NDK_PROJECT_PATH)/jni/include/ frameworks/base/include

LOCAL_SHARED_LIBRARIES := libtuils libctuils

# optimization
LOCAL_CFLAGS := -O3 -DCONFIG_EMBEDDED
APP_OPTIM := release

include $(BUILD_SHARED_LIBRARY)