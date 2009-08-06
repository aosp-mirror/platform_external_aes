LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES :=  \
    aescrypt.c      \
    aeskey.c        \
    aestab.c

LOCAL_MODULE := libaes

# include $(BUILD_SHARED_LIBRARY)
