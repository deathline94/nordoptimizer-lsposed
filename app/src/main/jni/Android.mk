LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE    := nordjunk
LOCAL_SRC_FILES := nordjunk.c
LOCAL_CFLAGS    := -O2 -fvisibility=hidden
LOCAL_LDLIBS    := -llog
include $(BUILD_SHARED_LIBRARY)
