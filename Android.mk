# Copyright (C) 2014 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE:= libkeymaster
LOCAL_SRC_FILES:= \
		authorization_set.cpp \
		dsa_operation.cpp \
		ecdsa_operation.cpp \
		google_keymaster \
		google_keymaster_messages.cpp \
		google_keymaster_utils.cpp \
		key_blob.cpp \
		ocb.c \
		rsa_operation.cpp \
		serializable.cpp
LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/include \
	external/openssl/include
LOCAL_SHARED_LIBRARIES := libcrypto
LOCAL_CFLAGS = -Wall -Werror
LOCAL_MODULE_TAGS := optional
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
include $(BUILD_STATIC_LIBRARY)
