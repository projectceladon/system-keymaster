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

###
# libkeymaster_messages contains just the code necessary to communicate with a
# GoogleKeymaster implementation, e.g. one running in TrustZone.
##
include $(CLEAR_VARS)
# Disable clang until we find a way to suppress clang optmization in google_keymaster_utils.h.
LOCAL_CLANG := false
LOCAL_MODULE:= libkeymaster_messages
LOCAL_SRC_FILES:= \
		authorization_set.cpp \
		google_keymaster_messages.cpp \
		google_keymaster_utils.cpp \
		key_blob.cpp \
		serializable.cpp
LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/include
LOCAL_CFLAGS = -Wall -Werror
LOCAL_MODULE_TAGS := optional
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
include $(BUILD_SHARED_LIBRARY)

###
# libkeymaster contains almost everything needed for a keymaster implementation,
# lacking only a subclass of the (abstract) GoogleKeymaster class to provide
# environment-specific services and a wrapper to translate from the
# function-based keymaster HAL API to the message-based GoogleKeymaster API.
###
include $(CLEAR_VARS)
# Disable clang until we find a way to suppress clang optmization in google_keymaster_utils.h.
LOCAL_CLANG := false
LOCAL_MODULE:= libkeymaster
LOCAL_SRC_FILES:= \
		aead_mode_operation.cpp \
		aes_key.cpp \
		aes_operation.cpp \
		asymmetric_key.cpp \
		authorization_set.cpp \
		ecdsa_key.cpp \
		ecdsa_operation.cpp \
		google_keymaster.cpp \
		google_keymaster_messages.cpp \
		google_keymaster_utils.cpp \
		hmac_key.cpp \
		hmac_operation.cpp \
		key.cpp \
		key_blob.cpp \
		logger.cpp \
		ocb.c \
		operation.cpp \
		rsa_key.cpp \
		rsa_operation.cpp \
		serializable.cpp \
		symmetric_key.cpp \
		unencrypted_key_blob.cpp
LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/include
LOCAL_SHARED_LIBRARIES := libcrypto
LOCAL_CFLAGS = -Wall -Werror
LOCAL_MODULE_TAGS := optional
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
include $(BUILD_SHARED_LIBRARY)


###
# libsoftkeymaster provides a software-based keymaster HAL implementation.
# This is used by keystore as a fallback for when the hardware keymaster does
# not support the request.
###
include $(CLEAR_VARS)
LOCAL_MODULE := libsoftkeymasterdevice
LOCAL_SRC_FILES := \
	soft_keymaster_device.cpp \
	soft_keymaster_logger.cpp
LOCAL_C_INCLUDES := \
	system/security/keystore
LOCAL_CFLAGS = -Wall -Werror
LOCAL_SHARED_LIBRARIES := libkeymaster liblog
LOCAL_MODULE_TAGS := optional
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
include $(BUILD_SHARED_LIBRARY)
