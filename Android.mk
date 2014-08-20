#
# Copyright (c) 2012-2014, NVIDIA CORPORATION. All rights reserved
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MULTILIB := 32

LOCAL_MODULE:= trusty_keymaster
LOCAL_C_INCLUDES:= $(LOCAL_PATH) \
	$(TOP)/3rdparty/ote/lib/include \
	$(TOP)/external/openssl/include

LOCAL_SHARED_LIBRARIES := libstlport
LOCAL_SRC_FILES:= \
		serializable.cpp \
		google_keymaster_messages.cpp \
		authorization_set.cpp \
		trusty_keymaster_device.cpp \
		trusty_keymaster_lib.c

LOCAL_STATIC_LIBRARIES:= \
		libtlk_client \
		libtlk_common

include external/libcxx/libcxx.mk
include external/stlport/libstlport.mk

include $(BUILD_EXECUTABLE)