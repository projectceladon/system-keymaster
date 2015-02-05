BASE=../..
SUBS=system/core \
	hardware/libhardware \
	external/gtest
GTEST=$(BASE)/external/gtest

INCLUDES=$(foreach dir,$(SUBS),-I $(BASE)/$(dir)/include) \
	-I $(BASE)/libnativehelper/include/nativehelper \
	-I $(GTEST) -Iinclude

ifdef USE_CLANG
CC=/usr/bin/clang
CXX=/usr/bin/clang
CLANG_TEST_DEFINE=-DKEYMASTER_CLANG_TEST_BUILD
COMPILER_SPECIFIC_ARGS=-std=c++11 $(CLANG_TEST_DEFINE)
else
COMPILER_SPECIFIC_ARGS=-std=c++0x -fprofile-arcs
endif

CPPFLAGS=$(INCLUDES) -g -O0 -MD
CXXFLAGS=-Wall -Werror -Wno-unused -Winit-self -Wpointer-arith	-Wunused-parameter \
	-Wmissing-declarations -ftest-coverage \
	-Wno-deprecated-declarations -fno-exceptions -DKEYMASTER_NAME_TAGS \
	$(COMPILER_SPECIFIC_ARGS)
LDLIBS=-lcrypto -lpthread -lstdc++

CPPSRCS=\
	aead_mode_operation.cpp \
	aes_key.cpp \
	aes_operation.cpp \
	asymmetric_key.cpp \
	authorization_set.cpp \
	authorization_set_test.cpp \
	ecdsa_key.cpp \
	ecdsa_operation.cpp \
	google_keymaster.cpp \
	google_keymaster_messages.cpp \
	google_keymaster_messages_test.cpp \
	google_keymaster_test.cpp \
	google_keymaster_test_utils.cpp \
	google_keymaster_utils.cpp \
	hmac_key.cpp \
	hmac_operation.cpp \
	key.cpp \
	key_blob.cpp \
	key_blob_test.cpp \
	rsa_key.cpp \
	rsa_operation.cpp \
	serializable.cpp \
	soft_keymaster_device.cpp \
	symmetric_key.cpp \
	unencrypted_key_blob.cpp
CCSRCS=$(GTEST)/src/gtest-all.cc
CSRCS=ocb.c

OBJS=$(CPPSRCS:.cpp=.o) $(CCSRCS:.cc=.o) $(CSRCS:.c=.o)
DEPS=$(CPPSRCS:.cpp=.d) $(CCSRCS:.cc=.d) $(CSRCS:.c=.d)

LINK.o=$(LINK.cc)

BINARIES=authorization_set_test \
	google_keymaster_test \
	google_keymaster_messages_test \
	key_blob_test

.PHONY: coverage memcheck massif clean run

%.run: %
	./$<
	touch $@

run: $(BINARIES:=.run)

coverage: coverage.info
	genhtml coverage.info --output-directory coverage

coverage.info: run
	lcov --capture --directory=. --output-file coverage.info

%.coverage : %
	$(MAKE) clean && $(MAKE) $<
	./$<
	lcov --capture --directory=. --output-file coverage.info
	genhtml coverage.info --output-directory coverage

#UNINIT_OPTS=--track-origins=yes
UNINIT_OPTS=--undef-value-errors=no

MEMCHECK_OPTS=--leak-check=full \
	--show-reachable=yes \
	--vgdb=full \
	$(UNINIT_OPTS) \
	--error-exitcode=1

MASSIF_OPTS=--tool=massif \
	--stacks=yes

%.memcheck : %
	valgrind $(MEMCHECK_OPTS) ./$< && \
	touch $@

%.massif : %
	valgrind $(MASSIF_OPTS) --massif-out-file=$@ ./$<

memcheck: $(BINARIES:=.memcheck)

massif: $(BINARIES:=.massif)

authorization_set_test: authorization_set_test.o \
	authorization_set.o \
	google_keymaster_test_utils.o \
	serializable.o \
	$(GTEST)/src/gtest-all.o

key_blob_test: key_blob_test.o \
	authorization_set.o \
	google_keymaster_test_utils.o \
	key_blob.o \
	ocb.o \
	serializable.o \
	unencrypted_key_blob.o \
	$(GTEST)/src/gtest-all.o

google_keymaster_messages_test: google_keymaster_messages_test.o \
	authorization_set.o \
	google_keymaster_messages.o \
	google_keymaster_test_utils.o \
	google_keymaster_utils.o \
	serializable.o \
	$(GTEST)/src/gtest-all.o

google_keymaster_test: google_keymaster_test.o \
	aead_mode_operation.o \
	aes_key.o \
	aes_operation.o \
	asymmetric_key.o \
	authorization_set.o \
	ecdsa_key.o \
	ecdsa_operation.o \
	google_keymaster.o \
	google_keymaster_messages.o \
	google_keymaster_test_utils.o \
	google_keymaster_utils.o \
	hmac_key.o \
	hmac_operation.o \
	key.o \
	key_blob.o \
	ocb.o \
	rsa_key.o \
	rsa_operation.o \
	serializable.o \
	soft_keymaster_device.o \
	symmetric_key.o \
	unencrypted_key_blob.o \
	$(GTEST)/src/gtest-all.o

$(GTEST)/src/gtest-all.o: CXXFLAGS:=$(subst -Wmissing-declarations,,$(CXXFLAGS))
ocb.o: CFLAGS=$(CLANG_TEST_DEFINE)

clean:
	rm -f $(OBJS) $(DEPS) $(BINARIES) \
		$(BINARIES:=.run) $(BINARIES:=.memcheck) $(BINARIES:=.massif) \
		*gcno *gcda coverage.info
	rm -rf coverage

-include $(CPPSRCS:.cpp=.d)
-include $(CCSRCS:.cc=.d)

