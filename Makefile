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
	-Werror=sign-compare -Wmissing-declarations -ftest-coverage -fno-permissive \
	-Wno-deprecated-declarations -fno-exceptions -DKEYMASTER_NAME_TAGS \
	$(COMPILER_SPECIFIC_ARGS)

# Uncomment to enable debug logging.
# CXXFLAGS += -DDEBUG

LDLIBS=-lcrypto -lpthread -lstdc++ -lgcov

CPPSRCS=\
	abstract_factory_registry_test.cpp \
	aead_mode_operation.cpp \
	aes_key.cpp \
	aes_operation.cpp \
	asymmetric_key.cpp \
	authorization_set.cpp \
	authorization_set_test.cpp \
	ec_key.cpp \
	ecdsa_operation.cpp \
	google_keymaster.cpp \
	google_keymaster_messages.cpp \
	google_keymaster_messages_test.cpp \
	google_keymaster_test.cpp \
	google_keymaster_test_utils.cpp \
	google_keymaster_utils.cpp \
	hkdf.cpp \
	hkdf_test.cpp \
	hmac.cpp \
	hmac_test.cpp \
	hmac_key.cpp \
	hmac_operation.cpp \
	key.cpp \
	key_blob.cpp \
	key_blob_test.cpp \
	keymaster_enforcement.cpp \
	keymaster_enforcement_test.cpp \
	logger.cpp \
	openssl_err.cpp \
	openssl_utils.cpp \
	operation.cpp \
	operation_table.cpp \
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

BINARIES = abstract_factory_registry_test \
	authorization_set_test \
	google_keymaster_test \
	google_keymaster_messages_test \
	hkdf_test \
	hmac_test \
	key_blob_test \
	keymaster_enforcement_test \

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

hmac_test: hmac_test.o \
	hmac.o \
	authorization_set.o \
	google_keymaster_test_utils.o \
	logger.o \
	serializable.o \
	$(GTEST)/src/gtest-all.o

hkdf_test: hkdf_test.o \
	hkdf.o \
	hmac.o \
	authorization_set.o \
	logger.o \
	google_keymaster_test_utils.o \
	serializable.o \
	$(GTEST)/src/gtest-all.o

authorization_set_test: authorization_set_test.o \
	authorization_set.o \
	google_keymaster_test_utils.o \
	logger.o \
	serializable.o \
	$(GTEST)/src/gtest-all.o

key_blob_test: key_blob_test.o \
	authorization_set.o \
	google_keymaster_test_utils.o \
	key_blob.o \
	logger.o \
	ocb.o \
	openssl_err.o \
	serializable.o \
	unencrypted_key_blob.o \
	$(GTEST)/src/gtest-all.o

google_keymaster_messages_test: google_keymaster_messages_test.o \
	authorization_set.o \
	google_keymaster_messages.o \
	google_keymaster_test_utils.o \
	google_keymaster_utils.o \
	logger.o \
	serializable.o \
	$(GTEST)/src/gtest-all.o

google_keymaster_test: google_keymaster_test.o \
	aead_mode_operation.o \
	aes_key.o \
	aes_operation.o \
	asymmetric_key.o \
	authorization_set.o \
	ec_key.o \
	ecdsa_operation.o \
	google_keymaster.o \
	google_keymaster_messages.o \
	google_keymaster_test_utils.o \
	google_keymaster_utils.o \
	hmac_key.o \
	hmac_operation.o \
	key.o \
	key_blob.o \
	logger.o \
	ocb.o \
	openssl_err.o \
	openssl_utils.o \
	operation.o \
	operation_table.o \
	rsa_key.o \
	rsa_operation.o \
	serializable.o \
	soft_keymaster_device.o \
	symmetric_key.o \
	unencrypted_key_blob.o \
	$(GTEST)/src/gtest-all.o

abstract_factory_registry_test: abstract_factory_registry_test.o \
	logger.o \
	$(GTEST)/src/gtest-all.o

keymaster_enforcement_test: keymaster_enforcement_test.o \
	keymaster_enforcement.o \
	authorization_set.o \
	google_keymaster_utils.o \
	google_keymaster_messages.o \
	google_keymaster_test_utils.o \
	logger.o \
	serializable.o \
	$(GTEST)/src/gtest-all.o

$(GTEST)/src/gtest-all.o: CXXFLAGS:=$(subst -Wmissing-declarations,,$(CXXFLAGS))
ocb.o: CFLAGS=$(CLANG_TEST_DEFINE)

clean:
	rm -f $(OBJS) $(DEPS) $(BINARIES) \
		$(BINARIES:=.run) $(BINARIES:=.memcheck) $(BINARIES:=.massif) \
		*gcov *gcno *gcda coverage.info
	rm -rf coverage

-include $(CPPSRCS:.cpp=.d)
-include $(CCSRCS:.cc=.d)

