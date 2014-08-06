BASE=../..
SUBS=system/core \
	hardware/libhardware \
	external/gtest

INCLUDES=$(foreach dir,$(SUBS),-I $(BASE)/$(dir)/include) \
	-I $(BASE)/system/core/include/utils \
	-I $(BASE)/external/gtest

CPPFLAGS=$(INCLUDES) -g -O0 -MD
CXXFLAGS=-Wall -Werror -Wno-unused -Winit-self -Wpointer-arith	-Wunused-parameter \
	-Wmissing-declarations -std=c++0x -fprofile-arcs -ftest-coverage \
	-Wno-deprecated-declarations -fno-exceptions
LDLIBS=-lcrypto -lpthread

CPPSRCS=authorization_set.cpp \
	authorization_set_test.cpp \
	google_keymaster.cpp \
	google_keymaster_test.cpp \
	google_keymaster_messages.cpp \
	google_keymaster_messages_test.cpp \
	serializable.cpp
CCSRCS=$(BASE)/external/gtest/src/gtest-all.cc
CSRCS=ocb.c

OBJS=$(CPPSRCS:.cpp=.o) $(CCSRCS:.cc=.o) $(CSRCS:.c=.o)
DEPS=$(CPPSRCS:.cpp=.d) $(CCSRCS:.cc=.d) $(CSRCS:.c=.d)

LINK.o=$(LINK.cc)

BINARIES=authorization_set_test \
	google_keymaster_test \
	google_keymaster_messages_test

.PHONY: coverage valgrind clean run

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

VALGRIND_OPTS=--leak-check=full \
	--show-reachable=yes \
	--vgdb=full \
	$(UNINIT_OPTS) \
	--error-exitcode=1

%.valgrind : %
	valgrind $(VALGRIND_OPTS) ./$< && \
	touch $@

valgrind: $(BINARIES:=.valgrind)

authorization_set_test: authorization_set_test.o \
	authorization_set.o \
	serializable.o \
	$(BASE)/external/gtest/src/gtest-all.o

google_keymaster_test: google_keymaster_test.o \
	google_keymaster.o \
	google_keymaster_messages.o \
	authorization_set.o \
	serializable.o \
	ocb.o \
	$(BASE)/external/gtest/src/gtest-all.o

google_keymaster_messages_test: google_keymaster_messages_test.o \
	google_keymaster_messages.o \
	authorization_set.o \
	serializable.o \
	$(BASE)/external/gtest/src/gtest-all.o

$(BASE)/external/gtest/src/gtest-all.o: CXXFLAGS:=$(subst -Wmissing-declarations,,$(CXXFLAGS))

clean:
	rm -f $(OBJS) $(DEPS) $(BINARIES) $(BINARIES:=.run) $(BINARIES:=.valgrind) \
		*gcno *gcda coverage.info
	rm -rf coverage

-include $(CPPSRCS:.cpp=.d)
-include $(CCSRCS:.cc=.d)

