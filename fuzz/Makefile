# SPDX-License-Identifier: Apache-2.0

MODE	?= libFuzzer
BUILD	?= ..

ifeq ($(shell test -e $(BUILD)/libgost_core.a && echo 1),1)
# engine should be already configured
include $(BUILD)/CMakeFiles/gost_engine.dir/flags.make
else
$(error Compile engine first)
endif

LINK	= $(shell grep -o -e -Wl,-rpath.* $(BUILD)/CMakeFiles/gost_engine.dir/link.txt \
	  | sed s/:/:$(BUILD)/ \
	  | sed s,libgost_core.a,$(BUILD)\/\\0,)

OPENSSL_ROOT_DIR = $(shell grep OPENSSL_ROOT_DIR: ${BUILD}/CMakeCache.txt | sed s/.*=// | sed s/./-DOPENSSL_ROOT_DIR=\\0/)

EFLAGS	= -ggdb
CFLAGS	= -ggdb -Wno-deprecated-declarations

ifeq ($(MODE),honggfuzz)
CC	= hfuzz-clang
LD	= $(CC)
HFUZZ_CC_ASAN = 1
else ifeq ($(MODE),libFuzzer)
CC	= clang
LD	= $(CC)
FLAGS	+= -fsanitize=address,fuzzer
EFLAGS	+= -fsanitize=address
else ifeq ($(MODE),afl)
$(notice afl mode)
CC	= afl-clang-fast
LD	= afl-clang-fast++
LDFLAGS	+= afl_driver.cpp
else
$(error unknown fuzzing mode)
endif

CFLAGS  += $(C_INCLUDES) $(FLAGS)
LDFLAGS += $(FLAGS) $(LINK)

cms: cms.o
pkey: pkey.o
x509: x509.o

# Not just compile, but re-compile gost-engine.
engine:
	@rm -f $(BUILD)/CMakeCache.txt
	@make -C$(BUILD) clean -s
	cd $(BUILD); \
	CFLAGS="$(EFLAGS)" HFUZZ_CC_ASAN=$(HFUZZ_CC_ASAN) CC=$(CC) \
	cmake $(OPENSSL_ROOT_DIR) .
	make -C$(BUILD) -j$(shell nproc) VERBOSE=1

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $<
%: %.o
	$(LD) $(LDFLAGS) $< $(LOADLIBES) $(LDLIBS) -o $@

fuzz: pkey
	mkdir -p input output
	#honggfuzz -i input --output output --rlimit_stack 20000 -t 1 -- ./$<
	honggfuzz -i input --output output --rlimit_core 11111111111 -- ./$<

afl_driver.cpp:
	wget https://raw.githubusercontent.com/llvm/llvm-project/master/compiler-rt/lib/fuzzer/afl/afl_driver.cpp

clean:
	rm -f pkey x509 cms *.o

fuzzclean:
	rm -f HF.sanitizer.log.* HONGGFUZZ.REPORT.TXT SIG*.fuzz fuzz*.log
	find input/ output/ -name '*.cov' -delete

.PHONY: distclean clean
