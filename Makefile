PONGO_PATH                  := ./pongoOS
SRC                         := $(PONGO_PATH)/src
DEP                         := $(PONGO_PATH)/newlib
LIB                         := $(DEP)/aarch64-none-darwin
INC                         := $(PONGO_PATH)/include
BUILD                       := build
RA1N                        := .

ifndef HOST_OS
    ifeq ($(OS),Windows_NT)
        HOST_OS             := Windows
    else
        HOST_OS             := $(shell uname -s)
    endif
endif

# Toolchain
ifdef LLVM_CONFIG
    EMBEDDED_LLVM_CONFIG    ?= $(LLVM_CONFIG)
endif

ifdef EMBEDDED_LLVM_CONFIG
ifndef EMBEDDED_LLVM_BINDIR
    EMBEDDED_LLVM_BINDIR    := $(shell $(EMBEDDED_LLVM_CONFIG) --bindir)
endif
endif

ifdef LLVM_BINDIR
    EMBEDDED_LLVM_BINDIR    ?= $(LLVM_BINDIR)
endif

ifdef EMBEDDED_LLVM_BINDIR
    EMBEDDED_CC             ?= $(EMBEDDED_LLVM_BINDIR)/clang
endif

CLANG                       ?= clang

ifeq ($(HOST_OS),Darwin)
    CC                      ?= $(CLANG)
    EMBEDDED_CC             ?= xcrun -sdk iphoneos clang
    STAT                    ?= stat -L -f %z
else
ifeq ($(HOST_OS),Linux)
    CC                      ?= $(CLANG)
    EMBEDDED_CC             ?= $(CLANG)
ifndef EMBEDDED_LD
    EMBEDDED_LD             := $(shell which ld64)
endif
    STAT                    ?= stat -L -c %s
endif
endif

ifdef EMBEDDED_LD
    EMBEDDED_LDFLAGS        ?= -fuse-ld='$(EMBEDDED_LD)'
endif

EMBEDDED_LD_FLAGS           ?= -nostdlib -Wl,-dead_strip -Wl,-Z $(EMBEDDED_LDFLAGS)
EMBEDDED_CC_FLAGS           ?= --target=arm64-apple-ios15.0 -std=gnu17 -Wall -Wstrict-prototypes -Werror=incompatible-function-pointer-types -flto -ffreestanding -nostdlibinc -fno-blocks -U__nonnull -DTARGET_OS_OSX=0 -DTARGET_OS_MACCATALYST=0 -D_GNU_SOURCE -D__DYNAMIC_REENT__ -DDER_TAG_SIZE=8 -I$(LIB)/include $(EMBEDDED_LD_FLAGS) $(EMBEDDED_CFLAGS) -Wno-strict-prototypes

ifdef DEV_BUILD
    EMBEDDED_CC_FLAGS       += -DDEV_BUILD
endif

AES_LD_FLAGS                ?= -Wl,-kext $(AES_LDFLAGS)
AES_CC_FLAGS                ?= -O3 -I$(INC) -I$(PONGO_PATH)/apple-include -I$(SRC)/kernel -I$(SRC)/drivers -I$(SRC)/lib $(AES_CFLAGS) $(AES_LD_FLAGS)

PONGO_H                     := $(wildcard $(SRC)/*/*.h) $(wildcard $(SRC)/*/*/*.h) $(wildcard $(SRC)/*/*/*/*.h)

AES_H                       := $(wildcard $(RA1N)/*.h)
AES_C                       := $(wildcard $(RA1N)/*.c) $(wildcard $(RA1N)/*.S)

.PHONY: all clean

all: $(BUILD)/aeskey

$(BUILD)/aeskey: Makefile $(AES_C) $(AES_H) $(PONGO_H) $(LIB)/fixup/libc.a | $(BUILD)
	$(EMBEDDED_CC) -o $@ $(AES_C) $(EMBEDDED_CC_FLAGS) $(AES_CC_FLAGS)

clean:
	rm -rf $(BUILD)/*
