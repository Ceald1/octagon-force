## Compiler settings
CLANG ?= clang
CFLAGS ?= -O2 -g -Wall -std=gnu17

# BPF Architecture Target
BPF_TARGET := -target bpf

# Directories and Discovery
BPF_SRC := $(wildcard *.c) $(wildcard */*.c)
BPF_OBJ := $(patsubst %.c, build/%.o, $(BPF_SRC))

# Basic Linux architecture detection
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
INCLUDES := -I/usr/include -I/usr/include/$(shell uname -m)-linux-gnu

# Dynamic Program Extraction Target (Default fallback if PROG is empty)
PROG ?= hello
# Strip any trailing .c or .o from the argument to get the clean base name
BASE_NAME := $(basename $(notdir $(PROG)))

# Dynamic Path Specifications based on the variable argument
TARGET_OBJ  := build/$(BASE_NAME).o
BPF_FS_PATH := /sys/fs/bpf/$(BASE_NAME)

.PHONY: all clean load unload logs status

all: $(BPF_OBJ)

# Rule to compile any BPF source file into eBPF bytecode
build/%.o: %.c
	mkdir -p $(dir $@)
	$(CLANG) $(CFLAGS) $(BPF_TARGET) -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -c $< -o $@

# 1. Load and Dynamic Auto-Attach via ARG/PROG variable
load:
	@if [ ! -f $(TARGET_OBJ) ]; then \
		echo "Error: $(TARGET_OBJ) does not exist. Compiling it now..."; \
		make $(TARGET_OBJ) || exit 1; \
	fi
	@echo "Loading and attaching $(TARGET_OBJ) to $(BPF_FS_PATH)..."
	@if [ -e $(BPF_FS_PATH) ]; then echo "Program '$(BASE_NAME)' already loaded. Run 'make unload PROG=$(BASE_NAME)' first."; exit 1; fi
	sudo bpftool prog load $(TARGET_OBJ) $(BPF_FS_PATH) autoattach
	@echo "Successfully loaded and attached '$(BASE_NAME)'!"

# 2. Unload any specific BPF program via ARG/PROG variable
unload:
	@echo "Detaching and unloading BPF program pinned at $(BPF_FS_PATH)..."
	@if [ ! -e $(BPF_FS_PATH) ]; then echo "No active BPF object found pinned at $(BPF_FS_PATH)"; exit 1; fi
	sudo rm -f $(BPF_FS_PATH)
	@echo "Successfully unloaded '$(BASE_NAME)'."

# 3. Stream printk tracing logs
logs:
	@echo "Streaming BPF printk trace logs (Press Ctrl+C to stop)..."
	sudo bpftool prog tracelog

# 4. Show state matching our targeted program name variable
status:
	@echo "=== Active BPF Links ==="
	sudo bpftool link list
	@echo "\n=== Running Program Instance ==="
	sudo bpftool prog show name $(BASE_NAME) || sudo bpftool prog show

clean:
	rm -rf ./build


