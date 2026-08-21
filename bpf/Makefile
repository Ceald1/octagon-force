## Compiler settings
CLANG ?= clang
CFLAGS ?= -O2 -g -Wall -std=gnu17

# BPF Architecture Target
BPF_TARGET := -target bpf

# Directories and Discovery
#BPF_SRC := $(wildcard *.c) $(wildcard */*.c)
#BPF_OBJ := $(patsubst %.c, build/%.o, $(BPF_SRC))
BPF_SRC := $(wildcard *.c) $(wildcard */*.c)
BPF_OBJ := $(addprefix build/, $(notdir $(BPF_SRC:.c=.o)))

# Basic Linux architecture detection
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
INCLUDES := -I/usr/include -I/usr/include/$(shell uname -m)-linux-gnu

# Dynamic Program Extraction Target (Default fallback if PROG is empty)
# PROG ?= hello
# Strip any trailing .c or .o from the argument to get the clean base name
BASE_NAME := $(basename $(notdir $(PROG)))

# Dynamic Path Specifications based on the variable argument
TARGET_OBJ  := build/$(BASE_NAME).o
BPF_DIR  := /sys/fs/bpf/octagon_force/$(BASE_NAME)
BPF_FS_PATH := /sys/fs/bpf/octagon_force/$(BASE_NAME)
PROG_PIN := $(BPF_DIR)/prog

vpath %.c . $(sort $(dir $(wildcard */*.c)))

.PHONY: all clean load unload logs status help

all: $(BPF_OBJ)

# Rule to compile any BPF source file into eBPF bytecode
build/%.o: %.c | build
	$(CLANG) $(CFLAGS) $(BPF_TARGET) -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -c $< -o $@

build:
	mkdir -p ./build
# 1. Load and Dynamic Auto-Attach via ARG/PROG variable
load:
	@if [ ! -f "$(TARGET_OBJ)" ]; then \
		echo "Building $(TARGET_OBJ)..."; \
		$(MAKE) "$(TARGET_OBJ)" || exit 1; \
	fi

	@if test -e "$(PROG_PIN)"; then \
		echo "Program '$(BASE_NAME)' already loaded."; \
		echo "Run: make unload PROG=$(BASE_NAME)"; \
		exit 1; \
	fi

	@echo "Loading $(TARGET_OBJ)..."

	mkdir -p "$(BPF_DIR)"

	bpftool prog loadall \
		"$(TARGET_OBJ)" \
		"$(PROG_PIN)" \
		autoattach \
		pinmaps "$(BPF_DIR)"

	@echo "Successfully loaded '$(BASE_NAME)'"
loadall:
	@for obj in build/*.o; do \
		[ -f "$$obj" ] || continue; \
		prog=$$(basename "$$obj" .o); \
		$(MAKE) --no-print-directory load PROG="$$prog" || exit 1; \
	done

#load:
#	mkdir -p $(BPF_FS_PATH)
#	@if [ ! -f $(TARGET_OBJ) ]; then \
#		echo "Error: $(TARGET_OBJ) does not exist. Compiling it now..."; \
#		make $(TARGET_OBJ) || exit 1; \
#	fi
#	@echo "Loading and attaching $(TARGET_OBJ) to $(BPF_FS_PATH)..."
#	bpftool prog load $(TARGET_OBJ) $(BPF_FS_PATH) autoattach pinmaps $(BPF_FS_PATH)
#	@echo "Successfully loaded and attached '$(BASE_NAME)'!"

# 2. Unload any specific BPF program via ARG/PROG variable

unload:
	@echo "Unloading '$(BASE_NAME)'..."

	@if test -d "$(BPF_DIR)"; then \
		rm -rf "$(BPF_DIR)"; \
		echo "Removed $(BPF_DIR)"; \
	else \
		echo "Program not loaded."; \
	fi
unloadall:
	@for obj in build/*.o; do \
		[ -f "$$obj" ] || continue; \
		prog=$$(basename "$$obj" .o); \
		$(MAKE) --no-print-directory unload PROG="$$prog" || exit 1; \
	done
#unload:
#	@echo "Detaching and unloading BPF program pinned at $(BPF_FS_PATH)..."
#	rm -rf $(BPF_FS_PATH)
#
#	@echo "Successfully unloaded '$(BASE_NAME)'."

# 3. Stream printk tracing logs
logs:
	@echo "Streaming BPF printk trace logs (Press Ctrl+C to stop)..."
	bpftool prog tracelog

# 4. Show state matching our targeted program name variable
status:
	@echo "=== Active BPF Links ==="
	bpftool link list
	@echo "\n=== Running Program Instance ==="
	bpftool prog show name $(BASE_NAME) || sudo bpftool prog show

clean:
	rm -rf ./build

help:
	@echo "Usage: make <command> [PROG=program_name]"
	@echo ""
	@echo "Available Commands:"
	@echo "  help         - Show this menu with command descriptions and usage."
	@echo "  all          - Compile all discovered .c files into build/*.o bytecode."
	@echo "  load         - Load and auto-attach a specific BPF program into the kernel."
	@echo "  unload       - Detach and safely remove a specific BPF program from memory."
	@echo "  logs         - Stream live 'bpf_printk' output globally from the kernel."
	@echo "  status       - Show currently active kernel links and loaded modules."
	@echo "  clean        - Delete the local build/ directory and its binary objects."
	@echo ""
	@echo "Argument Options:"
	@echo "  PROG=name    - Target a specific source file (Defaults to 'hello')."
	@echo "                 Works with 'load', 'unload', and 'status'."
	@echo ""
	@echo "Examples:"
	@echo "  make                         --> Shows this help screen"
	@echo "  make all                     --> Compiles everything"
	@echo "  make load                    --> Loads default build/hello.o"
	@echo "  make load PROG=packet_drop   --> Compiles & loads build/packet_drop.o"
	@echo "  make unload PROG=packet_drop --> Safely unloads packet_drop"
	@echo "  make logs                    --> Streams printk output live"
	@echo "========================================================================="

