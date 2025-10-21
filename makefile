# Makefile for libbpf network monitor

# Compiler and flags
CLANG ?= clang
LLC ?= llc
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)

# User-space compiler
CC = gcc
CFLAGS = -g -Wall -O2
LDFLAGS = -lbpf -lelf -lz

# Targets
BPF_OBJ = network_monitor.bpf.o
USER_PROG = network_monitor

.PHONY: all clean vmlinux

all: vmlinux $(USER_PROG)

# Generate vmlinux.h if it doesn't exist
vmlinux:
	@if [ ! -f vmlinux.h ]; then \
		echo "Generating vmlinux.h..."; \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
	fi

# Compile BPF program
$(BPF_OBJ): network_monitor.bpf.c vmlinux.h network_monitor.h
	$(CLANG) $(BPF_CFLAGS) -c network_monitor.bpf.c -o $(BPF_OBJ)

# Compile user-space program
$(USER_PROG): network_monitor.c $(BPF_OBJ) network_monitor.h
	$(CC) $(CFLAGS) network_monitor.c -o $(USER_PROG) $(LDFLAGS)

clean:
	rm -f $(BPF_OBJ) $(USER_PROG)
	rm -f vmlinux.h

install: all
	install -m 755 $(USER_PROG) /usr/local/bin/
	install -m 644 $(BPF_OBJ) /usr/local/lib/bpf/

.DEFAULT_GOAL := all