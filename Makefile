CC ?= gcc
CLANG ?= clang

TARGET := if_flow
BPF_OBJ := bpf/if_flow.bpf.o
VMLINUX := bpf/vmlinux.h

USER_CFLAGS ?= -O2 -Wall -Wextra -std=gnu11
BPF_CFLAGS ?= -O2 -g -target bpf -D__TARGET_ARCH_x86
INCLUDES ?= -Iinclude
BPF_INCLUDES ?= $(shell pkg-config --cflags libbpf 2>/dev/null || echo)
PCAP_LIBS ?= $(shell pkg-config --libs libpcap 2>/dev/null || echo -lpcap)
LIBBPF_LIBS ?= $(shell pkg-config --libs libbpf 2>/dev/null || echo -lbpf -lelf -lz)

SRC := \
	src/main.c \
	src/config.c \
	src/flow_table.c \
	src/local_ip.c \
	src/ebpf_tracker.c \
	src/parser.c \
	src/resolver.c \
	src/writer_jsonl.c

OBJ := $(SRC:.c=.o)

all: $(BPF_OBJ) $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(USER_CFLAGS) $(INCLUDES) -o $@ $(OBJ) $(PCAP_LIBS) $(LIBBPF_LIBS)

$(BPF_OBJ): bpf/if_flow.bpf.c $(VMLINUX)
	$(CLANG) $(BPF_CFLAGS) $(BPF_INCLUDES) -c $< -o $@

$(VMLINUX):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

%.o: %.c
	$(CC) $(USER_CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJ) $(BPF_OBJ)

test: $(TARGET)
	bash ./tests/run_tests.sh

install-systemd: all
	bash ./scripts/install_systemd_layout.sh

.PHONY: all clean test install-systemd
