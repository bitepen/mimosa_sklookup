CLANG ?= clang
BPFTOOL ?= bpftool
CC ?= gcc

all: sklookup

vmlinux.h:
	$(BPFTOOL) btf dump file vmlinux format c > vmlinux.h

sklookup.bpf.o: vmlinux.h sklookup.bpf.c
	$(CLANG) -O2 -g -target bpf -I. -c sklookup.bpf.c -o sklookup.bpf.o

sklookup.skel.h: sklookup.bpf.o
	$(BPFTOOL) gen skeleton sklookup.bpf.o > sklookup.skel.h

sklookup: sklookup.c sklookup.skel.h
	$(CC) -O2 -Wall -Wextra -static sklookup.c -o sklookup -lbpf -lelf -lz -lzstd

clean:
	rm -f sklookup sklookup.bpf.o sklookup.skel.h vmlinux.h