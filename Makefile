# hsp: `make` builds build/hsp; `make test` runs the host-side walker test.
# Toolchain (g++, clang for BPF, bpftool, libbpf, yyjson, zlib) comes from
# `nix develop` / `nix build`; plain make works where they are installed.
CXX      ?= g++
CC       ?= cc
CLANG    ?= clang
BPFTOOL  ?= bpftool
CXXFLAGS ?= -O2 -g
CFLAGS   ?= -O2 -g
CXXFLAGS += -std=c++20 -Wall -Wextra
CFLAGS   += -Wall -Wextra -Wno-unused-parameter
DEPS      = libbpf libcurl libdw libelf
CPPFLAGS += $(shell pkg-config --cflags $(DEPS)) -Ibpf -Ibuild
LDLIBS   += $(shell pkg-config --libs $(DEPS))
BPF_CFLAGS ?= $(shell pkg-config --cflags libbpf)
PREFIX   ?= /usr/local

CXXSRC = $(wildcard src/*.cpp)
CSRC   = $(wildcard src/*.c)
OBJ    = $(CXXSRC:src/%.cpp=build/%.o) $(CSRC:src/%.c=build/%.o)

build/hsp: $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

build/%.o: src/%.cpp $(wildcard src/*.h) bpf/hsp_abi.h | build
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c -o $@ $<

# C sources; the sampler library needs the skeleton, generated from the BPF object
build/%.o: src/%.c src/sampler.h bpf/hsp_abi.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<
build/sampler.o: build/hsp.skel.h

build/hsp.bpf.o: bpf/hsp.bpf.c bpf/hswalk.h bpf/hsp_abi.h bpf/vmlinux.h | build
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 $(BPF_CFLAGS) -Ibpf -c $< -o $@

build/hsp.skel.h: build/hsp.bpf.o
	$(BPFTOOL) gen skeleton $< > $@.tmp && mv $@.tmp $@

build/hswalk_test: tests/hswalk_test.c bpf/hswalk.h bpf/hsp_abi.h | build
	$(CC) $(CFLAGS) -Ibpf -o $@ $<

build:
	mkdir -p build

test: build/hswalk_test
	./build/hswalk_test

install: build/hsp
	install -Dm755 build/hsp $(PREFIX)/bin/hsp

clean:
	rm -rf build

.PHONY: test install clean
