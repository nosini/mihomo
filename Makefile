.DEFAULT_GOAL := build
GO ?= go
PYTHON ?= python3
BINDIR ?= $(CURDIR)/bin
# Marked dirty when the tree, including the upstream pin, differs from the commit.
VERSION ?= $(shell git describe --always --dirty --exclude='*')
BUILDTIME ?= $(shell date -u)

# Do not send make's attempt to remake its own input through the fallback.
Makefile: ;

# Upstream's build targets run the go on PATH; use the toolchain GO names.
GOROOT_BIN = $(shell $(GO) env GOROOT)/bin

.PHONY: prepare build clean test test-assembly test-process test-vm
prepare:
	$(PYTHON) scripts/prepare-source.py

build: linux-amd64

# Only the assembly: bin/ may hold builds that are kept or deployed.
clean:
	rm -rf build

test-assembly:
	$(PYTHON) -m unittest discover -s tests -v

test: prepare test-assembly
	cd build/mihomo && CGO_ENABLED=0 SKIP_INTEROP_TEST=1 $(GO) test ./...

test-process: prepare
	cd build/mihomo && CGO_ENABLED=0 $(GO) test ./component/process

test-vm: prepare
	mkdir -p "$(abspath $(BINDIR))"
	cd build/mihomo && CGO_ENABLED=0 $(GO) test -c -tags sockowner_vm -o "$(abspath $(BINDIR))/process.test" ./component/process

# Use upstream's build tags, architecture settings and linker flags, while
# identifying the outer repository's source revision and keeping output in bin/.
%: prepare
	PATH="$(GOROOT_BIN):$$PATH" $(MAKE) -C build/mihomo $@ BINDIR="$(abspath $(BINDIR))" VERSION="$(VERSION)" BUILDTIME="$(BUILDTIME)"
