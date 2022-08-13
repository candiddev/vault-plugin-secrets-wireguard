ARCH ?= amd64
OS ?= linux
TAG ?= $(shell git describe --tags --abbrev=0)
TARGETS ?= linux-amd64 linux-arm64

.PHONY: build
build:
	.bin/go build 

.PHONY: release
release:
	for target in $(TARGETS); do \
		export GOARCH=$${target##*-}; \
		export GOOS=$${target%%-*}; \
		export NAME=vault-plugin-secrets-wireguard_$(TAG)_$${GOOS}-$${GOARCH}; \
		GOARCH=$${target##*-} GOOS=$${target%%-*} .bin/go build -o $${NAME}; \
		sha256sum $${NAME} > $${NAME}}.sha256; \
		gzip $${NAME}; \
	done

.PHONY: test
test:
	.bin/go test
