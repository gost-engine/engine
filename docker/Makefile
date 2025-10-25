
OK           := \e[1;32mOK\e[0m
FAIL         := \e[1;31mFAIL\e[0m
PRINT_RESULT := echo '${OK}' || echo '${FAIL}'

#
# for git tag used tag name as version
# else version is name of branch or "unknown" if no .git repo
# also you can replace VERSION value using environment variables: 
#   VERSION=latest make help
# 
VERSION ?= $(shell \
	if git describe --tags --exact-match >/dev/null 2>&1; then \
		git describe --tags --exact-match; \
	else \
		git branch --show-current 2>/dev/null || echo "unknown"; \
	fi \
)
DOCKER_IMAGE := gost-engine

RELEASES     := alpine debian 
# rockylinux -- unsuitable version "3.2.2", but required is at least "3.4"

.PHONY: help $(RELEASES)

help:
	@ echo "The GOST Engine version: $(VERSION)"
	@ echo "Available targets: help $(RELEASES)"
	@ echo "--"
	@ echo "To build images use:"
	@ for r in $(RELEASES); do \
		echo " > make $$r => $(DOCKER_IMAGE):$(VERSION)-$$r"; \
	done	


update:
	git submodule update --init



$(RELEASES): update
	docker build \
		--file Dockerfile.$@ \
		--tag $(DOCKER_IMAGE):$(VERSION)-$@ \
		..
	@ echo 
	@ echo "\e[1;37m => Checking the OpenSSL version\e[0m"
	@ docker run -it --rm $(DOCKER_IMAGE):$(VERSION)-$@ openssl version -v
	@ echo "$(OK)"
	@ echo "\e[1;37m => Checking the GOST ciphers\e[0m"
	@ docker run -it --rm $(DOCKER_IMAGE):$(VERSION)-$@ openssl ciphers | tr ':' '\n' | grep 'GOST' && $(PRINT_RESULT)