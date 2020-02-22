.PHONY: build-kit build bump helm helm-clean

VERSION := 0.1.2
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
GIT_COMMIT := $(shell git rev-parse --short HEAD)
IMAGE_NAME := $(if $(REGISTRY),$(REGISTRY)/,)keycloak-forward

ifeq ($(GIT_BRANCH),master)
EXPORT_CACHE := --export-cache type=registry,ref=$(IMAGE_NAME):cache
IMPORT_CACHE := --import-cache type=registry,ref=$(IMAGE_NAME):cache
OUTPUT := --output type=image,name=$(IMAGE_NAME):$(VERSION),push=true
else
EXPORT_CACHE := --export-cache type=local,dest=./cache
IMPORT_CACHE := --import-cache type=local,src=./cache
endif

helm-clean:
	helm3 uninstall keycloak-forward

helm:
	helm3 install keycloak-forward helm/keycloak-forward $(HELM_ARGS)

bump:
	bump2version patch

build:
	docker run \
		-it --rm --privileged \
		-v $(PWD):/src -w /src \
		--entrypoint /bin/sh \
		moby/buildkit:master \
		build.sh $(EXPORT_CACHE) $(IMPORT_CACHE) $(OUTPUT)

buildkit:
	build.sh $(EXPORT_CACHE) $(IMPORT_CACHE) $(OUTPUT)
