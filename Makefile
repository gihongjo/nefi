.PHONY: all build build-agent build-server build-ui test lint fmt proto clean \
	docker-agent docker-server docker-ui docker docker-push \
	ebpf-test ebpf-test-deploy ebpf-test-logs ebpf-test-clean \
	helm-install helm-uninstall help

GO := go
GOFLAGS := -trimpath
BPF_CLANG := clang
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

# Docker
REGISTRY ?= ghcr.io/gihongjo
IMAGE_TAG ?= $(VERSION)

## Build

all: build

build: build-agent build-server build-ui

build-agent:
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o bin/nefi-agent ./cmd/nefi-agent

build-server:
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o bin/nefi-server ./cmd/nefi-server

build-ui:
	cd ui && npm install && npm run build

## eBPF

bpf: bpf-connection bpf-http bpf-dns

bpf-connection:
	$(BPF_CLANG) $(BPF_CFLAGS) -c bpf/connection_tracker.c -o bpf/connection_tracker.o -I bpf

bpf-http:
	$(BPF_CLANG) $(BPF_CFLAGS) -c bpf/http_parser.c -o bpf/http_parser.o -I bpf

bpf-dns:
	$(BPF_CLANG) $(BPF_CFLAGS) -c bpf/dns_tracker.c -o bpf/dns_tracker.o -I bpf

## Proto

proto:
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		internal/proto/nefi.proto

## Test

test:
	$(GO) test -race -count=1 ./...

test-cover:
	$(GO) test -race -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

## Lint & Format

lint:
	golangci-lint run ./...

fmt:
	gofumpt -w .
	$(GO) mod tidy

## Docker

docker-agent:
	docker build -f Dockerfile.agent -t $(REGISTRY)/nefi-agent:$(IMAGE_TAG) .

docker-server:
	docker build -f Dockerfile.server -t $(REGISTRY)/nefi-server:$(IMAGE_TAG) .

docker-ui:
	docker build -f Dockerfile.ui -t $(REGISTRY)/nefi-ui:$(IMAGE_TAG) .

docker: docker-agent docker-server docker-ui

docker-push: docker
	docker push $(REGISTRY)/nefi-agent:$(IMAGE_TAG)
	docker push $(REGISTRY)/nefi-server:$(IMAGE_TAG)
	docker push $(REGISTRY)/nefi-ui:$(IMAGE_TAG)

## eBPF Test

ebpf-test:
	docker build -f Dockerfile.ebpf-test -t $(REGISTRY)/nefi-ebpf-test:latest .

ebpf-test-deploy: ebpf-test
	docker push $(REGISTRY)/nefi-ebpf-test:latest
	-kubectl delete pod ebpf-test -n nefi --ignore-not-found
	kubectl apply -f deploy/ebpf-test-pod.yaml

ebpf-test-logs:
	kubectl logs -n nefi ebpf-test -f

ebpf-test-clean:
	kubectl delete pod ebpf-test -n nefi --ignore-not-found

## Helm

helm-install:
	helm upgrade --install nefi deploy/helm/nefi \
		--namespace nefi --create-namespace \
		--set agent.image.tag=$(IMAGE_TAG) \
		--set server.image.tag=$(IMAGE_TAG) \
		--set ui.image.tag=$(IMAGE_TAG)

helm-uninstall:
	helm uninstall nefi --namespace nefi

## Clean

clean:
	rm -rf bin/ coverage.out coverage.html
	rm -f bpf/*.o
	cd ui && rm -rf node_modules dist

## Help

help:
	@echo "nefi - Kubernetes Observability Tool"
	@echo ""
	@echo "Build:"
	@echo "  make build          Build agent, server, and UI"
	@echo "  make build-agent    Build nefi-agent"
	@echo "  make build-server   Build nefi-server"
	@echo "  make build-ui       Build React UI"
	@echo "  make bpf            Compile eBPF programs"
	@echo "  make proto          Generate protobuf Go code"
	@echo ""
	@echo "Test & Lint:"
	@echo "  make test           Run tests with race detector"
	@echo "  make test-cover     Run tests with coverage"
	@echo "  make lint           Run golangci-lint"
	@echo "  make fmt            Format code"
	@echo ""
	@echo "Docker:"
	@echo "  make docker         Build all Docker images (agent, server, ui)"
	@echo "  make docker-agent   Build nefi-agent image"
	@echo "  make docker-server  Build nefi-server image"
	@echo "  make docker-ui      Build nefi-ui image"
	@echo "  make docker-push    Build and push all images"
	@echo ""
	@echo "Deploy:"
	@echo "  make helm-install   Install/upgrade Helm chart"
	@echo "  make helm-uninstall Uninstall Helm chart"
