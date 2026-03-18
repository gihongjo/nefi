.PHONY: agent agent-deploy agent-logs agent-clean \
        agent-enable-node agent-disable-node \
        ui ui-dev \
        server server-deploy server-logs server-clean \
        proto \
        bcc-test bcc-test-deploy bcc-test-logs bcc-test-clean help

REGISTRY ?= ghcr.io/gihongjo

## Agent (libbpf/CO-RE)

agent:
	docker build -f Dockerfile.agent -t $(REGISTRY)/nefi-agent:latest .
	docker push $(REGISTRY)/nefi-agent:latest

agent-deploy: agent
	docker push $(REGISTRY)/nefi-agent:latest
	kubectl create namespace nefi --dry-run=client -o yaml | kubectl apply -f -
	kubectl delete daemonset nefi-agent -n nefi --ignore-not-found
	kubectl apply -f deploy/agent-daemonset.yaml

agent-logs:
	kubectl logs -n nefi -l app=nefi-agent -f --max-log-requests=20

agent-clean:
	kubectl delete daemonset nefi-agent -n nefi --ignore-not-found

## Node targeting — label a node to enable/disable the agent on it
## Usage: make agent-enable-node NODE=worker1

agent-enable-node:
	kubectl label node $(NODE) nefi-agent=enabled --overwrite

agent-disable-node:
	kubectl label node $(NODE) nefi-agent-

## UI (Svelte + Vite)

ui:
	cd ui && npm ci && npm run build

ui-dev:
	cd ui && npm run dev

## Server

server: ui
	docker build -f Dockerfile.server -t $(REGISTRY)/nefi-server:latest .
	docker push $(REGISTRY)/nefi-server:latest

server-deploy: server
	docker build -f Dockerfile.server -t $(REGISTRY)/nefi-server:latest .
	docker push $(REGISTRY)/nefi-server:latest
	kubectl create namespace nefi --dry-run=client -o yaml | kubectl apply -f -
	kubectl delete deployment nefi-server -n nefi --ignore-not-found
	kubectl apply -f deploy/server-deployment.yaml

server-logs:
	kubectl logs -n nefi -l app=nefi-server -f

server-clean:
	kubectl delete deployment nefi-server -n nefi --ignore-not-found

## Proto (macOS 로컬에서 실행, protoc + protoc-gen-go + protoc-gen-go-grpc 필요)

proto:
	protoc \
	  --proto_path=proto \
	  --go_out=gen/go \
	  --go_opt=paths=source_relative \
	  --go-grpc_out=gen/go \
	  --go-grpc_opt=paths=source_relative \
	  nefi/v1/events.proto nefi/v1/collector.proto

## BCC Test

bcc-test:
	docker build -f Dockerfile.bcc-test -t $(REGISTRY)/nefi-bcc-test:latest .

bcc-test-deploy: bcc-test
	docker push $(REGISTRY)/nefi-bcc-test:latest
	-kubectl delete pod bcc-test -n nefi --ignore-not-found
	kubectl create namespace nefi --dry-run=client -o yaml | kubectl apply -f -
	kubectl apply -f deploy/bcc-test-pod.yaml

bcc-test-logs:
	kubectl logs -n nefi bcc-test -f

bcc-test-clean:
	kubectl delete pod bcc-test -n nefi --ignore-not-found

## Help

help:
	@echo "nefi - eBPF Network Tracing"
	@echo ""
	@echo "Agent (libbpf/CO-RE):"
	@echo "  make agent                       Build agent image"
	@echo "  make agent-deploy                Build, push, and deploy DaemonSet"
	@echo "  make agent-logs                  Follow logs from all agent pods"
	@echo "  make agent-clean                 Delete DaemonSet"
	@echo "  make agent-enable-node NODE=X    Deploy agent to node X"
	@echo "  make agent-disable-node NODE=X   Remove agent from node X"
	@echo ""
	@echo "UI (Svelte + Vite):"
	@echo "  make ui                          Build UI (npm ci + npm run build → web/dist/)"
	@echo "  make ui-dev                      Start Vite dev server (localhost:5173)"
	@echo ""
	@echo "Server:"
	@echo "  make server                      Build UI then server Docker image"
	@echo "  make server-deploy               Build, push, and deploy Deployment"
	@echo "  make server-logs                 Follow server logs"
	@echo "  make server-clean                Delete Deployment"
	@echo ""
	@echo "Proto:"
	@echo "  make proto                       Regenerate Go code from .proto files"
	@echo ""
	@echo "BCC Test:"
	@echo "  make bcc-test         Build BCC test image"
	@echo "  make bcc-test-deploy  Build, push, and deploy test pod"
	@echo "  make bcc-test-logs    Follow test pod logs"
	@echo "  make bcc-test-clean   Delete test pod"
