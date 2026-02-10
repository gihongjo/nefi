.PHONY: agent agent-deploy agent-logs agent-clean \
       bcc-test bcc-test-deploy bcc-test-logs bcc-test-clean help

REGISTRY ?= ghcr.io/gihongjo

## Agent (libbpf/CO-RE)

agent:
	docker build -f Dockerfile.agent -t $(REGISTRY)/nefi-agent:latest .

agent-deploy: agent
	docker push $(REGISTRY)/nefi-agent:latest
	-kubectl delete pod nefi-agent-test -n nefi --ignore-not-found
	kubectl create namespace nefi --dry-run=client -o yaml | kubectl apply -f -
	kubectl apply -f deploy/agent-test-pod.yaml

agent-logs:
	kubectl logs -n nefi nefi-agent-test -f

agent-clean:
	kubectl delete pod nefi-agent-test -n nefi --ignore-not-found

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
	@echo "nefi - eBPF Data Engineering Tool"
	@echo ""
	@echo "Agent (libbpf/CO-RE):"
	@echo "  make agent            Build agent image"
	@echo "  make agent-deploy     Build, push, and deploy agent pod"
	@echo "  make agent-logs       Follow agent pod logs"
	@echo "  make agent-clean      Delete agent pod"
	@echo ""
	@echo "BCC Test:"
	@echo "  make bcc-test         Build BCC test image"
	@echo "  make bcc-test-deploy  Build, push, and deploy test pod"
	@echo "  make bcc-test-logs    Follow test pod logs"
	@echo "  make bcc-test-clean   Delete test pod"
