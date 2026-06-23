# vgi-secretscan Makefile
#
# A VGI worker (Go) that scans text / source code for leaked secrets — cloud
# keys (AWS/GCP/Azure), GitHub/Slack tokens, private keys, JWTs, high-entropy
# strings — using the embedded gitleaks ruleset plus Shannon-entropy
# heuristics, exposed as DuckDB SQL functions. Detection is pure and offline
# (no network) and never verifies whether a secret is live. Targets:
#
#   make build       Build the worker binary
#   make test-unit   Run the pure-Go unit tests (detection is offline)
#   make test-sql    Run the haybarn-unittest SQL E2E
#   make test        test-unit + test-sql
#   make fmt         gofmt -w
#   make vet         go vet
#   make lint        golangci-lint (if installed) else vet
#   make clean       Remove built binaries
#
# test-sql needs haybarn-unittest on PATH:
#   uv tool install haybarn-unittest
#   export PATH="$$HOME/.local/bin:$$PATH"

WORKER_BIN := vgi-secretscan-worker
WORKER_CMD := ./cmd/vgi-secretscan-worker

TEST_DIR     := .
TEST_PATTERN := test/sql/*

# Absolute path to the built worker (the VGI extension launches it via LOCATION).
WORKER_PATH := $(CURDIR)/$(WORKER_BIN)

.PHONY: build test test-unit test-sql fmt vet lint clean

build:
	go build -o $(WORKER_BIN) $(WORKER_CMD)

test: test-unit test-sql

test-unit:
	go test ./...

# Secret detection is pure/offline — no mock server is needed. Build the worker,
# point the SQL suite at it via VGI_SECRETSCAN_WORKER (the ATTACH LOCATION),
# then run the haybarn suite.
test-sql: build
	@set -e; \
	VGI_SECRETSCAN_WORKER="$(WORKER_PATH)" \
		haybarn-unittest --test-dir "$(TEST_DIR)" "$(TEST_PATTERN)"

fmt:
	gofmt -w .

vet:
	go vet ./...

lint:
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "golangci-lint not found. Install: https://golangci-lint.run/usage/install/"; \
		exit 1; \
	}
	golangci-lint run ./...

clean:
	rm -f $(WORKER_BIN)
