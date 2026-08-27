# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

SHELL := /bin/bash

.DEFAULT_GOAL := help

PKG       ?=
RELEASE   ?=
ARGS      ?=
FILTER    ?=
NOCAPTURE ?=
FEATURES  ?= --all-features
PLANE     ?= control
CONFIG    ?= config.local.yml

# Where this Makefile lives, so that `make -f .../Makefile cp-rspipe` from a playground copies
# *from* the repository while `$(CURDIR)` stays the directory make was invoked in.
REPO_DIR := $(patsubst %/,%,$(dir $(realpath $(firstword $(MAKEFILE_LIST)))))

profile = $(if $(RELEASE),--release)
scope = $(if $(PKG),-p $(PKG),--workspace)

.PHONY: clean coverage coverage-html coverage-lcov bench-grafana bench-grpc bench-hold lab-clean bench-ladder bench-peak bench-server bench-server-shed bench-shed bench-tls build check check-core-deps check-headers check-seams check-systems cli cp-basics cp-rspipe help lab-all lab-down lab-logs lab-observability lab-up lab-where lint plane-run prepare-release run-all run-as-mtls-all run-as-mtls-control run-as-mtls-data run-as-tls-all run-as-tls-control run-as-tls-data run-control run-data test version-control

build: ## Build every Permguard crate.
	cargo build $(scope) $(profile) $(ARGS)

check: ## Run lint, structural checks, and tests.
	$(MAKE) lint
	$(MAKE) check-seams
	$(MAKE) check-core-deps
	$(MAKE) check-systems
	$(MAKE) check-headers
	$(MAKE) test

coverage: ## Measure test coverage and enforce the 60% per-crate line floor.
	./scripts/check-coverage.sh

coverage-html: ## Measure coverage and open the annotated-source HTML report.
	cargo llvm-cov --workspace --html --open

coverage-lcov: ## Write coverage as lcov.info, for editors and CI uploaders.
	cargo llvm-cov --workspace --lcov --output-path lcov.info

check-core-deps: ## Check that permguard-core keeps its dependency list minimal.
	./scripts/check-core-dependencies.sh

check-seams: ## Check that concrete collaborators are constructed only in application crates.
	./scripts/check-composition-root.sh

cli: ## Run the Permguard CLI. ARGS is the command line, defaulting to --help.
	-cargo run -q $(profile) -p permguard-cli --bin permguard -- $(if $(ARGS),$(ARGS),--help)

help: ## Show this help.
	@printf 'Permguard Rust workspace\n\n'
	@printf 'Usage: make <target> [VAR=value ...]\n\n'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_.-]+:.*?## /{printf "  %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

cp-rspipe: ## Copy the release-pipeline example into the current directory.
	$(REPO_DIR)/scripts/copy-example.sh release-pipeline "$(CURDIR)"

cp-basics: ## Copy the basics example into the current directory.
	$(REPO_DIR)/scripts/copy-example.sh basics "$(CURDIR)"

lint: ## Run clippy over every crate and target.
	cargo clippy $(scope) --all-targets --all-features $(ARGS) -- -D warnings

plane-run: ## Run a plane. PLANE is control or data.
	cargo run $(profile) -p permguard-$(PLANE)-plane --bin permguard-$(PLANE)-plane -- crates/permguard-$(PLANE)-plane/$(CONFIG) $(ARGS)

run-control: ## Run the control plane locally.
	$(MAKE) plane-run PLANE=control CONFIG=$(CONFIG) ARGS="$(ARGS)" RELEASE=$(RELEASE)

run-data: ## Run the data plane locally.
	$(MAKE) plane-run PLANE=data CONFIG=$(CONFIG) ARGS="$(ARGS)" RELEASE=$(RELEASE)

run-all: ## Run the all-in-one runtime locally.
	PERMGUARD_RUNTIME_PLANES=$${PERMGUARD_RUNTIME_PLANES:-control,data} cargo run $(profile) -p permguard-all-in-one --bin permguard-all-in-one -- crates/permguard-all-in-one/$(CONFIG) $(ARGS)

run-as-tls-control: ## Run the control plane locally, with TLS.
	$(MAKE) plane-run PLANE=control CONFIG=config.local-tls.yml ARGS="$(ARGS)" RELEASE=$(RELEASE)

run-as-tls-data: ## Run the data plane locally, with TLS.
	$(MAKE) plane-run PLANE=data CONFIG=config.local-tls.yml ARGS="$(ARGS)" RELEASE=$(RELEASE)

run-as-tls-all: ## Run the all-in-one runtime locally, with TLS.
	$(MAKE) run-all CONFIG=config.local-tls.yml ARGS="$(ARGS)" RELEASE=$(RELEASE)

run-as-mtls-control: ## Run the control plane locally, with TLS on HTTP and mutual TLS on gRPC.
	$(MAKE) plane-run PLANE=control CONFIG=config.local-mtls.yml ARGS="$(ARGS)" RELEASE=$(RELEASE)

run-as-mtls-data: ## Run the data plane locally, with TLS on HTTP and mutual TLS on gRPC.
	$(MAKE) plane-run PLANE=data CONFIG=config.local-mtls.yml ARGS="$(ARGS)" RELEASE=$(RELEASE)

run-as-mtls-all: ## Run the all-in-one runtime locally, with TLS on HTTP and mutual TLS on gRPC.
	$(MAKE) run-all CONFIG=config.local-mtls.yml ARGS="$(ARGS)" RELEASE=$(RELEASE)

lab-up: ## Start the compose lab: both planes, Prometheus, Grafana, Loki.
	docker compose -f docker-compose.lab.yml --profile lab up --build $(if $(ARGS),$(ARGS),-d)
	$(MAKE) lab-where

lab-all: ## Start the compose lab with the all-in-one runtime instead of the two planes.
	docker compose -f docker-compose.lab.yml --profile all-in-one up --build $(if $(ARGS),$(ARGS),-d)
	$(MAKE) lab-where

lab-observability: ## Start only Prometheus, Grafana and Loki, to watch planes running on the host.
	docker compose -f docker-compose.lab.yml --profile observability up $(if $(ARGS),$(ARGS),-d)
	$(MAKE) lab-where

lab-down: ## Stop the compose lab, keeping its data: metrics, logs and dashboards survive the next up.
	docker compose -f docker-compose.lab.yml --profile lab --profile all-in-one --profile observability down $(ARGS)

lab-clean: ## Stop the compose lab AND discard its data: the next up starts with empty dashboards.
	docker compose -f docker-compose.lab.yml --profile lab --profile all-in-one --profile observability down -v

clean: ## Remove build artifacts. STALE=7 removes only what nothing has touched for 7 days.
	@set -eu; \
	if [ -n "$(STALE)" ]; then \
		command -v cargo-sweep >/dev/null 2>&1 || { echo "cargo-sweep is not installed: cargo install cargo-sweep" >&2; exit 1; }; \
		cargo sweep --time "$(STALE)"; \
	else \
		cargo clean; \
	fi

lab-logs: ## Follow the compose lab's logs. SERVICE names one service.
	docker compose -f docker-compose.lab.yml logs --follow --tail 50 $(SERVICE)

lab-where: ## Print where the lab is listening.
	@printf 'Grafana     http://127.0.0.1:%s   (dashboards are already provisioned)\n' "$${PERMGUARD_GRAFANA_PORT:-7590}"
	@printf 'Prometheus  http://127.0.0.1:%s\n' "$${PERMGUARD_PROMETHEUS_PORT:-7591}"
	@printf 'Loki        http://127.0.0.1:%s\n' "$${PERMGUARD_LOKI_PORT:-7592}"
	@printf 'Control     http://127.0.0.1:%s\n' "$${PERMGUARD_CONTROL_HTTP_PORT:-7556}"
	@printf 'Data        http://127.0.0.1:%s\n' "$${PERMGUARD_DATA_HTTP_PORT:-7656}"

bench-server: ## Run the control plane for capacity benchmarks: release build, limits out of the way (each PERMGUARD_LIMITS_* overridable).
	PERMGUARD_LIMITS_CONCURRENT_REQUESTS=$${PERMGUARD_LIMITS_CONCURRENT_REQUESTS:-100000} PERMGUARD_LIMITS_CONNECTIONS=$${PERMGUARD_LIMITS_CONNECTIONS:-20000} PERMGUARD_LIMITS_CONNECTIONS_PER_PEER=$${PERMGUARD_LIMITS_CONNECTIONS_PER_PEER:-0} cargo run --release -p permguard-control-plane --bin permguard-control-plane -- crates/permguard-control-plane/config.local.yml $(ARGS)

bench-server-shed: ## Run the control plane for the shed benchmark: a low request ceiling, per-address bound off.
	PERMGUARD_LIMITS_CONCURRENT_REQUESTS=8 PERMGUARD_LIMITS_CONNECTIONS_PER_PEER=0 cargo run --release -p permguard-control-plane --bin permguard-control-plane -- crates/permguard-control-plane/config.local.yml $(ARGS)

bench-peak: ## Closed-loop throughput ceiling against /version. Needs bench-server running.
	k6 run --tag testid=peak-$$(date +%Y%m%d-%H%M%S) $(K6_ARGS) bench/peak.js

bench-ladder: ## Latency at fixed rising rates (open model). Needs bench-server running.
	k6 run --tag testid=ladder-$$(date +%Y%m%d-%H%M%S) $(K6_ARGS) bench/ladder.js

bench-shed: ## Overload behaviour of the shed layer: run against bench-server-shed.
	k6 run --tag testid=shed-$$(date +%Y%m%d-%H%M%S) $(K6_ARGS) bench/shed.js

bench-grpc: ## gRPC GetInfo throughput and latency. Needs bench-server running.
	k6 run --tag testid=grpc-$$(date +%Y%m%d-%H%M%S) $(K6_ARGS) bench/grpc.js

bench-tls: ## Request cost over TLS/mTLS, handshake measured apart. See bench/tls.js.
	k6 run --tag testid=tls-$$(date +%Y%m%d-%H%M%S) $(K6_ARGS) bench/tls.js

bench-hold: ## How many connections the plane can hold: ramps keep-alive sockets. Needs bench-server.
	k6 run --tag testid=hold-$$(date +%Y%m%d-%H%M%S) $(K6_ARGS) bench/hold.js

bench-grafana: ## Print the k6 flags that push client metrics into the lab's Prometheus.
	@printf 'run the lab first (make lab-observability), then add to any bench target:\n\n'
	@printf '  K6_ARGS="-o experimental-prometheus-rw" \\\n'
	@printf '  K6_PROMETHEUS_RW_SERVER_URL=http://127.0.0.1:%s/api/v1/write \\\n' "$${PERMGUARD_PROMETHEUS_PORT:-7591}"
	@printf '  K6_PROMETHEUS_RW_TREND_STATS="p(50),p(95),p(99),avg,max" \\\n'
	@printf '  make bench-ladder\n\nGrafana: Permguard - Load test, http://127.0.0.1:%s\n' "$${PERMGUARD_GRAFANA_PORT:-7590}"

prepare-release: ## Move the repository to a version, so that tagging it is safe.
	./scripts/prepare-release.sh $(VERSION)

check-headers: ## Check that every source file carries the licence header.
	./scripts/check-license-headers.sh

check-systems: ## Check that the Makefile and the Taskfile offer the same commands.
	./scripts/check-build-systems.sh

test: ## Run tests.
	cargo test $(scope) $(FEATURES) $(profile) $(ARGS) $(FILTER) $(if $(NOCAPTURE),-- --nocapture)

version-control: ## Report the control plane version.
	cargo run $(profile) -p permguard-control-plane --bin permguard-control-plane -- version
