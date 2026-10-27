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

.PHONY: check-boundaries check-traceability traceability-index check-chart check-durability check-mutations fuzz clean coverage coverage-html coverage-lcov bench-release bench-decide bench-grafana bench-temporal bench-grpc bench-hold lab-clean bench-ladder bench-peak bench-server bench-server-shed bench-shed bench-tls build check check-core-deps check-headers check-notices check-seams check-systems check-vectors notices cli cp-basics cp-dogwood cp-rspipe help lab-all lab-down lab-logs lab-observability lab-test lab-up lab-where lint plane-run prepare-release run-all run-as-mtls-all run-as-mtls-control run-as-mtls-data run-as-tls-all run-as-tls-control run-as-tls-data run-control run-data run-experimental run-experimental-control run-experimental-data test version-control llm-init

build: ## Build every Permguard crate.
	cargo build $(scope) $(profile) $(ARGS)

check: ## Run lint, structural checks, and tests.
	$(MAKE) lint
	$(MAKE) check-seams
	$(MAKE) check-core-deps
	$(MAKE) check-systems
	$(MAKE) check-headers
	$(MAKE) check-notices
	$(MAKE) check-boundaries
	$(MAKE) check-durability
	$(MAKE) check-mutations
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

cp-dogwood: ## Copy the dogwood-session-access example into the current directory.
	$(REPO_DIR)/scripts/copy-example.sh dogwood-session-access "$(CURDIR)"

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

run-experimental-control: ## Run the control plane with the event store on.
	$(MAKE) plane-run PLANE=control CONFIG=config.local-experimental.yml ARGS="$(ARGS)" RELEASE=$(RELEASE)

run-experimental-data: ## Run the data plane with the temporal interface on.
	$(MAKE) plane-run PLANE=data CONFIG=config.local-experimental.yml ARGS="$(ARGS)" RELEASE=$(RELEASE)

run-experimental: ## Run both planes in one process with every experimental runtime turned on.
	$(MAKE) run-all CONFIG=config.local-experimental.yml ARGS="$(ARGS)" RELEASE=$(RELEASE)

run-as-tls-control: ## Run the control plane locally, with TLS.
	$(MAKE) plane-run PLANE=control CONFIG=config.local-tls.yml ARGS="$(ARGS)" RELEASE=$(RELEASE)

run-as-tls-data: ## Run the data plane locally, with TLS.
	$(MAKE) plane-run PLANE=data CONFIG=config.local-tls.yml ARGS="$(ARGS)" RELEASE=$(RELEASE)

run-as-tls-all: ## Run the all-in-one runtime locally, with TLS.
	$(MAKE) run-all CONFIG=config.local-tls.yml ARGS="$(ARGS)" RELEASE=$(RELEASE)

run-as-mtls-control: ## Run the control plane locally, with mutual TLS on its shared HTTP+gRPC listener.
	$(MAKE) plane-run PLANE=control CONFIG=config.local-mtls.yml ARGS="$(ARGS)" RELEASE=$(RELEASE)

run-as-mtls-data: ## Run the data plane locally, with mutual TLS on its shared HTTP+gRPC listener.
	$(MAKE) plane-run PLANE=data CONFIG=config.local-mtls.yml ARGS="$(ARGS)" RELEASE=$(RELEASE)

run-as-mtls-all: ## Run all-in-one locally, with mutual TLS on each shared HTTP+gRPC plane listener.
	$(MAKE) run-all CONFIG=config.local-mtls.yml ARGS="$(ARGS)" RELEASE=$(RELEASE)

lab-up: ## Start one Compose lab profile, enrolled by the lab's authority. PROFILE: all-in-one, split-plane (default), multi-data-plane, multi-group, temporal-replicas.
	COMPOSE_PROFILES=$(if $(PROFILE),$(PROFILE),split-plane) docker compose -f docker-compose.lab.yml up --build $(if $(ARGS),$(ARGS),-d)
	$(MAKE) lab-where

lab-all: ## Start the Compose lab's all-in-one profile.
	$(MAKE) lab-up PROFILE=all-in-one ARGS="$(ARGS)"

lab-test: ## Run the Compose lab's gate: every profile, or PROFILE, on fresh volumes, then tear it down (TD-3).
	scripts/compose-lab.sh $(PROFILE)

lab-observability: ## Start only Prometheus, Grafana and Loki, to watch planes running on the host.
	COMPOSE_PROFILES=observability docker compose -f docker-compose.lab.yml up $(if $(ARGS),$(ARGS),-d)
	$(MAKE) lab-where

lab-down: ## Stop the compose lab, keeping its data: metrics, logs and dashboards survive the next up.
	docker compose -f docker-compose.lab.yml --profile '*' down $(ARGS)

lab-clean: ## Stop the compose lab AND discard its data: the next up starts from a new authority and empty dashboards.
	docker compose -f docker-compose.lab.yml --profile '*' down -v

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

lab-where: ## Print where the lab is listening. Its ports are ephemeral, on the host's loopback.
	@printf 'Grafana     http://127.0.0.1:%s   (with the observability profile)\n' "$${PERMGUARD_GRAFANA_PORT:-7590}"
	@printf 'Prometheus  http://127.0.0.1:%s\n' "$${PERMGUARD_PROMETHEUS_PORT:-7591}"
	@printf 'Loki        http://127.0.0.1:%s\n' "$${PERMGUARD_LOKI_PORT:-7592}"
	@docker compose -f docker-compose.lab.yml --profile '*' ps
	@printf '\nThe certificates name the service: pass --tls-server-name <service> with the lab authority,\n'
	@printf 'docker compose -f docker-compose.lab.yml cp lab-pki:/lab/pki/ca.crt .\n'

bench-release: ## The release benchmark on this machine: every interface and evidence mode, report in permguard-benchmark.json (STORAGE names the storage class).
	cargo build --release --locked -p permguard-all-in-one -p permguard-cli -p permguard-conformance --bins
	target/release/permguard-bench run --server target/release/permguard-all-in-one --cli target/release/permguard --storage-class "$(or $(STORAGE),unspecified local storage)" --out permguard-benchmark.json $(ARGS)
	target/release/permguard-bench capacity permguard-benchmark.json

bench-server: ## Run the control plane for capacity benchmarks: release build, limits out of the way (each PERMGUARD_LIMITS_* overridable).
	PERMGUARD_LIMITS_CONCURRENT_REQUESTS=$${PERMGUARD_LIMITS_CONCURRENT_REQUESTS:-100000} PERMGUARD_LIMITS_CONNECTIONS=$${PERMGUARD_LIMITS_CONNECTIONS:-20000} PERMGUARD_LIMITS_CONNECTIONS_PER_PEER=$${PERMGUARD_LIMITS_CONNECTIONS_PER_PEER:-0} cargo run --release -p permguard-control-plane --bin permguard-control-plane -- crates/permguard-control-plane/config.local.yml $(ARGS)

bench-server-shed: ## Run the control plane for the shed benchmark: a low request ceiling, per-address bound off.
	PERMGUARD_LIMITS_CONCURRENT_REQUESTS=8 PERMGUARD_LIMITS_CONNECTIONS_PER_PEER=0 cargo run --release -p permguard-control-plane --bin permguard-control-plane -- crates/permguard-control-plane/config.local.yml $(ARGS)

bench-decide: ## What a decision costs — the PDP path, cold and warm, single and boxcarred.
	k6 run --tag testid=decide-$$(date +%Y%m%d-%H%M%S) $(K6_ARGS) bench/decide.js

bench-temporal: ## What an occurrence costs — recorded, decided, and under overlap.
	k6 run --tag testid=temporal-$$(date +%Y%m%d-%H%M%S) $(K6_ARGS) bench/temporal.js

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

check-boundaries: ## Check that every untrusted decoder is registered, bounded and fuzzed.
	cargo test -p permguard-conformance --test boundaries --locked

check-chart: ## Lint the Helm chart and run its rendering tests; `make test` runs them too, so both need helm.
	helm lint charts/permguard --values charts/permguard/values-production.yaml --values charts/permguard/ci/image-verification.yaml
	cargo test -p permguard-conformance --test chart --locked

check-durability: ## Check that every durability primitive lives in the storage library or is allow-listed.
	cargo test -p permguard-conformance --test durability --locked

check-mutations: ## Check that security state and the catalog are written only through the mutation engine.
	cargo test -p permguard-conformance --test mutations --locked
	cargo test -p permguard-conformance --test catalog_writers --locked

fuzz: ## Run every fuzz target for SECONDS each (nightly toolchain and cargo-fuzz).
	./scripts/fuzz.sh $(or $(SECONDS),30)

check-headers: ## Check that every source file carries the licence header.
	./scripts/check-license-headers.sh

check-traceability: ## Check that every section and finding of the blueprint is traced to code and tests (WP-7.13).
	cargo test -p permguard-conformance --test traceability

traceability-index: ## Regenerate the blueprint index from the knowledge base (KNOWLEDGE=<workspace>/.agents/knowledge/permguard).
	python3 scripts/blueprint-index.py $(or $(KNOWLEDGE),../../.agents/knowledge/permguard)

check-vectors: ## Check that the golden vectors are what their independent generator prints (Python 3, `cryptography`).
	python3 contracts/vectors/generate.py | diff - contracts/vectors/evidence.json
	python3 contracts/vectors/identity.py | diff - contracts/vectors/identity.json
	python3 contracts/vectors/session.py | diff - contracts/vectors/session.json
	python3 contracts/vectors/secrets.py | diff - contracts/vectors/secrets.json
	python3 contracts/vectors/keys.py | diff - contracts/vectors/keys.json
	python3 contracts/vectors/membership.py | diff - contracts/vectors/membership.json
	python3 contracts/vectors/host_cli.py | diff - contracts/vectors/host-cli.json
	python3 contracts/vectors/audit.py | diff - contracts/vectors/audit.json
	python3 contracts/vectors/plan.py | diff - contracts/vectors/plan.json
	python3 contracts/vectors/stream.py | diff - contracts/vectors/stream.json
	python3 contracts/vectors/notp.py | diff - contracts/vectors/notp.json
	python3 contracts/vectors/signed_response.py | diff - contracts/vectors/signed-response.json

notices: ## Regenerate THIRD_PARTY_NOTICES.md from the resolved dependency graph.
	./scripts/third-party-notices.sh

check-notices: ## Check that THIRD_PARTY_NOTICES.md matches the dependency graph.
	./scripts/third-party-notices.sh --check

check-systems: ## Check that the Makefile and the Taskfile offer the same commands.
	./scripts/check-build-systems.sh

test: ## Run tests.
	cargo test $(scope) $(FEATURES) $(profile) $(ARGS) $(FILTER) $(if $(NOCAPTURE),-- --nocapture)

version-control: ## Report the control plane version.
	cargo run $(profile) -p permguard-control-plane --bin permguard-control-plane -- version

llm-init: ## Initialize LLM agent workspace
	@./scripts/llm-init.sh
