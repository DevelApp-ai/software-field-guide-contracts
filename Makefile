# Estate and seam contract validator — The Software Field Guide.
#
# Targets:
#   make fmt            format the Rego sources in place
#   make check          compile-check the policies
#   make test           run the Rego unit tests
#   make build         compile the three wasm bundles into build/wasm/
#   make site           assemble the deployable playground in site-build/
#   make e2e            run the node wasm smoke test (needs `make build` first)
#   make check-enclave FILE=examples/enclaves/checkout.yaml [TODAY=YYYY-MM-DD]
#   make check-seam    FILE=examples/seams/checkout-web-tier.yaml [TODAY=YYYY-MM-DD]
#   make check-bundle  FILE=examples/bundle.yaml
#
# Requirements: opa (v1.21+), jq, yq (v4). CI pins TODAY to an anchor date so
# the examples stay valid; locally TODAY defaults to the current date.

OPA ?= opa
TODAY ?= $(shell date +%F)
ANCHOR_TODAY ?= 2026-10-20

.PHONY: fmt check test build site e2e \
	check-enclave check-seam check-bundle \
	examples ci

fmt:
	$(OPA) fmt -w policies

check:
	$(OPA) check policies

test:
	$(OPA) test policies -v

build:
	rm -rf build
	mkdir -p build/wasm
	$(OPA) build -t wasm -e estate/enclave/validate -o build/enclave.tar.gz policies
	tar -xzf build/enclave.tar.gz -C build /policy.wasm
	mv build/policy.wasm build/wasm/enclave.wasm
	$(OPA) build -t wasm -e estate/seam/validate -o build/seam.tar.gz policies
	tar -xzf build/seam.tar.gz -C build /policy.wasm
	mv build/policy.wasm build/wasm/seam.wasm
	$(OPA) build -t wasm -e estate/cross/validate -o build/cross.tar.gz policies
	tar -xzf build/cross.tar.gz -C build /policy.wasm
	mv build/policy.wasm build/wasm/cross.wasm

site: build
	rm -rf site-build
	mkdir -p site-build/wasm
	cp -r site/* site-build/
	cp build/wasm/*.wasm site-build/wasm/

e2e: build
	node test/e2e.mjs

check-enclave:
	@test -f "$(FILE)" || { echo "usage: make check-enclave FILE=path/to/enclave.yaml"; exit 2; }
	yq -o=json '.' '$(FILE)' | jq -cs --arg today "$(TODAY)" '{contract: .[0], today: $today}' \
		| $(OPA) eval -d policies -I 'data.estate.enclave.validate' --format=pretty

check-seam:
	@test -f "$(FILE)" || { echo "usage: make check-seam FILE=path/to/seam.yaml"; exit 2; }
	yq -o=json '.' '$(FILE)' | jq -cs --arg today "$(TODAY)" '{contract: .[0], today: $today}' \
		| $(OPA) eval -d policies -I 'data.estate.seam.validate' --format=pretty

check-bundle:
	@test -f "$(FILE)" || { echo "usage: make check-bundle FILE=path/to/bundle.yaml"; exit 2; }
	yq -o=json '.' '$(FILE)' | $(OPA) eval -d policies -I 'data.estate.cross.validate' --format=pretty

# Validate every shipped example against the CI anchor date.
examples:
	$(MAKE) check-enclave FILE=examples/enclaves/checkout.yaml TODAY=$(ANCHOR_TODAY)
	$(MAKE) check-enclave FILE=examples/enclaves/payments.yaml TODAY=$(ANCHOR_TODAY)
	$(MAKE) check-seam FILE=examples/seams/checkout-web-tier.yaml TODAY=$(ANCHOR_TODAY)
	$(MAKE) check-seam FILE=examples/seams/payments-3ds-redirect.yaml TODAY=$(ANCHOR_TODAY)
	$(MAKE) check-bundle FILE=examples/bundle.yaml

# Everything CI runs, in order.
ci: check test examples e2e
	$(OPA) fmt --fail -l policies
