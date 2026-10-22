# Estate and seam contract validator — The Software Field Guide.
#
# Targets:
#   make fmt            format the Rego sources in place
#   make check          compile-check the policies
#   make test           run the Rego unit tests
#   make build         compile the four wasm bundles into build/wasm/
#   make site           assemble the deployable playground in site-build/
#   make e2e            run the node wasm smoke test (needs `make build` first)
#   make check-enclave FILE=examples/enclaves/checkout.yaml [TODAY=YYYY-MM-DD]
#   make check-seam    FILE=examples/seams/checkout-web-tier.yaml [TODAY=YYYY-MM-DD]
#   make check-bundle  FILE=examples/bundle.yaml
#   make check-authz  FILE=examples/authz/storefront.yaml [TODAY=YYYY-MM-DD]
#   make explain-authz FILE=examples/authz/storefront.yaml SUBJECT=bob \
#                      ACTION=order.charge RESOURCE=orders-1041 [CONTEXT={"mfa": false}]
#   make who-could-access FILE=examples/authz/storefront.yaml RESOURCE=orders-1041 \
#                      [ACTION=order.read] FROM=2026-01-01 TO=2026-12-31
#   make authz-disabled FILE=examples/authz/storefront.yaml
#
# Requirements: opa (v1.21+), jq, yq (v4). CI pins TODAY to an anchor date so
# the examples stay valid; locally TODAY defaults to the current date.

OPA ?= opa
TODAY ?= $(shell date +%F)
ANCHOR_TODAY ?= 2026-10-20
SUBJECT ?= bob
ACTION ?= order.charge
RESOURCE ?= orders-1041
CONTEXT ?= {}
WHO_RESOURCE ?= orders-1041
WHO_ACTION ?=
FROM ?= 2026-01-01
TO ?= 2026-12-31

.PHONY: fmt check test build site e2e \
	check-enclave check-seam check-bundle check-authz \
	explain-authz who-could-access authz-disabled \
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
	$(OPA) build -t wasm -e authz/decide -o build/authz.tar.gz policies
	tar -xzf build/authz.tar.gz -C build /policy.wasm
	mv build/policy.wasm build/wasm/authz.wasm

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

check-authz:
	@test -f "$(FILE)" || { echo "usage: make check-authz FILE=path/to/policy-set.yaml [TODAY=YYYY-MM-DD]"; exit 2; }
	yq -o=json '.' '$(FILE)' | jq -cs --arg today "$(TODAY)" '{policySet: .[0], today: $today}' \
		| $(OPA) eval -d policies -I 'data.authz.validate' --format=pretty

# Answer one real 403 question from the tool alone: who asked for what,
# what the policy set answered, and the trace explaining every rule.
explain-authz:
	@test -f "$(FILE)" || { echo "usage: make explain-authz FILE=... SUBJECT=... ACTION=... RESOURCE=... [CONTEXT={...}]"; exit 2; }
	yq -o=json '.' '$(FILE)' | jq -cs --arg subject "$(SUBJECT)" --arg action "$(ACTION)" --arg resource "$(RESOURCE)" --argjson context "$(CONTEXT)" \
		'{request: {subject: $subject, action: $action, resource: $resource, context: $context}, policySet: .[0]}' \
		| $(OPA) eval -d policies -I 'data.authz.decide' --format=pretty

# Retrospective access question: which subjects could touch this resource
# (optionally: via this action) at any point in the window, from the
# versioned policy set as the audit substrate.
who-could-access:
	@test -f "$(FILE)" || { echo "usage: make who-could-access FILE=... RESOURCE=... [ACTION=...] FROM=YYYY-MM-DD TO=YYYY-MM-DD"; exit 2; }
	yq -o=json '.' '$(FILE)' | jq -cs --arg resource "$(WHO_RESOURCE)" --arg action "$(WHO_ACTION)" --arg from "$(FROM)" --arg to "$(TO)" \
		'{resource: $resource} + (if $action == "" then {} else {action: $action} end) + {window: {from: $from, to: $to}, policySet: .[0]}' \
		| $(OPA) eval -d policies -I 'data.authz.who_could_access' --format=pretty

# Fail-closed proof for the disabled state: generate the test inventory
# from the policy set's probes, then run every probe against the disabled
# set and fail unless each answer is deny by the fail-closed rule.
authz-disabled:
	@test -f "$(FILE)" || { echo "usage: make authz-disabled FILE=path/to/policy-set.yaml"; exit 2; }
	@echo "--- generated disabled-state test inventory ---"
	yq -o=json '.' '$(FILE)' | jq -cs '{policySet: .[0]}' | $(OPA) eval -d policies -I 'data.authz.disabled_tests' --format=pretty
	@echo "--- disabled-state run: every probe must deny ---"
	yq -o=json '.' '$(FILE)' | jq -cs '{policySet: .[0]}' | $(OPA) eval -d policies -I 'data.authz.disabled_check' --format=pretty

# Validate every shipped example against the CI anchor date.
examples:
	$(MAKE) check-enclave FILE=examples/enclaves/checkout.yaml TODAY=$(ANCHOR_TODAY)
	$(MAKE) check-enclave FILE=examples/enclaves/payments.yaml TODAY=$(ANCHOR_TODAY)
	$(MAKE) check-seam FILE=examples/seams/checkout-web-tier.yaml TODAY=$(ANCHOR_TODAY)
	$(MAKE) check-seam FILE=examples/seams/payments-3ds-redirect.yaml TODAY=$(ANCHOR_TODAY)
	$(MAKE) check-bundle FILE=examples/bundle.yaml
	$(MAKE) check-authz FILE=examples/authz/storefront.yaml TODAY=$(ANCHOR_TODAY)

# Everything CI runs, in order.
ci: check test examples e2e
	$(OPA) fmt --fail -l policies
