# Estate and seam contract validator — The Software Field Guide.
#
# Targets:
#   make fmt            format the Rego sources in place
#   make check          compile-check the policies
#   make test           run the Rego unit tests
#   make build         compile the six wasm bundles into build/wasm/
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
#   make check-obs    validate the three observability contracts
#                      [VOCAB=... SCHEMA=... BUDGET=...] [TODAY=YYYY-MM-DD]
#   make obs-lint      scan instrumentation code against the vocabularies
#                      [SCAN_SRC='src/a.py src/b.py']
#   make obs-gate      check a metrics export against the cardinality budget
#                      [SCHEMA=... BUDGET=... EXPORT=...]
#   make obs-demo      the done-when proof: a budget-breeding label caught
#                      with the budget file cited (runs the whole demo)
#   make check-actions validate the action registry (micro-actions, envelopes,
#                      ceilings, servers) [ACTIONS_REGISTRY=...] [TODAY=...]
#   make actions-gate  gate an agent manifest against the action registry
#                      [ACTIONS_REGISTRY=... ACTIONS_MANIFEST=...] [TODAY=...]
#   make actions-demo  the done-when proof: a phantom grant caught with the
#                      manifest cited (runs the whole demo)

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
VOCAB ?= examples/observability/vocabulary.yaml
SCHEMA ?= examples/observability/label-schema.yaml
BUDGET ?= examples/observability/cardinality-budget.yaml
SCAN_SRC ?= examples/observability/demo/src/storefront.py examples/observability/demo/src/payments.py
EXPORT ?= examples/observability/demo/metrics-export.json
ACTIONS_REGISTRY ?= examples/actions/registry.yaml
ACTIONS_MANIFEST ?= examples/actions/manifest.yaml

.PHONY: fmt check test build site e2e \
	check-enclave check-seam check-bundle check-authz \
	explain-authz who-could-access authz-disabled \
	check-obs obs-lint obs-gate obs-demo \
	check-actions actions-gate actions-demo \
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
	$(OPA) build -t wasm -e obs/audit -o build/obs.tar.gz policies
	tar -xzf build/obs.tar.gz -C build /policy.wasm
	mv build/policy.wasm build/wasm/obs.wasm
	$(OPA) build -t wasm -e actions/audit -o build/actions.tar.gz policies
	tar -xzf build/actions.tar.gz -C build /policy.wasm
	mv build/policy.wasm build/wasm/actions.wasm

site: build
	rm -rf site-build
	mkdir -p site-build/wasm
	cp -r site/* site-build/
	cp build/wasm/*.wasm site-build/wasm/

e2e: build
	node test/e2e.mjs

check-enclave:
	@test -f "$(FILE)" || { echo "usage: make check-enclave FILE=path/to/enclave.yaml"; exit 2; }
	@mkdir -p build
	yq -o=json '.' '$(FILE)' | jq -cs --arg today "$(TODAY)" '{contract: .[0], today: $$today}' \
		| $(OPA) eval -d policies -I 'data.estate.enclave.validate' --format=pretty | tee build/check-enclave.json
	@jq -e '.valid == true' build/check-enclave.json > /dev/null \
		|| { echo "check-enclave: the contract is invalid — findings above"; exit 1; }

check-seam:
	@test -f "$(FILE)" || { echo "usage: make check-seam FILE=path/to/seam.yaml"; exit 2; }
	@mkdir -p build
	yq -o=json '.' '$(FILE)' | jq -cs --arg today "$(TODAY)" '{contract: .[0], today: $$today}' \
		| $(OPA) eval -d policies -I 'data.estate.seam.validate' --format=pretty | tee build/check-seam.json
	@jq -e '.valid == true' build/check-seam.json > /dev/null \
		|| { echo "check-seam: the contract is invalid — findings above"; exit 1; }

check-bundle:
	@test -f "$(FILE)" || { echo "usage: make check-bundle FILE=path/to/bundle.yaml"; exit 2; }
	@mkdir -p build
	yq -o=json '.' '$(FILE)' | $(OPA) eval -d policies -I 'data.estate.cross.validate' --format=pretty | tee build/check-bundle.json
	@jq -e '.valid == true' build/check-bundle.json > /dev/null \
		|| { echo "check-bundle: the estate is invalid — findings above"; exit 1; }

check-authz:
	@test -f "$(FILE)" || { echo "usage: make check-authz FILE=path/to/policy-set.yaml [TODAY=YYYY-MM-DD]"; exit 2; }
	@mkdir -p build
	yq -o=json '.' '$(FILE)' | jq -cs --arg today "$(TODAY)" '{policySet: .[0], today: $$today}' \
		| $(OPA) eval -d policies -I 'data.authz.validate' --format=pretty | tee build/check-authz.json
	@jq -e '.valid == true' build/check-authz.json > /dev/null \
		|| { echo "check-authz: the policy set is invalid — findings above"; exit 1; }

# Answer one real 403 question from the tool alone: who asked for what,
# what the policy set answered, and the trace explaining every rule.
explain-authz:
	@test -f "$(FILE)" || { echo "usage: make explain-authz FILE=... SUBJECT=... ACTION=... RESOURCE=... [CONTEXT={...}]"; exit 2; }
	yq -o=json '.' '$(FILE)' | jq -cs --arg subject "$(SUBJECT)" --arg action "$(ACTION)" --arg resource "$(RESOURCE)" --argjson context "$(CONTEXT)" \
		'{request: {subject: $$subject, action: $$action, resource: $$resource, context: $$context}, policySet: .[0]}' \
		| $(OPA) eval -d policies -I 'data.authz.decide' --format=pretty

# Retrospective access question: which subjects could touch this resource
# (optionally: via this action) at any point in the window, from the
# versioned policy set as the audit substrate.
who-could-access:
	@test -f "$(FILE)" || { echo "usage: make who-could-access FILE=... RESOURCE=... [ACTION=...] FROM=YYYY-MM-DD TO=YYYY-MM-DD"; exit 2; }
	yq -o=json '.' '$(FILE)' | jq -cs --arg resource "$(WHO_RESOURCE)" --arg action "$(WHO_ACTION)" --arg from "$(FROM)" --arg to "$(TO)" \
		'{resource: $$resource} + (if $$action == "" then {} else {action: $$action} end) + {window: {from: $$from, to: $$to}, policySet: .[0]}' \
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

# Observability: validate the three contract documents (vocabulary, label
# schema, cardinality budget) together.
check-obs:
	@test -f "$(VOCAB)" || { echo "usage: make check-obs [VOCAB=... SCHEMA=... BUDGET=...] [TODAY=YYYY-MM-DD]"; exit 2; }
	@mkdir -p build
	yq -o=json '.' '$(VOCAB)' '$(SCHEMA)' '$(BUDGET)' \
		| jq -cs --arg today "$(TODAY)" '{vocabulary: .[0], labels: .[1], budget: .[2], today: $$today}' \
		| $(OPA) eval -d policies -I 'data.obs.validate' --format=pretty | tee build/check-obs.json
	@jq -e '.valid == true' build/check-obs.json > /dev/null \
		|| { echo "check-obs: the observability contracts are invalid — findings above"; exit 1; }

# Lint instrumentation code against the vocabularies: the scanner emits
# scan.json from the sources, then the policies judge every telemetry
# call. Fails (exit 1) when an event name, metric, or label is undeclared.
obs-lint:
	@mkdir -p build
	python3 scan/scan_instrumentation.py $(SCAN_SRC) > build/scan.json
	yq -o=json '.' '$(VOCAB)' '$(SCHEMA)' \
		| jq -cs --slurpfile scan build/scan.json '{vocabulary: .[0], labels: .[1], scan: $$scan[0]}' \
		| $(OPA) eval -d policies -I 'data.obs.lint' --format=pretty | tee build/obs-lint.json
	@jq -e '.valid == true' build/obs-lint.json > /dev/null \
		|| { echo "obs-lint: the instrumentation linter found errors above"; exit 1; }

# Gate a metrics export against the cardinality budget: per-label
# allocations and per-metric totals, with the budget file cited in the
# findings. Fails (exit 1) when the budget is breached.
obs-gate:
	@mkdir -p build
	yq -o=json '.' '$(SCHEMA)' '$(BUDGET)' \
		| jq -cs --slurpfile obs '$(EXPORT)' --arg budgetFile "$(BUDGET)" \
			'{labels: .[0], budget: .[1], observations: $$obs[0].observations, budgetFile: $$budgetFile}' \
		| $(OPA) eval -d policies -I 'data.obs.gate' --format=pretty | tee build/obs-gate.json
	@jq -e '.valid == true' build/obs-gate.json > /dev/null \
		|| { echo "obs-gate: the cardinality gate found errors above"; exit 1; }

# The done-when proof for book issue #61: a budget-breeding label is
# caught in a demo run with the budget file cited. Runs the good demo
# end to end, then proves both broken variants fail loudly.
obs-demo:
	@echo "--- 1. the three contracts validate ---"
	@$(MAKE) check-obs TODAY=$(ANCHOR_TODAY)
	@echo "--- 2. the demo instrumentation lints clean ---"
	@$(MAKE) obs-lint
	@echo "--- 3. the demo export passes the cardinality gate ---"
	@$(MAKE) obs-gate
	@echo "--- 4. an undeclared label in code is caught at PR time ---"
	@if $(MAKE) obs-lint SCAN_SRC=examples/observability/demo/broken/src/storefront.undeclared.py > build/obs-lint-undeclared.txt 2>&1; \
		then echo "FAIL: the undeclared label was not caught"; cat build/obs-lint-undeclared.txt; exit 1; \
		else grep -q 'lint/label-undeclared' build/obs-lint-undeclared.txt \
			|| { echo "FAIL: lint failed without the label-accretion rule"; cat build/obs-lint-undeclared.txt; exit 1; }; \
		fi
	@grep -q 'order_id.*storefront.undeclared.py' build/obs-lint-undeclared.txt \
		|| { echo "FAIL: the finding does not cite the file"; cat build/obs-lint-undeclared.txt; exit 1; }
	@echo "caught as expected: lint/label-undeclared citing the instrumentation file"
	@echo "--- 5. a budget-breeding label is caught with the budget file cited ---"
	@if $(MAKE) obs-gate SCHEMA=examples/observability/demo/broken/label-schema.with-order-id.yaml BUDGET=examples/observability/demo/broken/cardinality-budget.with-order-id.yaml EXPORT=examples/observability/demo/broken/metrics-export.breach.json > build/obs-gate-breach.txt 2>&1; \
		then echo "FAIL: the budget breach was not caught"; cat build/obs-gate-breach.txt; exit 1; \
		else grep -q 'budget/label-over-allocation' build/obs-gate-breach.txt \
			|| { echo "FAIL: the gate failed without the over-allocation rule"; cat build/obs-gate-breach.txt; exit 1; }; \
		fi
	@grep -q 'budget/metric-total-exceeded' build/obs-gate-breach.txt \
		|| { echo "FAIL: the gate missed the metric total breach"; cat build/obs-gate-breach.txt; exit 1; }
	@grep -q 'cardinality-budget.with-order-id.yaml' build/obs-gate-breach.txt \
		|| { echo "FAIL: the findings do not cite the budget file"; cat build/obs-gate-breach.txt; exit 1; }
	@echo "caught as expected: budget/label-over-allocation and budget/metric-total-exceeded citing the budget file"
	@echo "--- obs demo: all done-when proofs passed ---"

# Actions: validate the action registry (named, typed, parameter-checked
# micro-actions under the platform ceilings) alone.
check-actions:
	@test -f "$(ACTIONS_REGISTRY)" || { echo "usage: make check-actions [ACTIONS_REGISTRY=...] [TODAY=YYYY-MM-DD]"; exit 2; }
	@mkdir -p build
	yq -o=json '.' '$(ACTIONS_REGISTRY)' \
		| jq -cs --arg today "$(TODAY)" '{registry: .[0], today: $$today}' \
		| $(OPA) eval -d policies -I 'data.actions.validate' --format=pretty | tee build/check-actions.json
	@jq -e '.valid == true' build/check-actions.json > /dev/null \
		|| { echo "check-actions: the action registry is invalid — findings above"; exit 1; }

# Gate the agent manifest against the action registry: every grant names
# a declared action, every argument scope constrains a declared
# parameter, and no stage contradicts the effects it grants. Fails
# (exit 1) when the gate finds errors.
actions-gate:
	@test -f "$(ACTIONS_REGISTRY)" || { echo "usage: make actions-gate [ACTIONS_REGISTRY=... ACTIONS_MANIFEST=...] [TODAY=YYYY-MM-DD]"; exit 2; }
	@mkdir -p build
	yq -o=json '.' '$(ACTIONS_REGISTRY)' '$(ACTIONS_MANIFEST)' \
		| jq -cs --arg today "$(TODAY)" '{registry: .[0], manifest: .[1], today: $$today}' \
		| $(OPA) eval -d policies -I 'data.actions.gate' --format=pretty | tee build/actions-gate.json
	@jq -e '.valid == true' build/actions-gate.json > /dev/null \
		|| { echo "actions-gate: the action scope gate found errors above"; exit 1; }

# The done-when proof for book issue #70: a phantom grant is caught with
# the agent and the undeclared action cited. Runs the good pair end to
# end, then proves all five broken variants fail loudly.
actions-demo:
	@echo "--- 1. the action registry validates ---"
	@$(MAKE) check-actions TODAY=$(ANCHOR_TODAY)
	@echo "--- 2. the seeded manifest passes the action scope gate ---"
	@$(MAKE) actions-gate TODAY=$(ANCHOR_TODAY)
	@echo "--- 3. an untyped parameter is caught at contract time ---"
	@if $(MAKE) check-actions ACTIONS_REGISTRY=examples/actions/broken/registry.untyped-parameter.yaml TODAY=$(ANCHOR_TODAY) > build/actions-untyped.txt 2>&1; \
		then echo "FAIL: the untyped parameter was not caught"; cat build/actions-untyped.txt; exit 1; \
		else grep -q 'action/parameter-untyped' build/actions-untyped.txt \
			|| { echo "FAIL: the registry failed without the untyped-parameter rule"; cat build/actions-untyped.txt; exit 1; }; \
		fi
	@grep -q 'invoiceId' build/actions-untyped.txt \
		|| { echo "FAIL: the finding does not name the parameter"; cat build/actions-untyped.txt; exit 1; }
	@echo "caught as expected: action/parameter-untyped naming invoiceId"
	@echo "--- 4. an envelope that exceeds the platform ceiling is caught ---"
	@if $(MAKE) check-actions ACTIONS_REGISTRY=examples/actions/broken/registry.envelope-breach.yaml TODAY=$(ANCHOR_TODAY) > build/actions-envelope.txt 2>&1; \
		then echo "FAIL: the envelope breach was not caught"; cat build/actions-envelope.txt; exit 1; \
		else grep -q 'envelope/exceeds-ceiling' build/actions-envelope.txt \
			|| { echo "FAIL: the registry failed without the ceiling rule"; cat build/actions-envelope.txt; exit 1; }; \
		fi
	@grep -q 'compile-quarterly-report' build/actions-envelope.txt \
		|| { echo "FAIL: the finding does not name the action"; cat build/actions-envelope.txt; exit 1; }
	@echo "caught as expected: envelope/exceeds-ceiling naming compile-quarterly-report"
	@echo "--- 5. a Critical action that no longer asks is caught ---"
	@if $(MAKE) check-actions ACTIONS_REGISTRY=examples/actions/broken/registry.autoconfirm-critical.yaml TODAY=$(ANCHOR_TODAY) > build/actions-autoconfirm.txt 2>&1; \
		then echo "FAIL: the auto-confirmed Critical action was not caught"; cat build/actions-autoconfirm.txt; exit 1; \
		else grep -q 'action/confirm-required-at-level' build/actions-autoconfirm.txt \
			|| { echo "FAIL: the registry failed without the confirmation rule"; cat build/actions-autoconfirm.txt; exit 1; }; \
		fi
	@grep -q 'send-invoice-email' build/actions-autoconfirm.txt \
		|| { echo "FAIL: the finding does not name the action"; cat build/actions-autoconfirm.txt; exit 1; }
	@echo "caught as expected: action/confirm-required-at-level naming send-invoice-email"
	@echo "--- 6. a grant for an action the registry never declared is caught ---"
	@if $(MAKE) actions-gate ACTIONS_MANIFEST=examples/actions/broken/manifest.phantom-grant.yaml TODAY=$(ANCHOR_TODAY) > build/actions-phantom.txt 2>&1; \
		then echo "FAIL: the phantom grant was not caught"; cat build/actions-phantom.txt; exit 1; \
		else grep -q 'manifest/action-unknown' build/actions-phantom.txt \
			|| { echo "FAIL: the gate failed without the phantom-grant rule"; cat build/actions-phantom.txt; exit 1; }; \
		fi
	@grep -q 'purge-invoice-archive' build/actions-phantom.txt \
		|| { echo "FAIL: the finding does not name the undeclared action"; cat build/actions-phantom.txt; exit 1; }
	@echo "caught as expected: manifest/action-unknown naming purge-invoice-archive"
	@echo "--- 7. a read-only agent granted a write is caught ---"
	@if $(MAKE) actions-gate ACTIONS_MANIFEST=examples/actions/broken/manifest.readonly-writer.yaml TODAY=$(ANCHOR_TODAY) > build/actions-readonly.txt 2>&1; \
		then echo "FAIL: the stage contradiction was not caught"; cat build/actions-readonly.txt; exit 1; \
		else grep -q 'manifest/stage-contradiction' build/actions-readonly.txt \
			|| { echo "FAIL: the gate failed without the stage-contradiction rule"; cat build/actions-readonly.txt; exit 1; }; \
		fi
	@grep -q 'archive-reader' build/actions-readonly.txt \
		|| { echo "FAIL: the finding does not name the agent"; cat build/actions-readonly.txt; exit 1; }
	@echo "caught as expected: manifest/stage-contradiction naming archive-reader"
	@echo "--- actions demo: all done-when proofs passed ---"

# Validate every shipped example against the CI anchor date.
examples:
	$(MAKE) check-enclave FILE=examples/enclaves/checkout.yaml TODAY=$(ANCHOR_TODAY)
	$(MAKE) check-enclave FILE=examples/enclaves/payments.yaml TODAY=$(ANCHOR_TODAY)
	$(MAKE) check-seam FILE=examples/seams/checkout-web-tier.yaml TODAY=$(ANCHOR_TODAY)
	$(MAKE) check-seam FILE=examples/seams/payments-3ds-redirect.yaml TODAY=$(ANCHOR_TODAY)
	$(MAKE) check-bundle FILE=examples/bundle.yaml
	$(MAKE) check-authz FILE=examples/authz/storefront.yaml TODAY=$(ANCHOR_TODAY)
	$(MAKE) check-obs TODAY=$(ANCHOR_TODAY)
	$(MAKE) check-actions TODAY=$(ANCHOR_TODAY)
	$(MAKE) actions-gate TODAY=$(ANCHOR_TODAY)

# Everything CI runs, in order.
ci: check test examples e2e obs-demo actions-demo
	$(OPA) fmt --fail -l policies
