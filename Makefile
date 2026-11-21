# Estate and seam contract validator — The Software Field Guide.
#
# Targets:
#   make fmt            format the Rego sources in place
#   make check          compile-check the policies
#   make test           run the Rego unit tests
#   make build         compile the fourteen wasm bundles into build/wasm/
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
#   make check-alerts validate the alerting contract (severity ladder, runbooks,
#                      alert rules) [ALERTING=...] [TODAY=YYYY-MM-DD]
#   make alerts-gate  gate an incident register against the alerting contract
#                      [ALERTING=... REGISTER=...] [TODAY=YYYY-MM-DD]
#   make alerts-demo  the done-when proof: an unlinked alert caught with the
#                      alert and register cited (runs the whole demo)
#   make check-actions validate the action registry (micro-actions, envelopes,
#                      ceilings, servers) [ACTIONS_REGISTRY=...] [TODAY=...]
#   make actions-gate  gate an agent manifest against the action registry
#                      [ACTIONS_REGISTRY=... ACTIONS_MANIFEST=...] [TODAY=...]
#   make actions-demo  the done-when proof: a phantom grant caught with the
#                      manifest cited (runs the whole demo)
#   make check-erasure validate the DEK registry (per-tenant keys, states,
#                      destruction evidence) [ERASURE_KEYS=...] [TODAY=...]
#   make erasure-gate  gate an erasure case against the DEK registry
#                      [ERASURE_KEYS=... ERASURE_CASE=...] [TODAY=...]
#   make erasure-demo  the done-when proof: a replica without its sweep
#                      record caught citing the store (runs the whole demo)
#   make check-segment validate the segment contract (segments, rules,
#                      TTL-bound exceptions) [CONTRACT=...] [TODAY=...]
#   make segment-gate gate renders, flow evidence, and a promotion PR
#                      against the contract [CONTRACT=... RENDERS=...
#                      FLOWS=... PROMOTION=...] [TODAY=...]
#   make segment-demo  the done-when proof: a render missing one fabric
#                      caught citing both files (runs the whole demo)
#   make check-ingress validate the ingress posture case (the zone and its
#                      wildcards, the default-deny, the certificate clocks,
#                      the SLOs, the audit coverage) [INGRESS_CASE=...]
#   make ingress-gate gate the kill path against the drill record
#                      [INGRESS_CASE=... INGRESS_DRILL=...] [TODAY=...]
#   make ingress-demo the done-when proof: a kill path never rehearsed
#                      caught citing the drill record (runs the whole demo)
#   make check-component validate the component package manifest
#                      [COMPONENT_PACKAGE=...] [TODAY=YYYY-MM-DD]
#   make component-gate gate the package against the component registry
#                      [COMPONENT_PACKAGE=... COMPONENT_REGISTRY=...] [TODAY=...]
#   make component-demo the done-when proof: an unregistered package caught
#                      citing both files (runs the whole demo)
#   make check-matrix  validate the render matrix (the fabrics it covers and
#                      their rendered copies of the package) [MATRIX=...]
#   make matrix-gate  gate every fabric's render against the component
#                      package manifest [COMPONENT_PACKAGE=... MATRIX=...]
#   make matrix-demo  the done-when proof: one fabric quietly running a
#                      different release caught citing both files
#   make check-broker validate the broker grant document (the consumer
#                      identities it declares and the grants it issued)
#                      [BROKER_GRANTS=...] [TODAY=YYYY-MM-DD]
#   make broker-gate  gate the grants against the component package
#                      manifest [BROKER_GRANTS=... COMPONENT_PACKAGE=...]
#                      [TODAY=YYYY-MM-DD]
#   make broker-demo the done-when proof: a wildcard grant caught naming
#                      the scope the broker exists to prevent

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
ALERTING ?= examples/alerting/alerting.yaml
REGISTER ?= examples/alerting/register.yaml
ACTIONS_REGISTRY ?= examples/actions/registry.yaml
ACTIONS_MANIFEST ?= examples/actions/manifest.yaml
ERASURE_KEYS ?= examples/erasure/keys.yaml
ERASURE_CASE ?= examples/erasure/case-forgotten.yaml
CONTRACT ?= examples/segment/contract.yaml
RENDERS ?= examples/segment/renders.yaml
FLOWS ?= examples/segment/flows.yaml
PROMOTION ?= examples/segment/promotion.yaml
INGRESS_CASE ?= examples/ingress/case.yaml
INGRESS_DRILL ?= examples/ingress/drill.yaml
CITIZEN_MANIFEST ?= examples/citizen/manifest.yaml
CITIZEN_SPEC ?= examples/citizen/spec.yaml
CITIZEN_REGISTRY ?= examples/citizen/guardrails.yaml
COMPONENT_PACKAGE ?= examples/component/package.yaml
COMPONENT_REGISTRY ?= examples/component/registry.yaml
MATRIX ?= examples/matrix/matrix.yaml
BROKER_GRANTS ?= examples/broker/grants.yaml

.PHONY: fmt check test build site e2e \
	check-enclave check-seam check-bundle check-authz \
	explain-authz who-could-access authz-disabled \
	check-obs obs-lint obs-gate obs-demo \
	check-alerts alerts-gate alerts-demo \
	check-actions actions-gate actions-demo \
	check-erasure erasure-gate erasure-demo \
	check-segment segment-gate segment-demo \
	check-ingress ingress-gate ingress-demo \
	check-citizen citizen-gate citizen-demo \
	check-component component-gate component-demo \
	check-matrix matrix-gate matrix-demo \
	check-broker broker-gate broker-demo \
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
	$(OPA) build -t wasm -e alerts/audit -o build/alerts.tar.gz policies
	tar -xzf build/alerts.tar.gz -C build /policy.wasm
	mv build/policy.wasm build/wasm/alerts.wasm
	$(OPA) build -t wasm -e actions/audit -o build/actions.tar.gz policies
	tar -xzf build/actions.tar.gz -C build /policy.wasm
	mv build/policy.wasm build/wasm/actions.wasm
	$(OPA) build -t wasm -e erasure/audit -o build/erasure.tar.gz policies
	tar -xzf build/erasure.tar.gz -C build /policy.wasm
	mv build/policy.wasm build/wasm/erasure.wasm
	$(OPA) build -t wasm -e segment/audit -o build/segment.tar.gz policies
	tar -xzf build/segment.tar.gz -C build /policy.wasm
	mv build/policy.wasm build/wasm/segment.wasm
	$(OPA) build -t wasm -e ingress/audit -o build/ingress.tar.gz policies
	tar -xzf build/ingress.tar.gz -C build /policy.wasm
	mv build/policy.wasm build/wasm/ingress.wasm
	$(OPA) build -t wasm -e citizen/audit -o build/citizen.tar.gz policies
	tar -xzf build/citizen.tar.gz -C build /policy.wasm
	mv build/policy.wasm build/wasm/citizen.wasm
	$(OPA) build -t wasm -e component/audit -o build/component.tar.gz policies
	tar -xzf build/component.tar.gz -C build /policy.wasm
	mv build/policy.wasm build/wasm/component.wasm
	$(OPA) build -t wasm -e matrix/audit -o build/matrix.tar.gz policies
	tar -xzf build/matrix.tar.gz -C build /policy.wasm
	mv build/policy.wasm build/wasm/matrix.wasm
	$(OPA) build -t wasm -e broker/audit -o build/broker.tar.gz policies
	tar -xzf build/broker.tar.gz -C build /policy.wasm
	mv build/policy.wasm build/wasm/broker.wasm

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

# Alerts: validate the alerting contract (severity ladder with definedOn
# dates, runbooks with escalation clocks, alert rules with owners) alone.
check-alerts:
	@test -f "$(ALERTING)" || { echo "usage: make check-alerts [ALERTING=...] [TODAY=YYYY-MM-DD]"; exit 2; }
	@mkdir -p build
	yq -o=json '.' '$(ALERTING)' \
		| jq -cs --arg today "$(TODAY)" '{alerting: .[0], today: $$today}' \
		| $(OPA) eval -d policies -I 'data.alerts.validate' --format=pretty | tee build/check-alerts.json
	@jq -e '.valid == true' build/check-alerts.json > /dev/null \
		|| { echo "check-alerts: the alerting contract is invalid — findings above"; exit 1; }

# Gate the incident register against the alerting contract: every fired
# alert must be claimed by an incident record, severities must be on the
# ladder as it stood at detection time, and postmortem actions must be
# verified closed. Fails (exit 1) when the gate finds errors.
alerts-gate:
	@test -f "$(ALERTING)" || { echo "usage: make alerts-gate [ALERTING=... REGISTER=...] [TODAY=YYYY-MM-DD]"; exit 2; }
	@mkdir -p build
	yq -o=json '.' '$(ALERTING)' '$(REGISTER)' \
		| jq -cs --arg today "$(TODAY)" '{alerting: .[0], register: .[1], today: $$today}' \
		| $(OPA) eval -d policies -I 'data.alerts.gate' --format=pretty | tee build/alerts-gate.json
	@jq -e '.valid == true' build/alerts-gate.json > /dev/null \
		|| { echo "alerts-gate: the alert-to-record gate found errors above"; exit 1; }

# The done-when proof for book issue #69: an unlinked alert is caught with
# the alert and the register cited. Runs the good pair end to end, then
# proves all five broken variants fail loudly.
alerts-demo:
	@echo "--- 1. the alerting contract validates ---"
	@$(MAKE) check-alerts TODAY=$(ANCHOR_TODAY)
	@echo "--- 2. the seeded register passes the alert-to-record gate ---"
	@$(MAKE) alerts-gate TODAY=$(ANCHOR_TODAY)
	@echo "--- 3. a runbook without its escalation clock is caught at contract time ---"
	@if $(MAKE) check-alerts ALERTING=examples/alerting/broken/alerting.no-escalation-clock.yaml TODAY=$(ANCHOR_TODAY) > build/alerts-no-clock.txt 2>&1; \
		then echo "FAIL: the missing escalation clock was not caught"; cat build/alerts-no-clock.txt; exit 1; \
		else grep -q 'runbook/escalation-clock-required' build/alerts-no-clock.txt \
			|| { echo "FAIL: the contract failed without the escalation-clock rule"; cat build/alerts-no-clock.txt; exit 1; }; \
		fi
	@echo "caught as expected: runbook/escalation-clock-required"
	@echo "--- 4. an alert that fired without a record is caught ---"
	@if $(MAKE) alerts-gate REGISTER=examples/alerting/broken/register.unlinked-alert.yaml TODAY=$(ANCHOR_TODAY) > build/alerts-unlinked.txt 2>&1; \
		then echo "FAIL: the unlinked alert was not caught"; cat build/alerts-unlinked.txt; exit 1; \
		else grep -q 'alerts/no-record-linkage' build/alerts-unlinked.txt \
			|| { echo "FAIL: the gate failed without the record-linkage rule"; cat build/alerts-unlinked.txt; exit 1; }; \
		fi
	@grep -q 'storefront-latency' build/alerts-unlinked.txt \
		|| { echo "FAIL: the finding does not name the unlinked alert"; cat build/alerts-unlinked.txt; exit 1; }
	@echo "caught as expected: alerts/no-record-linkage naming storefront-latency"
	@echo "--- 5. a severity off the ladder is caught ---"
	@if $(MAKE) alerts-gate REGISTER=examples/alerting/broken/register.off-ladder.yaml TODAY=$(ANCHOR_TODAY) > build/alerts-off-ladder.txt 2>&1; \
		then echo "FAIL: the off-ladder severity was not caught"; cat build/alerts-off-ladder.txt; exit 1; \
		else grep -q 'gate/severity-off-ladder' build/alerts-off-ladder.txt \
			|| { echo "FAIL: the gate failed without the severity-ladder rule"; cat build/alerts-off-ladder.txt; exit 1; }; \
		fi
	@echo "caught as expected: gate/severity-off-ladder"
	@echo "--- 6. a severity defined after the incident is caught ---"
	@if $(MAKE) alerts-gate ALERTING=examples/alerting/broken/alerting.late-ladder.yaml TODAY=$(ANCHOR_TODAY) > build/alerts-late-ladder.txt 2>&1; \
		then echo "FAIL: the late ladder was not caught"; cat build/alerts-late-ladder.txt; exit 1; \
		else grep -q 'gate/severity-defined-after-detection' build/alerts-late-ladder.txt \
			|| { echo "FAIL: the gate failed without the severity-timing rule"; cat build/alerts-late-ladder.txt; exit 1; }; \
		fi
	@echo "caught as expected: gate/severity-defined-after-detection"
	@echo "--- 7. a postmortem action without closure verification is caught ---"
	@if $(MAKE) alerts-gate REGISTER=examples/alerting/broken/register.unverified-action.yaml TODAY=$(ANCHOR_TODAY) > build/alerts-unverified.txt 2>&1; \
		then echo "FAIL: the unverified action was not caught"; cat build/alerts-unverified.txt; exit 1; \
		else grep -q 'gate/action-unverified' build/alerts-unverified.txt \
			|| { echo "FAIL: the gate failed without the action-verification rule"; cat build/alerts-unverified.txt; exit 1; }; \
		fi
	@echo "caught as expected: gate/action-unverified"
	@echo "--- alerts demo: all done-when proofs passed ---"

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

# Erasure: validate the DEK registry (named keys, states, and
# destruction evidence) alone.
check-erasure:
	@test -f "$(ERASURE_KEYS)" || { echo "usage: make check-erasure [ERASURE_KEYS=...] [TODAY=YYYY-MM-DD]"; exit 2; }
	@mkdir -p build
	yq -o=json '.' '$(ERASURE_KEYS)' \
		| jq -cs --arg today "$(TODAY)" '{keys: .[0], today: $$today}' \
		| $(OPA) eval -d policies -I 'data.erasure.validate' --format=pretty | tee build/check-erasure.json
	@jq -e '.valid == true' build/check-erasure.json > /dev/null \
		|| { echo "check-erasure: the DEK registry is invalid — findings above"; exit 1; }

# Gate the erasure case against the DEK registry: every store in the
# inventory swept or honestly pending, the backup windows declared,
# and the tenant's keys destroyed — nothing is forgotten without a
# record. Fails (exit 1) when the gate finds errors.
erasure-gate:
	@test -f "$(ERASURE_KEYS)" || { echo "usage: make erasure-gate [ERASURE_KEYS=... ERASURE_CASE=...] [TODAY=YYYY-MM-DD]"; exit 2; }
	@mkdir -p build
	yq -o=json '.' '$(ERASURE_KEYS)' '$(ERASURE_CASE)' \
		| jq -cs --arg today "$(TODAY)" '{keys: .[0], case: .[1], today: $$today}' \
		| $(OPA) eval -d policies -I 'data.erasure.gate' --format=pretty | tee build/erasure-gate.json
	@jq -e '.valid == true' build/erasure-gate.json > /dev/null \
		|| { echo "erasure-gate: the deletion evidence gate found errors above"; exit 1; }

# The done-when proof for book issue #79: a replica without its sweep
# record is caught citing the store. Runs the control and the pending
# case end to end, then proves all the broken variants fail loudly.
erasure-demo:
	@echo "--- 1. the DEK registry validates ---"
	@$(MAKE) check-erasure TODAY=$(ANCHOR_TODAY)
	@echo "--- 2. the destroyed-DEK control passes and renders forgotten ---"
	@$(MAKE) erasure-gate TODAY=$(ANCHOR_TODAY)
	@grep -q '"verdict": "forgotten"' build/erasure-gate.json \
		|| { echo "FAIL: the control case did not render the forgotten verdict"; cat build/erasure-gate.json; exit 1; }
	@echo "control verdict: forgotten"
	@echo "--- 3. the unexpired-backup case renders pending, honest and stays open ---"
	@$(MAKE) erasure-gate ERASURE_CASE=examples/erasure/case-pending.yaml TODAY=$(ANCHOR_TODAY)
	@grep -q '"verdict": "pending, honest"' build/erasure-gate.json \
		|| { echo "FAIL: the pending case did not render the pending, honest verdict"; cat build/erasure-gate.json; exit 1; }
	@jq -e '.stores[] | select(.store == "nightly-backups" and .verdict == "pending")' build/erasure-gate.json > /dev/null \
		|| { echo "FAIL: the pending backup did not render as pending"; cat build/erasure-gate.json; exit 1; }
	@echo "pending case verdict: pending, honest — the case stays open until the window closes"
	@echo "--- 4. a replica without its sweep record is caught citing the store ---"
	@if $(MAKE) erasure-gate ERASURE_CASE=examples/erasure/broken/case.replica-unswept.yaml TODAY=$(ANCHOR_TODAY) > build/erasure-replica.txt 2>&1; \
		then echo "FAIL: the unswept replica was not caught"; cat build/erasure-replica.txt; exit 1; \
		else grep -q 'sweep/store-unswept' build/erasure-replica.txt \
			|| { echo "FAIL: the gate failed without the unswept-store rule"; cat build/erasure-replica.txt; exit 1; }; \
		fi
	@grep -q 'postgres-replica-eu' build/erasure-replica.txt \
		|| { echo "FAIL: the finding does not cite the store"; cat build/erasure-replica.txt; exit 1; }
	@test $$(jq '[.findings[] | select(.severity == "error")] | length' build/erasure-gate.json) -eq 1 \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/erasure-replica.txt; exit 1; }
	@echo "caught as expected: sweep/store-unswept naming postgres-replica-eu"
	@echo "--- 5. a case closed while a backup window is still open is caught ---"
	@if $(MAKE) erasure-gate ERASURE_CASE=examples/erasure/broken/case.closed-early.yaml TODAY=$(ANCHOR_TODAY) > build/erasure-closed-early.txt 2>&1; \
		then echo "FAIL: the closed-early case was not caught"; cat build/erasure-closed-early.txt; exit 1; \
		else grep -q 'case/closed-early' build/erasure-closed-early.txt \
			|| { echo "FAIL: the gate failed without the closed-early rule"; cat build/erasure-closed-early.txt; exit 1; }; \
		fi
	@test $$(jq '[.findings[] | select(.severity == "error")] | length' build/erasure-gate.json) -eq 1 \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/erasure-closed-early.txt; exit 1; }
	@echo "caught as expected: case/closed-early"
	@echo "--- 6. a tenant whose key the registry still holds live is caught ---"
	@if $(MAKE) erasure-gate ERASURE_CASE=examples/erasure/broken/case.dek-active.yaml TODAY=$(ANCHOR_TODAY) > build/erasure-dek-active.txt 2>&1; \
		then echo "FAIL: the live key was not caught"; cat build/erasure-dek-active.txt; exit 1; \
		else grep -q 'keys/dek-not-destroyed' build/erasure-dek-active.txt \
			|| { echo "FAIL: the gate failed without the live-key rule"; cat build/erasure-dek-active.txt; exit 1; }; \
		fi
	@test $$(jq '[.findings[] | select(.severity == "error")] | length' build/erasure-gate.json) -eq 1 \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/erasure-dek-active.txt; exit 1; }
	@echo "caught as expected: keys/dek-not-destroyed"
	@echo "--- 7. a sweep dated before the erasure request is caught ---"
	@if $(MAKE) erasure-gate ERASURE_CASE=examples/erasure/broken/case.sweep-before-request.yaml TODAY=$(ANCHOR_TODAY) > build/erasure-before-request.txt 2>&1; \
		then echo "FAIL: the backdated sweep was not caught"; cat build/erasure-before-request.txt; exit 1; \
		else grep -q 'sweep/before-request' build/erasure-before-request.txt \
			|| { echo "FAIL: the gate failed without the before-request rule"; cat build/erasure-before-request.txt; exit 1; }; \
		fi
	@test $$(jq '[.findings[] | select(.severity == "error")] | length' build/erasure-gate.json) -eq 1 \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/erasure-before-request.txt; exit 1; }
	@echo "caught as expected: sweep/before-request"
	@echo "--- 8. a case for a tenant the registry never listed is caught ---"
	@if $(MAKE) erasure-gate ERASURE_CASE=examples/erasure/broken/case.tenant-unregistered.yaml TODAY=$(ANCHOR_TODAY) > build/erasure-unregistered.txt 2>&1; \
		then echo "FAIL: the unregistered tenant was not caught"; cat build/erasure-unregistered.txt; exit 1; \
		else grep -q 'keys/tenant-unregistered' build/erasure-unregistered.txt \
			|| { echo "FAIL: the gate failed without the tenant-registry rule"; cat build/erasure-unregistered.txt; exit 1; }; \
		fi
	@test $$(jq '[.findings[] | select(.severity == "error")] | length' build/erasure-gate.json) -eq 1 \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/erasure-unregistered.txt; exit 1; }
	@echo "caught as expected: keys/tenant-unregistered"
	@echo "--- 9. a backup without its expiry window is caught ---"
	@if $(MAKE) erasure-gate ERASURE_CASE=examples/erasure/broken/case.backup-no-expiry.yaml TODAY=$(ANCHOR_TODAY) > build/erasure-no-expiry.txt 2>&1; \
		then echo "FAIL: the backup without its window was not caught"; cat build/erasure-no-expiry.txt; exit 1; \
		else grep -q 'store/backup-expiry-required' build/erasure-no-expiry.txt \
			|| { echo "FAIL: the gate failed without the backup-window rule"; cat build/erasure-no-expiry.txt; exit 1; }; \
		fi
	@test $$(jq '[.findings[] | select(.severity == "error")] | length' build/erasure-gate.json) -eq 1 \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/erasure-no-expiry.txt; exit 1; }
	@echo "caught as expected: store/backup-expiry-required"
	@echo "--- 10. a destroyed key without its evidence record is caught at registry time ---"
	@if $(MAKE) check-erasure ERASURE_KEYS=examples/erasure/broken/keys.no-evidence.yaml TODAY=$(ANCHOR_TODAY) > build/erasure-no-evidence.txt 2>&1; \
		then echo "FAIL: the destruction without evidence was not caught"; cat build/erasure-no-evidence.txt; exit 1; \
		else grep -q 'key/destroyed-by-required' build/erasure-no-evidence.txt \
			|| { echo "FAIL: the registry failed without the evidence rule"; cat build/erasure-no-evidence.txt; exit 1; }; \
		fi
	@test $$(jq '[.findings[] | select(.severity == "error")] | length' build/check-erasure.json) -eq 1 \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/erasure-no-evidence.txt; exit 1; }
	@echo "caught as expected: key/destroyed-by-required"
	@echo "--- erasure demo: all done-when proofs passed ---"

# Segment: validate the contract (segments, rules between declared
# segments, TTL-bound exceptions unexpired) alone.
check-segment:
	@test -f "$(CONTRACT)" || { echo "usage: make check-segment [CONTRACT=...] [TODAY=YYYY-MM-DD]"; exit 2; }
	@mkdir -p build
	yq -o=json '.' '$(CONTRACT)' \
		| jq -cs --arg today "$(TODAY)" '{contract: .[0], today: $$today}' \
		| $(OPA) eval -d policies -I 'data.segment.validate' --format=pretty | tee build/check-segment.json
	@jq -e '.valid == true' build/check-segment.json > /dev/null \
		|| { echo "check-segment: the segment contract is invalid — findings above"; exit 1; }

# Gate the rendered policies, the flow evidence, and the promotion PR
# against the segment contract: every rule present in every declared
# render, no render carrying a rule the contract never had, the
# modeled subset agreeing, the promotion citing evidence it holds —
# a rule is not enforced until every fabric says so. Fails (exit 1)
# when the gate finds errors; a dead rule is a review flag, not a
# failure, and the verdict says review.
segment-gate:
	@test -f "$(CONTRACT)" || { echo "usage: make segment-gate [CONTRACT=... RENDERS=... FLOWS=... PROMOTION=...] [TODAY=YYYY-MM-DD]"; exit 2; }
	@mkdir -p build
	yq -o=json '.' '$(CONTRACT)' '$(RENDERS)' '$(FLOWS)' '$(PROMOTION)' \
		| jq -cs --arg today "$(TODAY)" --arg contractFile "$(CONTRACT)" --arg rendersFile "$(RENDERS)" --arg flowsFile "$(FLOWS)" \
			'{contract: .[0], renders: .[1], flows: .[2], promotion: .[3], today: $$today, contractFile: $$contractFile, rendersFile: $$rendersFile, flowsFile: $$flowsFile}' \
		| $(OPA) eval -d policies -I 'data.segment.gate' --format=pretty | tee build/segment-gate.json
	@jq -e '.valid == true' build/segment-gate.json > /dev/null \
		|| { echo "segment-gate: the render-consistency gate found errors above"; exit 1; }

# The done-when proof for book issue #80: a render missing one fabric
# is caught citing both files. Runs the control end to end, then proves
# all the broken variants fail loudly (or flag honestly).
segment-demo:
	@echo "--- 1. the segment contract validates ---"
	@$(MAKE) check-segment TODAY=$(ANCHOR_TODAY)
	@echo "--- 2. the control passes the gate and renders consistent ---"
	@$(MAKE) segment-gate TODAY=$(ANCHOR_TODAY)
	@grep -q '"verdict": "consistent"' build/segment-gate.json \
		|| { echo "FAIL: the control gate did not render the consistent verdict"; cat build/segment-gate.json; exit 1; }
	@echo "control verdict: consistent — one contract, two fabrics, every rule rendered everywhere"
	@echo "--- 3. a rule missing from one render is caught citing BOTH files ---"
	@if $(MAKE) segment-gate RENDERS=examples/segment/broken/renders.missing-in-render.yaml TODAY=$(ANCHOR_TODAY) > build/segment-missing.txt 2>&1; \
		then echo "FAIL: the missing render was not caught"; cat build/segment-missing.txt; exit 1; \
		else grep -q 'render/rule-missing' build/segment-missing.txt \
			|| { echo "FAIL: the gate failed without the missing-render rule"; cat build/segment-missing.txt; exit 1; }; \
		fi
	@grep -q 'examples/segment/contract.yaml' build/segment-missing.txt \
		|| { echo "FAIL: the finding does not cite the contract file"; cat build/segment-missing.txt; exit 1; }
	@grep -q 'renders.missing-in-render.yaml' build/segment-missing.txt \
		|| { echo "FAIL: the finding does not cite the renders file"; cat build/segment-missing.txt; exit 1; }
	@test $$(jq '[.findings[] | select(.severity == "error")] | length' build/segment-gate.json) -eq 1 \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/segment-missing.txt; exit 1; }
	@echo "caught as expected: render/rule-missing citing the contract file and the renders file"
	@echo "--- 4. a render carrying a rule the contract never had is caught ---"
	@if $(MAKE) segment-gate RENDERS=examples/segment/broken/renders.not-in-contract.yaml TODAY=$(ANCHOR_TODAY) > build/segment-phantom.txt 2>&1; \
		then echo "FAIL: the phantom rule was not caught"; cat build/segment-phantom.txt; exit 1; \
		else grep -q 'render/rule-unknown' build/segment-phantom.txt \
			|| { echo "FAIL: the gate failed without the phantom-rule rule"; cat build/segment-phantom.txt; exit 1; }; \
		fi
	@grep -q "'R9'" build/segment-phantom.txt \
		|| { echo "FAIL: the finding does not name the phantom rule"; cat build/segment-phantom.txt; exit 1; }
	@test $$(jq '[.findings[] | select(.severity == "error")] | length' build/segment-gate.json) -eq 1 \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/segment-phantom.txt; exit 1; }
	@echo "caught as expected: render/rule-unknown naming R9"
	@echo "--- 5. a direction disagreement inside the modeled subset is caught ---"
	@if $(MAKE) segment-gate RENDERS=examples/segment/broken/renders.direction-mismatch.yaml TODAY=$(ANCHOR_TODAY) > build/segment-direction.txt 2>&1; \
		then echo "FAIL: the direction mismatch was not caught"; cat build/segment-direction.txt; exit 1; \
		else grep -q 'render/direction-mismatch' build/segment-direction.txt \
			|| { echo "FAIL: the gate failed without the direction rule"; cat build/segment-direction.txt; exit 1; }; \
		fi
	@test $$(jq '[.findings[] | select(.severity == "error")] | length' build/segment-gate.json) -eq 1 \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/segment-direction.txt; exit 1; }
	@echo "caught as expected: render/direction-mismatch"
	@echo "--- 6. a type disagreement inside the modeled subset is caught ---"
	@if $(MAKE) segment-gate RENDERS=examples/segment/broken/renders.type-mismatch.yaml TODAY=$(ANCHOR_TODAY) > build/segment-type.txt 2>&1; \
		then echo "FAIL: the type mismatch was not caught"; cat build/segment-type.txt; exit 1; \
		else grep -q 'render/type-mismatch' build/segment-type.txt \
			|| { echo "FAIL: the gate failed without the type rule"; cat build/segment-type.txt; exit 1; }; \
		fi
	@test $$(jq '[.findings[] | select(.severity == "error")] | length' build/segment-gate.json) -eq 1 \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/segment-type.txt; exit 1; }
	@echo "caught as expected: render/type-mismatch"
	@echo "--- 7. a promotion without flow evidence fails ---"
	@if $(MAKE) segment-gate PROMOTION=examples/segment/broken/promotion.no-evidence.yaml TODAY=$(ANCHOR_TODAY) > build/segment-no-evidence.txt 2>&1; \
		then echo "FAIL: the promotion without evidence passed"; cat build/segment-no-evidence.txt; exit 1; \
		else grep -q 'promotion/no-flow-evidence' build/segment-no-evidence.txt \
			|| { echo "FAIL: the gate failed without the evidence rule"; cat build/segment-no-evidence.txt; exit 1; }; \
		fi
	@grep -q "'R3'" build/segment-no-evidence.txt \
		|| { echo "FAIL: the finding does not name the promoted rule"; cat build/segment-no-evidence.txt; exit 1; }
	@test $$(jq '[.findings[] | select(.severity == "error")] | length' build/segment-gate.json) -eq 1 \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/segment-no-evidence.txt; exit 1; }
	@echo "caught as expected: promotion/no-flow-evidence naming R3 — promotion is evidence, not assertion"
	@echo "--- 8. a promotion claiming a window its evidence never covered is caught ---"
	@if $(MAKE) segment-gate PROMOTION=examples/segment/broken/promotion.window-outside-evidence.yaml TODAY=$(ANCHOR_TODAY) > build/segment-window.txt 2>&1; \
		then echo "FAIL: the outside-evidence promotion passed"; cat build/segment-window.txt; exit 1; \
		else grep -q 'promotion/window-outside-evidence' build/segment-window.txt \
			|| { echo "FAIL: the gate failed without the window rule"; cat build/segment-window.txt; exit 1; }; \
		fi
	@test $$(jq '[.findings[] | select(.severity == "error")] | length' build/segment-gate.json) -eq 1 \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/segment-window.txt; exit 1; }
	@echo "caught as expected: promotion/window-outside-evidence"
	@echo "--- 9. a rule nothing exercised is flagged for review, not failed ---"
	@$(MAKE) segment-gate FLOWS=examples/segment/broken/flows.dead-rule.yaml TODAY=$(ANCHOR_TODAY)
	@grep -q 'flows/dead-rule' build/segment-gate.json \
		|| { echo "FAIL: the dead rule was not flagged"; cat build/segment-gate.json; exit 1; }
	@grep -q '"verdict": "review"' build/segment-gate.json \
		|| { echo "FAIL: the dead rule did not render the review verdict"; cat build/segment-gate.json; exit 1; }
	@jq -e '.rules[] | select(.rule == "R2" and .verdict == "dead")' build/segment-gate.json > /dev/null \
		|| { echo "FAIL: the R2 card did not render dead"; cat build/segment-gate.json; exit 1; }
	@echo "flagged as expected: flows/dead-rule naming R2 — the verdict is review, the gate stays green"
	@echo "--- 10. a TTL-expired exception is caught at contract time ---"
	@if $(MAKE) check-segment CONTRACT=examples/segment/broken/contract.ttl-expired.yaml TODAY=$(ANCHOR_TODAY) > build/segment-ttl.txt 2>&1; \
		then echo "FAIL: the expired exception was not caught"; cat build/segment-ttl.txt; exit 1; \
		else grep -q 'exception/ttl-expired' build/segment-ttl.txt \
			|| { echo "FAIL: the contract failed without the TTL rule"; cat build/segment-ttl.txt; exit 1; }; \
		fi
	@test $$(jq '[.findings[] | select(.severity == "error")] | length' build/check-segment.json) -eq 1 \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/segment-ttl.txt; exit 1; }
	@echo "caught as expected: exception/ttl-expired"
	@echo "--- segment demo: all done-when proofs passed ---"

# Ingress: validate the posture case (the zone and the wildcards it
# must contain, the default-deny, the certificate rotation clocks,
# the SLOs with their pagers, the audit coverage) alone.
check-ingress:
	@test -f "$(INGRESS_CASE)" || { echo "usage: make check-ingress [INGRESS_CASE=...] [TODAY=YYYY-MM-DD]"; exit 2; }
	@mkdir -p build
	yq -o=json '.' '$(INGRESS_CASE)' \
		| jq -cs --arg today "$(TODAY)" --arg caseFile "$(INGRESS_CASE)" '{case: .[0], today: $$today, caseFile: $$caseFile}' \
		| $(OPA) eval -d policies -I 'data.ingress.validate' --format=pretty | tee build/check-ingress.json
	@jq -e '.valid == true' build/check-ingress.json > /dev/null \
		|| { echo "check-ingress: the posture case is invalid — findings above"; exit 1; }

# Gate the kill path against the drill record: the case's declared
# kill path rehearsed on the record, inside the staleness clock the
# record itself declares — a kill path never rehearsed is a promise
# the platform has never kept, and a rehearsal grown stale is a kill
# path that has drifted. Fails (exit 1) when the gate finds errors;
# a stale rehearsal is a review flag, not a failure, and the verdict
# says review.
ingress-gate:
	@test -f "$(INGRESS_CASE)" || { echo "usage: make ingress-gate [INGRESS_CASE=... INGRESS_DRILL=...] [TODAY=YYYY-MM-DD]"; exit 2; }
	@mkdir -p build
	yq -o=json '.' '$(INGRESS_CASE)' '$(INGRESS_DRILL)' \
		| jq -cs --arg today "$(TODAY)" --arg caseFile "$(INGRESS_CASE)" --arg drillFile "$(INGRESS_DRILL)" \
			'{case: .[0], drill: .[1], today: $$today, caseFile: $$caseFile, drillFile: $$drillFile}' \
		| $(OPA) eval -d policies -I 'data.ingress.gate' --format=pretty | tee build/ingress-gate.json
	@jq -e '.valid == true' build/ingress-gate.json > /dev/null \
		|| { echo "ingress-gate: the ingress posture gate found errors above"; exit 1; }

# The done-when proof for book issue #82: a kill path declared but
# never rehearsed is caught citing the drill record. Runs the
# control case and drill end to end, then proves all the broken
# variants fail loudly (or flag honestly).
ingress-demo:
	@echo "--- 1. the posture case validates ---"
	@$(MAKE) check-ingress TODAY=$(ANCHOR_TODAY)
	@echo "--- 2. the control passes the gate and renders hardened ---"
	@$(MAKE) ingress-gate TODAY=$(ANCHOR_TODAY)
	@grep -q '"verdict": "hardened"' build/ingress-gate.json \
		|| { echo "FAIL: the control gate did not render the hardened verdict"; cat build/ingress-gate.json; exit 1; }
	@jq -e '.cards | length == 10' build/ingress-gate.json > /dev/null \
		|| { echo "FAIL: the control did not render one card per judged item"; cat build/ingress-gate.json; exit 1; }
	@echo "control verdict: hardened — the whole board says so, one card per judged item"
	@echo "--- 3. a wildcard the zone cannot hold is caught ---"
	@if $(MAKE) check-ingress INGRESS_CASE=examples/ingress/broken/case.broad-wildcard.yaml TODAY=$(ANCHOR_TODAY) > build/ingress-broad.txt 2>&1; \
		then echo "FAIL: the broad wildcard was not caught"; cat build/ingress-broad.txt; exit 1; \
		else grep -q 'domain/too-broad' build/ingress-broad.txt \
			|| { echo "FAIL: the case failed without the too-broad rule"; cat build/ingress-broad.txt; exit 1; }; \
		fi
	@grep -q "outside the platform zone" build/ingress-broad.txt \
		|| { echo "FAIL: the finding does not name the zone it escaped"; cat build/ingress-broad.txt; exit 1; }
	@test $$(jq '[.findings[] | select(.severity == "error")] | length' build/check-ingress.json) -eq 1 \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/ingress-broad.txt; exit 1; }
	@echo "caught as expected: domain/too-broad — the wildcard escaped dev.internal"
	@echo "--- 4. a missing default-deny is caught ---"
	@if $(MAKE) check-ingress INGRESS_CASE=examples/ingress/broken/case.no-default-deny.yaml TODAY=$(ANCHOR_TODAY) > build/ingress-default-deny.txt 2>&1; \
		then echo "FAIL: the missing default-deny was not caught"; cat build/ingress-default-deny.txt; exit 1; \
		else grep -q 'requestpolicy/default-deny-required' build/ingress-default-deny.txt \
			|| { echo "FAIL: the case failed without the default-deny rule"; cat build/ingress-default-deny.txt; exit 1; }; \
		fi
	@test $$(jq '[.findings[] | select(.severity == "error")] | length' build/check-ingress.json) -eq 1 \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/ingress-default-deny.txt; exit 1; }
	@echo "caught as expected: requestpolicy/default-deny-required — an allow list without the default is not an allow list"
	@echo "--- 5. an expired certificate is caught naming the host ---"
	@if $(MAKE) check-ingress INGRESS_CASE=examples/ingress/broken/case.expired-cert.yaml TODAY=$(ANCHOR_TODAY) > build/ingress-expired.txt 2>&1; \
		then echo "FAIL: the expired certificate was not caught"; cat build/ingress-expired.txt; exit 1; \
		else grep -q 'cert/expired' build/ingress-expired.txt \
			|| { echo "FAIL: the case failed without the expired-cert rule"; cat build/ingress-expired.txt; exit 1; }; \
		fi
	@grep -q 'edge.dev.internal' build/ingress-expired.txt \
		|| { echo "FAIL: the finding does not name the host the cert served"; cat build/ingress-expired.txt; exit 1; }
	@test $$(jq '[.findings[] | select(.severity == "error")] | length' build/check-ingress.json) -eq 1 \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/ingress-expired.txt; exit 1; }
	@echo "caught as expected: cert/expired naming edge.dev.internal"
	@echo "--- 6. a certificate inside its rotation window flags honestly, not fatally ---"
	@$(MAKE) check-ingress INGRESS_CASE=examples/ingress/broken/case.near-expiry-cert.yaml TODAY=$(ANCHOR_TODAY)
	@grep -q 'cert/near-expiry' build/check-ingress.json \
		|| { echo "FAIL: the late rotation was not flagged"; cat build/check-ingress.json; exit 1; }
	@test $$(jq '[.findings[] | select(.severity == "warning")] | length' build/check-ingress.json) -eq 1 \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/check-ingress.json; exit 1; }
	@jq -e '.valid == true' build/check-ingress.json > /dev/null \
		|| { echo "FAIL: a warning must not fail the case"; cat build/check-ingress.json; exit 1; }
	@echo "flagged as expected: cert/near-expiry — the case stays valid, the rotation is late"
	@echo "--- 7. an SLO without its pager is caught ---"
	@if $(MAKE) check-ingress INGRESS_CASE=examples/ingress/broken/case.slo-no-pager.yaml TODAY=$(ANCHOR_TODAY) > build/ingress-pager.txt 2>&1; \
		then echo "FAIL: the pagerless SLO was not caught"; cat build/ingress-pager.txt; exit 1; \
		else grep -q 'slo/pager-required' build/ingress-pager.txt \
			|| { echo "FAIL: the case failed without the pager rule"; cat build/ingress-pager.txt; exit 1; }; \
		fi
	@test $$(jq '[.findings[] | select(.severity == "error")] | length' build/check-ingress.json) -eq 1 \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/ingress-pager.txt; exit 1; }
	@echo "caught as expected: slo/pager-required — an SLO nobody pages is a promise nobody keeps"
	@echo "--- 8. an unlogged route class is caught naming the class ---"
	@if $(MAKE) check-ingress INGRESS_CASE=examples/ingress/broken/case.audit-gap.yaml TODAY=$(ANCHOR_TODAY) > build/ingress-gap.txt 2>&1; \
		then echo "FAIL: the audit gap was not caught"; cat build/ingress-gap.txt; exit 1; \
		else grep -q 'audit/class-unlogged' build/ingress-gap.txt \
			|| { echo "FAIL: the case failed without the audit-coverage rule"; cat build/ingress-gap.txt; exit 1; }; \
		fi
	@grep -q 'partner-api' build/ingress-gap.txt \
		|| { echo "FAIL: the finding does not name the unlogged class"; cat build/ingress-gap.txt; exit 1; }
	@test $$(jq '[.findings[] | select(.severity == "error")] | length' build/check-ingress.json) -eq 1 \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/ingress-gap.txt; exit 1; }
	@echo "caught as expected: audit/class-unlogged naming partner-api"
	@echo "--- 9. a kill path never rehearsed is caught citing the drill record ---"
	@if $(MAKE) ingress-gate INGRESS_DRILL=examples/ingress/broken/drill.never-rehearsed.yaml TODAY=$(ANCHOR_TODAY) > build/ingress-never.txt 2>&1; \
		then echo "FAIL: the unrehearsed kill path was not caught"; cat build/ingress-never.txt; exit 1; \
		else grep -q 'killpath/never-rehearsed' build/ingress-never.txt \
			|| { echo "FAIL: the gate failed without the rehearsal rule"; cat build/ingress-never.txt; exit 1; }; \
		fi
	@grep -q 'drill.never-rehearsed.yaml' build/ingress-never.txt \
		|| { echo "FAIL: the finding does not cite the drill record"; cat build/ingress-never.txt; exit 1; }
	@test $$(jq '[.findings[] | select(.severity == "error")] | length' build/ingress-gate.json) -eq 1 \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/ingress-never.txt; exit 1; }
	@echo "caught as expected: killpath/never-rehearsed citing drill.never-rehearsed.yaml"
	@echo "--- 10. a rehearsal grown stale flags for review, not failure ---"
	@$(MAKE) ingress-gate INGRESS_DRILL=examples/ingress/broken/drill.stale-rehearsal.yaml TODAY=$(ANCHOR_TODAY)
	@grep -q 'killpath/stale-rehearsal' build/ingress-gate.json \
		|| { echo "FAIL: the stale rehearsal was not flagged"; cat build/ingress-gate.json; exit 1; }
	@grep -q '"verdict": "review"' build/ingress-gate.json \
		|| { echo "FAIL: the stale rehearsal did not render the review verdict"; cat build/ingress-gate.json; exit 1; }
	@jq -e '.cards[] | select(.area == "kill path" and .verdict == "review")' build/ingress-gate.json > /dev/null \
		|| { echo "FAIL: the kill-path card did not render review"; cat build/ingress-gate.json; exit 1; }
	@echo "flagged as expected: killpath/stale-rehearsal — the verdict is review, the gate stays green"
	@echo "--- ingress demo: all done-when proofs passed ---"

# Validate the citizen app manifest alone: components with their
# behaviors, data bindings with names, modes, and rails, actions
# used, guardrails with versions — the citizen-built app as data,
# its own stamps and shapes honest before any join runs.
check-citizen:
	@test -f "$(CITIZEN_MANIFEST)" || { echo "usage: make check-citizen [CITIZEN_MANIFEST=...] [TODAY=YYYY-MM-DD]"; exit 2; }
	@mkdir -p build
	yq -o=json '.' '$(CITIZEN_MANIFEST)' \
		| jq -cs --arg today "$(TODAY)" --arg manifestFile "$(CITIZEN_MANIFEST)" '{manifest: .[0], today: $$today, manifestFile: $$manifestFile}' \
		| $(OPA) eval -d policies -I 'data.citizen.validate' --format=pretty | tee build/check-citizen.json
	@jq -e '.valid == true' build/check-citizen.json > /dev/null \
		|| { echo "check-citizen: the app manifest is invalid — findings above"; exit 1; }

# Gate the citizen app against its spec and the platform guardrail
# registry — advisor, not blocker: an escape hatch, an action
# outside the spec's rails, a behavior without spec coverage, and a
# guardrail below the platform floor are advisories that keep this
# gate green with the advice on the record. Fails (exit 1) only
# when a document is unreadable — the one red the advisor can show.
citizen-gate:
	@test -f "$(CITIZEN_MANIFEST)" || { echo "usage: make citizen-gate [CITIZEN_MANIFEST=... CITIZEN_SPEC=... CITIZEN_REGISTRY=...] [TODAY=YYYY-MM-DD]"; exit 2; }
	@mkdir -p build
	yq -o=json '.' '$(CITIZEN_MANIFEST)' '$(CITIZEN_SPEC)' '$(CITIZEN_REGISTRY)' \
		| jq -cs --arg today "$(TODAY)" --arg manifestFile "$(CITIZEN_MANIFEST)" --arg specFile "$(CITIZEN_SPEC)" --arg registryFile "$(CITIZEN_REGISTRY)" \
			'{manifest: .[0], spec: .[1], registry: .[2], today: $$today, manifestFile: $$manifestFile, specFile: $$specFile, registryFile: $$registryFile}' \
		| $(OPA) eval -d policies -I 'data.citizen.gate' --format=pretty | tee build/citizen-gate.json
	@jq -e '.valid == true' build/citizen-gate.json > /dev/null \
		|| { echo "citizen-gate: a document the advisor cannot read — findings above"; exit 1; }

# The done-when proof for book issue #84: the citizen spec-rails
# linter advises at the citizen's PR gate. Runs the control app end
# to end, then proves every drift variant bites exactly once — as an
# advisory, with the gate staying green — and that a manifest the
# advisor cannot read fails honestly.
citizen-demo:
	@echo "--- 1. the app manifest validates ---"
	@$(MAKE) check-citizen TODAY=$(ANCHOR_TODAY)
	@echo "--- 2. the control passes the gate and renders aligned ---"
	@$(MAKE) citizen-gate TODAY=$(ANCHOR_TODAY)
	@grep -q '"verdict": "aligned"' build/citizen-gate.json \
		|| { echo "FAIL: the control gate did not render the aligned verdict"; cat build/citizen-gate.json; exit 1; }
	@jq -e '.cards | length == 8' build/citizen-gate.json > /dev/null \
		|| { echo "FAIL: the control did not render one card per judged item"; cat build/citizen-gate.json; exit 1; }
	@echo "control verdict: aligned — the whole board says so, one card per judged item"
	@echo "--- 3. an escape hatch is caught advising ---"
	@$(MAKE) citizen-gate CITIZEN_MANIFEST=examples/citizen/broken/manifest.escape-hatch.yaml TODAY=$(ANCHOR_TODAY)
	@grep -q 'binding/escape-hatch' build/citizen-gate.json \
		|| { echo "FAIL: the escape hatch was not advised"; cat build/citizen-gate.json; exit 1; }
	@test $$(jq '[.findings[] | select(.severity == "advisory")] | length' build/citizen-gate.json) -eq 1 \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/citizen-gate.json; exit 1; }
	@grep -q '"verdict": "advises changes"' build/citizen-gate.json \
		|| { echo "FAIL: the gate did not render the advises-changes verdict"; cat build/citizen-gate.json; exit 1; }
	@jq -e '.valid == true' build/citizen-gate.json > /dev/null \
		|| { echo "FAIL: an advisory must not fail the gate"; cat build/citizen-gate.json; exit 1; }
	@jq -e '.cards[] | select(.area == "data bindings" and .verdict == "advises")' build/citizen-gate.json > /dev/null \
		|| { echo "FAIL: the binding card did not render advises"; cat build/citizen-gate.json; exit 1; }
	@echo "advised as expected: binding/escape-hatch — the gate stays green, the advice is on the record"
	@echo "--- 4. an action outside the spec's rails is caught advising ---"
	@$(MAKE) citizen-gate CITIZEN_MANIFEST=examples/citizen/broken/manifest.unspecced-action.yaml TODAY=$(ANCHOR_TODAY)
	@grep -q 'action/outside-rails' build/citizen-gate.json \
		|| { echo "FAIL: the unspecced action was not advised"; cat build/citizen-gate.json; exit 1; }
	@test $$(jq '[.findings[] | select(.severity == "advisory")] | length' build/citizen-gate.json) -eq 1 \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/citizen-gate.json; exit 1; }
	@grep -q '"verdict": "advises changes"' build/citizen-gate.json \
		|| { echo "FAIL: the gate did not render the advises-changes verdict"; cat build/citizen-gate.json; exit 1; }
	@jq -e '.valid == true' build/citizen-gate.json > /dev/null \
		|| { echo "FAIL: an advisory must not fail the gate"; cat build/citizen-gate.json; exit 1; }
	@echo "advised as expected: action/outside-rails — the gate stays green, the advice is on the record"
	@echo "--- 5. a behavior without spec coverage is caught advising ---"
	@$(MAKE) citizen-gate CITIZEN_MANIFEST=examples/citizen/broken/manifest.uncovered-behavior.yaml TODAY=$(ANCHOR_TODAY)
	@grep -q 'behavior/uncovered-by-spec' build/citizen-gate.json \
		|| { echo "FAIL: the uncovered behavior was not advised"; cat build/citizen-gate.json; exit 1; }
	@test $$(jq '[.findings[] | select(.severity == "advisory")] | length' build/citizen-gate.json) -eq 1 \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/citizen-gate.json; exit 1; }
	@grep -q '"verdict": "advises changes"' build/citizen-gate.json \
		|| { echo "FAIL: the gate did not render the advises-changes verdict"; cat build/citizen-gate.json; exit 1; }
	@jq -e '.valid == true' build/citizen-gate.json > /dev/null \
		|| { echo "FAIL: an advisory must not fail the gate"; cat build/citizen-gate.json; exit 1; }
	@jq -e '.cards[] | select(.area == "spec coverage" and .verdict == "advises")' build/citizen-gate.json > /dev/null \
		|| { echo "FAIL: the coverage card did not render advises"; cat build/citizen-gate.json; exit 1; }
	@echo "advised as expected: behavior/uncovered-by-spec — the gate stays green, the advice is on the record"
	@echo "--- 6. a guardrail below the platform floor is caught advising ---"
	@$(MAKE) citizen-gate CITIZEN_MANIFEST=examples/citizen/broken/manifest.stale-guardrail.yaml TODAY=$(ANCHOR_TODAY)
	@grep -q 'guardrail/below-floor' build/citizen-gate.json \
		|| { echo "FAIL: the below-floor guardrail was not advised"; cat build/citizen-gate.json; exit 1; }
	@test $$(jq '[.findings[] | select(.severity == "advisory")] | length' build/citizen-gate.json) -eq 1 \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/citizen-gate.json; exit 1; }
	@grep -q '"verdict": "advises changes"' build/citizen-gate.json \
		|| { echo "FAIL: the gate did not render the advises-changes verdict"; cat build/citizen-gate.json; exit 1; }
	@jq -e '.valid == true' build/citizen-gate.json > /dev/null \
		|| { echo "FAIL: an advisory must not fail the gate"; cat build/citizen-gate.json; exit 1; }
	@jq -e '.cards[] | select(.area == "guardrails" and .verdict == "advises")' build/citizen-gate.json > /dev/null \
		|| { echo "FAIL: the guardrail card did not render advises"; cat build/citizen-gate.json; exit 1; }
	@echo "advised as expected: guardrail/below-floor — the gate stays green, the advice is on the record"
	@echo "--- 7. a manifest the advisor cannot read fails honestly ---"
	@if $(MAKE) citizen-gate CITIZEN_MANIFEST=examples/citizen/broken/manifest.no-version.yaml TODAY=$(ANCHOR_TODAY) > build/citizen-no-version.txt 2>&1; \
		then echo "FAIL: the unreadable manifest passed the gate"; cat build/citizen-no-version.txt; exit 1; \
		else grep -q 'manifest/version-required' build/citizen-no-version.txt \
			|| { echo "FAIL: the gate failed without the version rule"; cat build/citizen-no-version.txt; exit 1; }; \
		fi
	@grep -q '"verdict": "unreadable"' build/citizen-gate.json \
		|| { echo "FAIL: the gate did not render the unreadable verdict"; cat build/citizen-gate.json; exit 1; }
	@echo "caught as expected: manifest/version-required — the advisor refuses to answer on a document it cannot read"
	@echo "--- citizen demo: all done-when proofs passed ---"

# Validate the component package manifest alone: the component-package
# chapter's package-as-data — its name, version, and tier, the artifact
# digest it publishes, the signature and attestation recorded over that
# digest, its provenance, and the dependencies it pins by digest.
# Conformance gate, not advisor: any finding fails.
check-component:
	@test -f "$(COMPONENT_PACKAGE)" || { echo "usage: make check-component [COMPONENT_PACKAGE=...] [TODAY=YYYY-MM-DD]"; exit 2; }
	@mkdir -p build
	yq -o=json '.' '$(COMPONENT_PACKAGE)' \
		| jq -cs --arg today "$(TODAY)" --arg packageFile "$(COMPONENT_PACKAGE)" '{package: .[0], today: $$today, packageFile: $$packageFile}' \
		| $(OPA) eval -d policies -I 'data.component.validate' --format=pretty | tee build/check-component.json
	@jq -e '.valid == true' build/check-component.json > /dev/null \
		|| { echo "check-component: the package manifest is not in conformance — findings above"; exit 1; }

# Gate the component package against the component registry — the
# estate's admitted packages, each as a component, version, tier, and
# digest row. Conformance gate, not advisor: an unregistered package,
# an artifact drifted from its registration, an unresolved
# dependency, a stale pin, and a customer-tier package depending
# downward are all refused, not advised.
component-gate:
	@test -f "$(COMPONENT_PACKAGE)" || { echo "usage: make component-gate [COMPONENT_PACKAGE=... COMPONENT_REGISTRY=...] [TODAY=YYYY-MM-DD]"; exit 2; }
	@mkdir -p build
	yq -o=json '.' '$(COMPONENT_PACKAGE)' '$(COMPONENT_REGISTRY)' \
		| jq -cs --arg today "$(TODAY)" --arg packageFile "$(COMPONENT_PACKAGE)" --arg registryFile "$(COMPONENT_REGISTRY)" \
			'{package: .[0], registry: .[1], today: $$today, packageFile: $$packageFile, registryFile: $$registryFile}' \
		| $(OPA) eval -d policies -I 'data.component.gate' --format=pretty | tee build/component-gate.json
	@jq -e '.valid == true' build/component-gate.json > /dev/null \
		|| { echo "component-gate: the package is not in conformance — findings above"; exit 1; }

# The done-when proof for book issue #101: the component package
# conformance gate refuses. Runs the control package end to end,
# then proves every drift variant bites exactly once — three at
# validation, three at the join — and that each bite names the rule
# and renders its verdict honestly.
component-demo:
	@echo "--- 1. the package manifest validates ---"
	@$(MAKE) check-component TODAY=$(ANCHOR_TODAY)
	@echo "--- 2. the control passes the gate and renders consistent ---"
	@$(MAKE) component-gate TODAY=$(ANCHOR_TODAY)
	@grep -q '"verdict": "consistent"' build/component-gate.json \
		|| { echo "FAIL: the control gate did not render the consistent verdict"; cat build/component-gate.json; exit 1; }
	@jq -e '.cards | length == 2' build/component-gate.json > /dev/null \
		|| { echo "FAIL: the control did not render one card per judged item"; cat build/component-gate.json; exit 1; }
	@echo "control verdict: consistent — the whole board says so, one card per judged item"
	@echo "--- 3. an unsigned artifact is caught at validation ---"
	@if $(MAKE) check-component COMPONENT_PACKAGE=examples/component/broken/package.no-signature.yaml TODAY=$(ANCHOR_TODAY) > build/component-no-signature.txt 2>&1; \
		then echo "FAIL: the unsigned artifact passed validation"; cat build/component-no-signature.txt; exit 1; \
		else grep -q 'signature/required' build/component-no-signature.txt \
			|| { echo "FAIL: the gate failed without the signature rule"; cat build/component-no-signature.txt; exit 1; }; \
		fi
	@echo "caught as expected: signature/required — an unsigned artifact is an artifact nobody vouches for"
	@echo "--- 4. an inconsistent signature is caught at validation ---"
	@if $(MAKE) check-component COMPONENT_PACKAGE=examples/component/broken/package.wrong-signed-digest.yaml TODAY=$(ANCHOR_TODAY) > build/component-wrong-digest.txt 2>&1; \
		then echo "FAIL: the mismatched signature passed validation"; cat build/component-wrong-digest.txt; exit 1; \
		else grep -q 'signature/digest-mismatch' build/component-wrong-digest.txt \
			|| { echo "FAIL: the gate failed without the mismatch rule"; cat build/component-wrong-digest.txt; exit 1; }; \
		fi
	@echo "caught as expected: signature/digest-mismatch — the recorded evidence is not even internally consistent"
	@echo "--- 5. a general-tier package with a dependency is caught at validation ---"
	@if $(MAKE) check-component COMPONENT_PACKAGE=examples/component/broken/package.general-with-dependency.yaml TODAY=$(ANCHOR_TODAY) > build/component-general.txt 2>&1; \
		then echo "FAIL: the general-tier dependency passed validation"; cat build/component-general.txt; exit 1; \
		else grep -q 'dependency/general-forbidden' build/component-general.txt \
			|| { echo "FAIL: the gate failed without the general-tier rule"; cat build/component-general.txt; exit 1; }; \
		fi
	@echo "caught as expected: dependency/general-forbidden — the baseline everything else builds on depends on nothing"
	@echo "--- 6. a stale pin is caught at the join ---"
	@if $(MAKE) component-gate COMPONENT_PACKAGE=examples/component/broken/package.stale-pin.yaml TODAY=$(ANCHOR_TODAY) > build/component-stale-pin.txt 2>&1; \
		then echo "FAIL: the stale pin passed the gate"; cat build/component-stale-pin.txt; exit 1; \
		else grep -q 'gate/dependency-digest-mismatch' build/component-stale-pin.txt \
			|| { echo "FAIL: the gate failed without the stale-pin rule"; cat build/component-stale-pin.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 1' build/component-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/component-gate.json; exit 1; }
	@grep -q '"verdict": "drifts"' build/component-gate.json \
		|| { echo "FAIL: the gate did not render the drifts verdict"; cat build/component-gate.json; exit 1; }
	@echo "caught as expected: gate/dependency-digest-mismatch — a pin to something the estate never admitted"
	@echo "--- 7. a downward tier is caught at the join ---"
	@if $(MAKE) component-gate COMPONENT_PACKAGE=examples/component/broken/package.customer-on-project.yaml TODAY=$(ANCHOR_TODAY) > build/component-downward.txt 2>&1; \
		then echo "FAIL: the downward tier passed the gate"; cat build/component-downward.txt; exit 1; \
		else grep -q 'gate/dependency-hierarchy-violation' build/component-downward.txt \
			|| { echo "FAIL: the gate failed without the hierarchy rule"; cat build/component-downward.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 1' build/component-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/component-gate.json; exit 1; }
	@grep -q '"verdict": "drifts"' build/component-gate.json \
		|| { echo "FAIL: the gate did not render the drifts verdict"; cat build/component-gate.json; exit 1; }
	@echo "caught as expected: gate/dependency-hierarchy-violation — the tiers are one-way, and this dependency points down"
	@echo "--- 8. an unregistered package is caught at the join ---"
	@if $(MAKE) component-gate COMPONENT_REGISTRY=examples/component/broken/registry.missing-package.yaml TODAY=$(ANCHOR_TODAY) > build/component-unregistered.txt 2>&1; \
		then echo "FAIL: the unregistered package passed the gate"; cat build/component-unregistered.txt; exit 1; \
		else grep -q 'gate/package-unregistered' build/component-unregistered.txt \
			|| { echo "FAIL: the gate failed without the registration rule"; cat build/component-unregistered.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 1' build/component-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/component-gate.json; exit 1; }
	@grep -q '"verdict": "drifts"' build/component-gate.json \
		|| { echo "FAIL: the gate did not render the drifts verdict"; cat build/component-gate.json; exit 1; }
	@echo "caught as expected: gate/package-unregistered — a package the estate never admitted is a package the estate never vouched for"
	@echo "--- component demo: all done-when proofs passed ---"

# Validate the render matrix alone: one component package's rendered
# copies, fabric by fabric — the fabrics it must cover, and each
# fabric's version, pinned digest, and the policy bindings in force.
# Conformance gate, not advisor: any finding fails.
check-matrix:
	@test -f "$(MATRIX)" || { echo "usage: make check-matrix [MATRIX=...] [TODAY=YYYY-MM-DD]"; exit 2; }
	@mkdir -p build
	yq -o=json '.' '$(MATRIX)' \
		| jq -cs --arg today "$(TODAY)" --arg matrixFile "$(MATRIX)" '{matrix: .[0], today: $$today, matrixFile: $$matrixFile}' \
		| $(OPA) eval -d policies -I 'data.matrix.validate' --format=pretty | tee build/check-matrix.json
	@jq -e '.valid == true' build/check-matrix.json > /dev/null \
		|| { echo "check-matrix: the render matrix is not in conformance — findings above"; exit 1; }

# Gate every fabric's render against the component package manifest —
# the same version, the same pinned digest, and the same policy
# bindings, on every declared fabric. Conformance gate, not advisor:
# a render for another component, a fabric with no render, a version
# or digest disagreement, and a binding disagreement in either
# direction are all refused, not advised.
matrix-gate:
	@test -f "$(COMPONENT_PACKAGE)" || { echo "usage: make matrix-gate [COMPONENT_PACKAGE=... MATRIX=...] [TODAY=YYYY-MM-DD]"; exit 2; }
	@mkdir -p build
	yq -o=json '.' '$(COMPONENT_PACKAGE)' '$(MATRIX)' \
		| jq -cs --arg today "$(TODAY)" --arg packageFile "$(COMPONENT_PACKAGE)" --arg matrixFile "$(MATRIX)" \
			'{package: .[0], matrix: .[1], today: $$today, packageFile: $$packageFile, matrixFile: $$matrixFile}' \
		| $(OPA) eval -d policies -I 'data.matrix.gate' --format=pretty | tee build/matrix-gate.json
	@jq -e '.valid == true' build/matrix-gate.json > /dev/null \
		|| { echo "matrix-gate: the fabric renders are not in conformance — findings above"; exit 1; }

# The done-when proof for book issue #102: the render-matrix
# conformance gate refuses. Runs the control matrix end to end,
# then proves every drift variant bites with its named rule — six
# at the join, one at validation, one at the fabric list — and
# that each bite renders its verdict honestly.
matrix-demo:
	@echo "--- 1. the render matrix validates ---"
	@$(MAKE) check-matrix TODAY=$(ANCHOR_TODAY)
	@echo "--- 2. the control passes the gate and renders consistent ---"
	@$(MAKE) matrix-gate TODAY=$(ANCHOR_TODAY)
	@grep -q '"verdict": "consistent"' build/matrix-gate.json \
		|| { echo "FAIL: the control gate did not render the consistent verdict"; cat build/matrix-gate.json; exit 1; }
	@jq -e '.fabrics | length == 3' build/matrix-gate.json > /dev/null \
		|| { echo "FAIL: the control did not render one card per declared fabric"; cat build/matrix-gate.json; exit 1; }
	@echo "control verdict: consistent — the whole board says so, one card per declared fabric"
	@echo "--- 3. a fabric on another release is caught at the join ---"
	@if $(MAKE) matrix-gate MATRIX=examples/matrix/broken/matrix.version-skew.yaml TODAY=$(ANCHOR_TODAY) > build/matrix-version-skew.txt 2>&1; \
		then echo "FAIL: the version skew passed the gate"; cat build/matrix-version-skew.txt; exit 1; \
		else grep -q 'gate/render-version-skew' build/matrix-version-skew.txt \
			|| { echo "FAIL: the gate failed without the version rule"; cat build/matrix-version-skew.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 1' build/matrix-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/matrix-gate.json; exit 1; }
	@grep -q '"verdict": "drifts"' build/matrix-gate.json \
		|| { echo "FAIL: the gate did not render the drifts verdict"; cat build/matrix-gate.json; exit 1; }
	@echo "caught as expected: gate/render-version-skew — one fabric quietly running a different release"
	@echo "--- 4. a re-render that swapped the artifact is caught at the join ---"
	@if $(MAKE) matrix-gate MATRIX=examples/matrix/broken/matrix.digest-drift.yaml TODAY=$(ANCHOR_TODAY) > build/matrix-digest-drift.txt 2>&1; \
		then echo "FAIL: the digest drift passed the gate"; cat build/matrix-digest-drift.txt; exit 1; \
		else grep -q 'gate/render-digest-drift' build/matrix-digest-drift.txt \
			|| { echo "FAIL: the gate failed without the digest rule"; cat build/matrix-digest-drift.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 1' build/matrix-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/matrix-gate.json; exit 1; }
	@grep -q '"verdict": "drifts"' build/matrix-gate.json \
		|| { echo "FAIL: the gate did not render the drifts verdict"; cat build/matrix-gate.json; exit 1; }
	@echo "caught as expected: gate/render-digest-drift — a digest the package never published"
	@echo "--- 5. a declared binding two fabrics never ran is caught at the join ---"
	@if $(MAKE) matrix-gate MATRIX=examples/matrix/broken/matrix.binding-one-fabric.yaml TODAY=$(ANCHOR_TODAY) > build/matrix-binding-one.txt 2>&1; \
		then echo "FAIL: the missing bindings passed the gate"; cat build/matrix-binding-one.txt; exit 1; \
		else grep -q 'gate/binding-missing' build/matrix-binding-one.txt \
			|| { echo "FAIL: the gate failed without the binding rule"; cat build/matrix-binding-one.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 2' build/matrix-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite once per fabric that never ran the policy"; cat build/matrix-gate.json; exit 1; }
	@grep -q '"verdict": "drifts"' build/matrix-gate.json \
		|| { echo "FAIL: the gate did not render the drifts verdict"; cat build/matrix-gate.json; exit 1; }
	@echo "caught as expected: gate/binding-missing × 2 — a policy the package shipped that two fabrics never ran"
	@echo "--- 6. a binding the package never declared is caught at the join ---"
	@if $(MAKE) matrix-gate MATRIX=examples/matrix/broken/matrix.extra-binding.yaml TODAY=$(ANCHOR_TODAY) > build/matrix-extra-binding.txt 2>&1; \
		then echo "FAIL: the undeclared binding passed the gate"; cat build/matrix-extra-binding.txt; exit 1; \
		else grep -q 'gate/binding-undeclared' build/matrix-extra-binding.txt \
			|| { echo "FAIL: the gate failed without the undeclared-binding rule"; cat build/matrix-extra-binding.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 1' build/matrix-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/matrix-gate.json; exit 1; }
	@grep -q '"verdict": "drifts"' build/matrix-gate.json \
		|| { echo "FAIL: the gate did not render the drifts verdict"; cat build/matrix-gate.json; exit 1; }
	@echo "caught as expected: gate/binding-undeclared — a policy in force the package never shipped"
	@echo "--- 7. a fabric with no render at all is caught at the join ---"
	@if $(MAKE) matrix-gate MATRIX=examples/matrix/broken/matrix.fabric-unrendered.yaml TODAY=$(ANCHOR_TODAY) > build/matrix-unrendered.txt 2>&1; \
		then echo "FAIL: the unrendered fabric passed the gate"; cat build/matrix-unrendered.txt; exit 1; \
		else grep -q 'gate/fabric-unrendered' build/matrix-unrendered.txt \
			|| { echo "FAIL: the gate failed without the coverage rule"; cat build/matrix-unrendered.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 1' build/matrix-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/matrix-gate.json; exit 1; }
	@grep -q '"verdict": "drifts"' build/matrix-gate.json \
		|| { echo "FAIL: the gate did not render the drifts verdict"; cat build/matrix-gate.json; exit 1; }
	@echo "caught as expected: gate/fabric-unrendered — coverage claimed and never delivered"
	@echo "--- 8. a matrix for another component is caught at the join ---"
	@if $(MAKE) matrix-gate MATRIX=examples/matrix/broken/matrix.wrong-component.yaml TODAY=$(ANCHOR_TODAY) > build/matrix-wrong-component.txt 2>&1; \
		then echo "FAIL: the other component passed the gate"; cat build/matrix-wrong-component.txt; exit 1; \
		else grep -q 'gate/component-mismatch' build/matrix-wrong-component.txt \
			|| { echo "FAIL: the gate failed without the component rule"; cat build/matrix-wrong-component.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 1' build/matrix-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/matrix-gate.json; exit 1; }
	@grep -q '"verdict": "drifts"' build/matrix-gate.json \
		|| { echo "FAIL: the gate did not render the drifts verdict"; cat build/matrix-gate.json; exit 1; }
	@echo "caught as expected: gate/component-mismatch — renders judged against somebody else's package"
	@echo "--- 9. a matrix nobody re-reads is caught at validation, and the gate refuses to answer ---"
	@if $(MAKE) check-matrix MATRIX=examples/matrix/broken/matrix.stale-review.yaml TODAY=$(ANCHOR_TODAY) > build/matrix-stale-review.txt 2>&1; \
		then echo "FAIL: the stale review passed validation"; cat build/matrix-stale-review.txt; exit 1; \
		else grep -q 'matrix/reviewed-stale' build/matrix-stale-review.txt \
			|| { echo "FAIL: the validator failed without the staleness rule"; cat build/matrix-stale-review.txt; exit 1; }; \
		fi
	@if $(MAKE) matrix-gate MATRIX=examples/matrix/broken/matrix.stale-review.yaml TODAY=$(ANCHOR_TODAY) > build/matrix-stale-gate.txt 2>&1; \
		then echo "FAIL: the stale review passed the gate"; cat build/matrix-stale-gate.txt; exit 1; \
		else grep -q '"verdict": "unreadable"' build/matrix-stale-gate.txt \
			|| { echo "FAIL: the gate did not render the unreadable verdict"; cat build/matrix-stale-gate.txt; exit 1; }; \
		fi
	@echo "caught as expected: matrix/reviewed-stale, verdict unreadable — a question the gate refuses to answer on stale inputs"
	@echo "--- 10. a render on a fabric the matrix never declared is caught at validation ---"
	@if $(MAKE) check-matrix MATRIX=examples/matrix/broken/matrix.undeclared-fabric.yaml TODAY=$(ANCHOR_TODAY) > build/matrix-undeclared-fabric.txt 2>&1; \
		then echo "FAIL: the undeclared fabric passed validation"; cat build/matrix-undeclared-fabric.txt; exit 1; \
		else grep -q 'render/fabric-undeclared' build/matrix-undeclared-fabric.txt \
			|| { echo "FAIL: the validator failed without the declared-fabric rule"; cat build/matrix-undeclared-fabric.txt; exit 1; }; \
		fi
	@if $(MAKE) matrix-gate MATRIX=examples/matrix/broken/matrix.undeclared-fabric.yaml TODAY=$(ANCHOR_TODAY) > build/matrix-undeclared-gate.txt 2>&1; \
		then echo "FAIL: the undeclared fabric passed the gate"; cat build/matrix-undeclared-gate.txt; exit 1; \
		else grep -q '"verdict": "unreadable"' build/matrix-undeclared-gate.txt \
			|| { echo "FAIL: the gate did not render the unreadable verdict"; cat build/matrix-undeclared-gate.txt; exit 1; }; \
		fi
	@echo "caught as expected: render/fabric-undeclared, verdict unreadable — the fabric list and the render rows disagree"
	@echo "--- matrix demo: all done-when proofs passed ---"

# Validate the broker grant document alone — the declared consumer
# identities and the grants the broker issued, each naming one
# principal, one component pinned by sha256 digest, an exact action
# set (the wildcard and the metacharacter are refused), and an
# expiry that is still in the future.
check-broker:
	@test -f "$(BROKER_GRANTS)" || { echo "usage: make check-broker [BROKER_GRANTS=...] [TODAY=YYYY-MM-DD]"; exit 2; }
	@mkdir -p build
	yq -o=json '.' '$(BROKER_GRANTS)' \
		| jq -cs --arg today "$(TODAY)" --arg brokerFile "$(BROKER_GRANTS)" '{broker: .[0], today: $$today, brokerFile: $$brokerFile}' \
		| $(OPA) eval -d policies -I 'data.broker.validate' --format=pretty | tee build/check-broker.json
	@jq -e '.valid == true' build/check-broker.json > /dev/null \
		|| { echo "check-broker: the broker grant document is not in conformance — findings above"; exit 1; }

# Gate the broker's grants against the component package manifest —
# every grant resolved by the manifest at exactly its pinned digest,
# for a declared principal, with the clock still on it. Conformance
# gate, not advisor: a grant for a component nobody packaged, a
# grant pinned at a digest the package never published, a wildcard
# or metacharacter action, an identity the broker never declared, a
# duplicated grant, and an expired grant still on the books are all
# refused. The package's own conformance is the component gate's
# word (book issue #101); this gate reads only the fields the grant
# join needs.
broker-gate:
	@test -f "$(BROKER_GRANTS)" && test -f "$(COMPONENT_PACKAGE)" || { echo "usage: make broker-gate [BROKER_GRANTS=... COMPONENT_PACKAGE=...] [TODAY=YYYY-MM-DD]"; exit 2; }
	@mkdir -p build
	yq -o=json '.' '$(BROKER_GRANTS)' '$(COMPONENT_PACKAGE)' \
		| jq -cs --arg today "$(TODAY)" --arg brokerFile "$(BROKER_GRANTS)" --arg packageFile "$(COMPONENT_PACKAGE)" \
			'{broker: .[0], package: .[1], today: $$today, brokerFile: $$brokerFile, packageFile: $$packageFile}' \
		| $(OPA) eval -d policies -I 'data.broker.audit' --format=pretty | tee build/broker-gate.json
	@jq -e '.valid == true' build/broker-gate.json > /dev/null \
		|| { echo "broker-gate: the broker grants are not in conformance — findings above"; exit 1; }

# The done-when proof for book issue #104: the supply-chain IAM-broker
# scope gate refuses. Runs the control grants end to end, then proves
# every broken variant bites with its named rule — the wildcard and
# the metacharacter actions, the expired grant, the identity the
# broker never declared, the component the manifest never named, and
# the digest the package never published.
broker-demo:
	@echo "--- 1. the broker grant document validates ---"
	@$(MAKE) check-broker TODAY=$(ANCHOR_TODAY)
	@echo "--- 2. the control passes the gate and renders consistent ---"
	@$(MAKE) broker-gate TODAY=$(ANCHOR_TODAY)
	@grep -q '"verdict": "consistent"' build/broker-gate.json \
		|| { echo "FAIL: the control gate did not render the consistent verdict"; cat build/broker-gate.json; exit 1; }
	@jq -e '.grants | length == 2' build/broker-gate.json > /dev/null \
		|| { echo "FAIL: the control did not render one card per issued grant"; cat build/broker-gate.json; exit 1; }
	@jq -e '[.grants[] | select(.verdict != "consistent")] | length == 0' build/broker-gate.json > /dev/null \
		|| { echo "FAIL: a control card drifted"; cat build/broker-gate.json; exit 1; }
	@echo "control verdict: consistent — two grants, two cards, the manifest vouches for both"
	@echo "--- 3. a wildcard grant is caught at the gate ---"
	@if $(MAKE) broker-gate BROKER_GRANTS=examples/broker/broken/grants.wildcard-action.yaml TODAY=$(ANCHOR_TODAY) > build/broker-wildcard.txt 2>&1; \
		then echo "FAIL: the wildcard grant passed the gate"; cat build/broker-wildcard.txt; exit 1; \
		else grep -q 'grant/action-wildcard' build/broker-wildcard.txt \
			|| { echo "FAIL: the gate failed without the wildcard rule"; cat build/broker-wildcard.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 1' build/broker-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/broker-gate.json; exit 1; }
	@grep -q '"verdict": "unreadable"' build/broker-gate.json \
		|| { echo "FAIL: the gate did not render the unreadable verdict"; cat build/broker-gate.json; exit 1; }
	@echo "caught as expected: grant/action-wildcard — a grant that can do anything is the scope the broker exists to prevent"
	@echo "--- 4. a metacharacter action is caught at the gate ---"
	@if $(MAKE) broker-gate BROKER_GRANTS=examples/broker/broken/grants.metachar-action.yaml TODAY=$(ANCHOR_TODAY) > build/broker-metachar.txt 2>&1; \
		then echo "FAIL: the metacharacter action passed the gate"; cat build/broker-metachar.txt; exit 1; \
		else grep -q 'grant/action-glob' build/broker-metachar.txt \
			|| { echo "FAIL: the gate failed without the glob rule"; cat build/broker-metachar.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 1' build/broker-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/broker-gate.json; exit 1; }
	@grep -q '"verdict": "unreadable"' build/broker-gate.json \
		|| { echo "FAIL: the gate did not render the unreadable verdict"; cat build/broker-gate.json; exit 1; }
	@echo "caught as expected: grant/action-glob — an action set is exact names or it is not a set"
	@echo "--- 5. an expired grant still on the books is caught at the gate ---"
	@if $(MAKE) broker-gate BROKER_GRANTS=examples/broker/broken/grants.expired.yaml TODAY=$(ANCHOR_TODAY) > build/broker-expired.txt 2>&1; \
		then echo "FAIL: the expired grant passed the gate"; cat build/broker-expired.txt; exit 1; \
		else grep -q 'grant/expires-in-past' build/broker-expired.txt \
			|| { echo "FAIL: the gate failed without the expiry rule"; cat build/broker-expired.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 1' build/broker-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/broker-gate.json; exit 1; }
	@grep -q '"verdict": "unreadable"' build/broker-gate.json \
		|| { echo "FAIL: the gate did not render the unreadable verdict"; cat build/broker-gate.json; exit 1; }
	@echo "caught as expected: grant/expires-in-past — an expired grant is a grant the broker never revoked"
	@echo "--- 6. an identity the broker never declared is caught at the gate ---"
	@if $(MAKE) broker-gate BROKER_GRANTS=examples/broker/broken/grants.unknown-principal.yaml TODAY=$(ANCHOR_TODAY) > build/broker-undeclared.txt 2>&1; \
		then echo "FAIL: the undeclared principal passed the gate"; cat build/broker-undeclared.txt; exit 1; \
		else grep -q 'grant/principal-undeclared' build/broker-undeclared.txt \
			|| { echo "FAIL: the gate failed without the principal rule"; cat build/broker-undeclared.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 1' build/broker-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/broker-gate.json; exit 1; }
	@grep -q '"verdict": "unreadable"' build/broker-gate.json \
		|| { echo "FAIL: the gate did not render the unreadable verdict"; cat build/broker-gate.json; exit 1; }
	@echo "caught as expected: grant/principal-undeclared — an identity the broker never declared is a principal nobody granted"
	@echo "--- 7. a grant for a component the manifest never named is caught at the join ---"
	@if $(MAKE) broker-gate BROKER_GRANTS=examples/broker/broken/grants.component-unresolved.yaml TODAY=$(ANCHOR_TODAY) > build/broker-unresolved.txt 2>&1; \
		then echo "FAIL: the unresolved grant passed the gate"; cat build/broker-unresolved.txt; exit 1; \
		else grep -q 'gate/component-unresolved' build/broker-unresolved.txt \
			|| { echo "FAIL: the gate failed without the unresolved-component rule"; cat build/broker-unresolved.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 1' build/broker-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/broker-gate.json; exit 1; }
	@grep -q '"verdict": "drifts"' build/broker-gate.json \
		|| { echo "FAIL: the gate did not render the drifts verdict"; cat build/broker-gate.json; exit 1; }
	@echo "caught as expected: gate/component-unresolved — a grant for a component nobody packaged, citing both files"
	@echo "--- 8. a grant pinned at a digest the package never published is caught at the join ---"
	@if $(MAKE) broker-gate BROKER_GRANTS=examples/broker/broken/grants.digest-drift.yaml TODAY=$(ANCHOR_TODAY) > build/broker-digest.txt 2>&1; \
		then echo "FAIL: the digest drift passed the gate"; cat build/broker-digest.txt; exit 1; \
		else grep -q 'gate/digest-drift' build/broker-digest.txt \
			|| { echo "FAIL: the gate failed without the digest-rule"; cat build/broker-digest.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 1' build/broker-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/broker-gate.json; exit 1; }
	@grep -q '"verdict": "drifts"' build/broker-gate.json \
		|| { echo "FAIL: the gate did not render the drifts verdict"; cat build/broker-gate.json; exit 1; }
	@echo "caught as expected: gate/digest-drift — a grant for bytes the package never published, citing both files"

# Validate every shipped example against the CI anchor date.
examples:
	$(MAKE) check-enclave FILE=examples/enclaves/checkout.yaml TODAY=$(ANCHOR_TODAY)
	$(MAKE) check-enclave FILE=examples/enclaves/payments.yaml TODAY=$(ANCHOR_TODAY)
	$(MAKE) check-seam FILE=examples/seams/checkout-web-tier.yaml TODAY=$(ANCHOR_TODAY)
	$(MAKE) check-seam FILE=examples/seams/payments-3ds-redirect.yaml TODAY=$(ANCHOR_TODAY)
	$(MAKE) check-bundle FILE=examples/bundle.yaml
	$(MAKE) check-authz FILE=examples/authz/storefront.yaml TODAY=$(ANCHOR_TODAY)
	$(MAKE) check-obs TODAY=$(ANCHOR_TODAY)
	$(MAKE) check-alerts TODAY=$(ANCHOR_TODAY)
	$(MAKE) alerts-gate TODAY=$(ANCHOR_TODAY)
	$(MAKE) check-actions TODAY=$(ANCHOR_TODAY)
	$(MAKE) actions-gate TODAY=$(ANCHOR_TODAY)
	$(MAKE) check-erasure TODAY=$(ANCHOR_TODAY)
	$(MAKE) erasure-gate TODAY=$(ANCHOR_TODAY)
	$(MAKE) erasure-gate ERASURE_CASE=examples/erasure/case-pending.yaml TODAY=$(ANCHOR_TODAY)
	$(MAKE) check-segment TODAY=$(ANCHOR_TODAY)
	$(MAKE) segment-gate TODAY=$(ANCHOR_TODAY)
	$(MAKE) check-ingress TODAY=$(ANCHOR_TODAY)
	$(MAKE) ingress-gate TODAY=$(ANCHOR_TODAY)
	$(MAKE) check-citizen TODAY=$(ANCHOR_TODAY)
	$(MAKE) citizen-gate TODAY=$(ANCHOR_TODAY)
	$(MAKE) check-component TODAY=$(ANCHOR_TODAY)
	$(MAKE) component-gate TODAY=$(ANCHOR_TODAY)
	$(MAKE) check-matrix TODAY=$(ANCHOR_TODAY)
	$(MAKE) matrix-gate TODAY=$(ANCHOR_TODAY)
	$(MAKE) check-broker TODAY=$(ANCHOR_TODAY)
	$(MAKE) broker-gate TODAY=$(ANCHOR_TODAY)

# Everything CI runs, in order.
ci: check test examples e2e obs-demo alerts-demo actions-demo erasure-demo segment-demo ingress-demo citizen-demo component-demo matrix-demo broker-demo
	$(OPA) fmt --fail -l policies
