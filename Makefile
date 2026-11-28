# Estate and seam contract validator — The Software Field Guide.
#
# Targets:
#   make fmt            format the Rego sources in place
#   make check          compile-check the policies
#   make test           run the Rego unit tests
#   make build         compile the nineteen wasm bundles into build/wasm/
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
#   make check-policy  validate the policy component catalog
#                      [POLICY_CATALOG=...] [TODAY=YYYY-MM-DD]
#   make policy-gate  gate the component package's policy bindings
#                      against the catalog [POLICY_CATALOG=...
#                      POLICY_PACKAGE=...] [TODAY=YYYY-MM-DD]
#   make policy-demo  the done-when proof: a package binding to a
#                      policy the catalog never declared caught
#                      citing both files (runs the whole demo)
#   make check-compliance  validate the controls manifest (the named
#                      evidence sources and the controls that cite
#                      them) [CONTROLS=...] [TODAY=YYYY-MM-DD]
#   make compliance-gate  gate the requirements catalog against the
#                      controls manifest [CONTROLS=... REQUIREMENTS=...]
#                      [TODAY=YYYY-MM-DD]
#   make compliance-demo  the done-when proof: a requirement nobody
#                      controls caught citing both files (runs the
#                      whole demo)
#   make check-broker validate the broker grant document (the consumer
#                      identities it declares and the grants it issued)
#                      [BROKER_GRANTS=...] [TODAY=YYYY-MM-DD]
#   make broker-gate  gate the grants against the component package
#                      manifest [BROKER_GRANTS=... COMPONENT_PACKAGE=...]
#                      [TODAY=YYYY-MM-DD]
#   make broker-demo the done-when proof: a wildcard grant caught naming
#                      the scope the broker exists to prevent
#   make check-lifecycle validate the component lifecycle record (its
#                      stamps, its review clock, every transition with
#                      the evidence its type demands)
#                      [LIFECYCLE_RECORD=...] [TODAY=YYYY-MM-DD]
#   make lifecycle-gate gate the record against the component package
#                      manifest by component name
#                      [LIFECYCLE_RECORD=... COMPONENT_PACKAGE=...] [TODAY=...]
#   make lifecycle-demo the done-when proof: a bake without its image
#                      digest caught citing the record (runs the whole
#                      demo)
#   make check-datacontract validate the data contract (the schema, the
#                      freshness SLA, the quality thresholds, the owner,
#                      the consumers, the enforcement checks, the change
#                      methodology) [DATACONTRACT=...] [TODAY=...]
#   make datacontract-gate gate the contract against the enforcement
#                      record — the CI's word [DATACONTRACT=...
#                      DATACONTRACT_ENFORCEMENT=...] [TODAY=...]
#   make datacontract-demo the done-when proof: a declared check the
#                      record never shows running caught citing both
#                      files (runs the whole demo)
#   make check-identity validate the identity manifest (its stamps,
#                      every identity named, every reference narrowed
#                      to one scope, no wildcards, no duplicates)
#                      [IDENTITY_MANIFEST=...] [TODAY=...]
#   make identity-gate gate the manifest against the secrets catalog
#                      — deny-by-default [IDENTITY_MANIFEST=...
#                      IDENTITY_CATALOG=...] [TODAY=...]
#   make identity-demo the done-when proof: a secret with no rotation
#                      clock and an undeclared identity caught citing
#                      both files (runs the whole demo)

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
POLICY_CATALOG ?= examples/policy/catalog.yaml
POLICY_PACKAGE ?= examples/component/package.yaml
CONTROLS ?= examples/compliance/controls.yaml
REQUIREMENTS ?= examples/compliance/requirements.yaml
BROKER_GRANTS ?= examples/broker/grants.yaml
LIFECYCLE_RECORD ?= examples/lifecycle/lifecycle.yaml
DATACONTRACT ?= examples/datacontract/datacontract.yaml
DATACONTRACT_ENFORCEMENT ?= examples/datacontract/enforcement.yaml
IDENTITY_MANIFEST ?= examples/identity/manifest.yaml
IDENTITY_CATALOG ?= examples/identity/catalog.yaml

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
	check-policy policy-gate policy-demo \
	check-compliance compliance-gate compliance-demo \
	check-broker broker-gate broker-demo \
	check-lifecycle lifecycle-gate lifecycle-demo \
	check-datacontract datacontract-gate datacontract-demo \
	check-identity identity-gate identity-demo \
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
	$(OPA) build -t wasm -e policy/audit -o build/policy.tar.gz policies
	tar -xzf build/policy.tar.gz -C build /policy.wasm
	mv build/policy.wasm build/wasm/policy.wasm
	$(OPA) build -t wasm -e compliance/audit -o build/compliance.tar.gz policies
	tar -xzf build/compliance.tar.gz -C build /policy.wasm
	mv build/policy.wasm build/wasm/compliance.wasm
	$(OPA) build -t wasm -e broker/audit -o build/broker.tar.gz policies
	tar -xzf build/broker.tar.gz -C build /policy.wasm
	mv build/policy.wasm build/wasm/broker.wasm
	$(OPA) build -t wasm -e lifecycle/audit -o build/lifecycle.tar.gz policies
	tar -xzf build/lifecycle.tar.gz -C build /policy.wasm
	mv build/policy.wasm build/wasm/lifecycle.wasm
	$(OPA) build -t wasm -e datacontract/audit -o build/datacontract.tar.gz policies
	tar -xzf build/datacontract.tar.gz -C build /policy.wasm
	mv build/policy.wasm build/wasm/datacontract.wasm
	$(OPA) build -t wasm -e identity/audit -o build/identity.tar.gz policies
	tar -xzf build/identity.tar.gz -C build /policy.wasm
	mv build/policy.wasm build/wasm/identity.wasm

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

# Validate the policy component catalog alone: the
# policy-component chapter's catalog — the platform's word on the
# policy components it admits, each versioned, signed over its
# digest, postured on the audit→warn→enforce ladder, and bound to
# one exact path. Conformance gate, not advisor: any finding fails.
check-policy:
	@test -f "$(POLICY_CATALOG)" || { echo "usage: make check-policy [POLICY_CATALOG=...] [TODAY=YYYY-MM-DD]"; exit 2; }
	@mkdir -p build
	yq -o=json '.' '$(POLICY_CATALOG)' \
		| jq -cs --arg today "$(TODAY)" --arg catalogFile "$(POLICY_CATALOG)" '{catalog: .[0], today: $$today, catalogFile: $$catalogFile}' \
		| $(OPA) eval -d policies -I 'data.policy.validate' --format=pretty | tee build/check-policy.json
	@jq -e '.valid == true' build/check-policy.json > /dev/null \
		|| { echo "check-policy: the policy component catalog is not in conformance — findings above"; exit 1; }

# Gate the component package's policy bindings against the policy
# component catalog: every policy the package binds must exist in
# the catalog and be bound at the catalog's declared exact path.
# Conformance gate, not advisor: a binding to a policy the catalog
# never admitted and a binding rendered at a path the catalog never
# named are both refused. The catalog is shared: a row no package
# currently binds is a policy available, not a drift.
policy-gate:
	@test -f "$(POLICY_CATALOG)" || { echo "usage: make policy-gate [POLICY_CATALOG=... POLICY_PACKAGE=...] [TODAY=YYYY-MM-DD]"; exit 2; }
	@mkdir -p build
	yq -o=json '.' '$(POLICY_CATALOG)' '$(POLICY_PACKAGE)' \
		| jq -cs --arg today "$(TODAY)" --arg catalogFile "$(POLICY_CATALOG)" --arg packageFile "$(POLICY_PACKAGE)" \
			'{catalog: .[0], package: .[1], today: $$today, catalogFile: $$catalogFile, packageFile: $$packageFile}' \
		| $(OPA) eval -d policies -I 'data.policy.audit' --format=pretty | tee build/policy-gate.json
	@jq -e '.valid == true' build/policy-gate.json > /dev/null \
		|| { echo "policy-gate: the policy bindings are not in conformance — findings above"; exit 1; }

# The done-when proof for book issue #103: the policy-component
# validation gate refuses. Runs the control package and catalog end
# to end, then proves every drift variant bites exactly once — three
# at validation, two at the join, one at the binding shapes — and
# that each bite names its rule and renders its verdict honestly.
policy-demo:
	@echo "--- 1. the policy component catalog validates ---"
	@$(MAKE) check-policy TODAY=$(ANCHOR_TODAY)
	@echo "--- 2. the control passes the gate and renders consistent ---"
	@$(MAKE) policy-gate TODAY=$(ANCHOR_TODAY)
	@grep -q '"verdict": "consistent"' build/policy-gate.json \
		|| { echo "FAIL: the control gate did not render the consistent verdict"; cat build/policy-gate.json; exit 1; }
	@jq -e '.policies | length == 2' build/policy-gate.json > /dev/null \
		|| { echo "FAIL: the control did not render one card per bound policy"; cat build/policy-gate.json; exit 1; }
	@echo "control verdict: consistent — two bound policies, both answering the catalog, one card per binding"
	@echo "--- 3. a glob-shaped catalog path is caught at validation ---"
	@if $(MAKE) check-policy POLICY_CATALOG=examples/policy/broken/catalog.path-glob.yaml TODAY=$(ANCHOR_TODAY) > build/policy-path-glob.txt 2>&1; \
		then echo "FAIL: the glob-shaped path passed validation"; cat build/policy-path-glob.txt; exit 1; \
		else grep -q 'policy/path-glob' build/policy-path-glob.txt \
			|| { echo "FAIL: the catalog failed without the path-glob rule"; cat build/policy-path-glob.txt; exit 1; }; \
		fi
	@echo "caught as expected: policy/path-glob — a binding that can match anything is a binding the join refuses to guess"
	@echo "--- 4. an unsigned policy component is caught at validation ---"
	@if $(MAKE) check-policy POLICY_CATALOG=examples/policy/broken/catalog.unsigned.yaml TODAY=$(ANCHOR_TODAY) > build/policy-unsigned.txt 2>&1; \
		then echo "FAIL: the unsigned policy passed validation"; cat build/policy-unsigned.txt; exit 1; \
		else grep -q 'policy/signature-required' build/policy-unsigned.txt \
			|| { echo "FAIL: the catalog failed without the signature rule"; cat build/policy-unsigned.txt; exit 1; }; \
		fi
	@echo "caught as expected: policy/signature-required — an unsigned policy is a policy nobody vouches for"
	@echo "--- 5. a signature that signed another digest is caught at validation ---"
	@if $(MAKE) check-policy POLICY_CATALOG=examples/policy/broken/catalog.signature-mismatch.yaml TODAY=$(ANCHOR_TODAY) > build/policy-mismatch.txt 2>&1; \
		then echo "FAIL: the inconsistent signature passed validation"; cat build/policy-mismatch.txt; exit 1; \
		else grep -q 'policy/signature-digest-mismatch' build/policy-mismatch.txt \
			|| { echo "FAIL: the catalog failed without the mismatch rule"; cat build/policy-mismatch.txt; exit 1; }; \
		fi
	@echo "caught as expected: policy/signature-digest-mismatch — the recorded evidence is not even internally consistent"
	@echo "--- 6. a binding to a policy the catalog never declared is caught at the join ---"
	@if $(MAKE) policy-gate POLICY_CATALOG=examples/policy/broken/catalog.missing-policy.yaml TODAY=$(ANCHOR_TODAY) > build/policy-unresolved.txt 2>&1; \
		then echo "FAIL: the unresolved binding passed the gate"; cat build/policy-unresolved.txt; exit 1; \
		else grep -q 'gate/policy-unresolved' build/policy-unresolved.txt \
			|| { echo "FAIL: the gate failed without the unresolved rule"; cat build/policy-unresolved.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 1' build/policy-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/policy-gate.json; exit 1; }
	@grep -q '"verdict": "drifts"' build/policy-gate.json \
		|| { echo "FAIL: the gate did not render the drifts verdict"; cat build/policy-gate.json; exit 1; }
	@echo "caught as expected: gate/policy-unresolved — a deny-by-default claim about a policy the estate never admitted is a claim nobody can check"
	@echo "--- 7. a binding rendered at a path the catalog never named is caught at the join ---"
	@if $(MAKE) policy-gate POLICY_CATALOG=examples/policy/broken/catalog.path-drift.yaml TODAY=$(ANCHOR_TODAY) > build/policy-path-drift.txt 2>&1; \
		then echo "FAIL: the drifted path passed the gate"; cat build/policy-path-drift.txt; exit 1; \
		else grep -q 'gate/binding-path-drift' build/policy-path-drift.txt \
			|| { echo "FAIL: the gate failed without the path-drift rule"; cat build/policy-path-drift.txt; exit 1; }; \
		fi
	@grep -q 'examples/component/package.yaml' build/policy-path-drift.txt \
		|| { echo "FAIL: the finding does not cite the package manifest"; cat build/policy-path-drift.txt; exit 1; }
	@grep -q 'catalog.path-drift.yaml' build/policy-path-drift.txt \
		|| { echo "FAIL: the finding does not cite the catalog"; cat build/policy-path-drift.txt; exit 1; }
	@jq -e '[.findings[]] | length == 1' build/policy-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/policy-gate.json; exit 1; }
	@grep -q '"verdict": "drifts"' build/policy-gate.json \
		|| { echo "FAIL: the gate did not render the drifts verdict"; cat build/policy-gate.json; exit 1; }
	@echo "caught as expected: gate/binding-path-drift citing both files — the same policy at a different path is a different binding"
	@echo "--- 8. a glob-shaped package binding is caught, and the gate refuses to answer ---"
	@if $(MAKE) policy-gate POLICY_PACKAGE=examples/policy/broken/package.path-glob-binding.yaml TODAY=$(ANCHOR_TODAY) > build/policy-glob-binding.txt 2>&1; \
		then echo "FAIL: the glob-shaped binding passed the gate"; cat build/policy-glob-binding.txt; exit 1; \
		else grep -q 'package/binding-path-glob' build/policy-glob-binding.txt \
			|| { echo "FAIL: the gate failed without the binding-path-glob rule"; cat build/policy-glob-binding.txt; exit 1; }; \
		fi
	@grep -q '"verdict": "unreadable"' build/policy-gate.json \
		|| { echo "FAIL: the gate did not render the unreadable verdict"; cat build/policy-gate.json; exit 1; }
	@echo "caught as expected: package/binding-path-glob, verdict unreadable — the exactness gap the component validator never checked"
	@echo "--- policy demo: all done-when proofs passed ---"


# Validate the controls manifest alone: the compliance chapter's
# manifest — the estate's own word, the named evidence sources it
# collects and every control's mappings, citations, and review
# clocks. Conformance gate, not advisor: any finding fails.
check-compliance:
	@test -f "$(CONTROLS)" || { echo "usage: make check-compliance [CONTROLS=...] [TODAY=YYYY-MM-DD]"; exit 2; }
	@mkdir -p build
	yq -o=json '.' '$(CONTROLS)' \
		| jq -cs --arg today "$(TODAY)" --arg controlsFile "$(CONTROLS)" '{controls: .[0], today: $$today, controlsFile: $$controlsFile}' \
		| $(OPA) eval -d policies -I 'data.compliance.validate' --format=pretty | tee build/check-compliance.json
	@jq -e '.valid == true' build/check-compliance.json > /dev/null \
		|| { echo "check-compliance: the controls manifest is not in conformance — findings above"; exit 1; }

# Gate the requirements catalog against the controls manifest: every
# catalog requirement must have a control mapped onto it, every
# control must map onto a declared requirement, every citation must
# resolve to a live evidence source, and every review clock must be
# fresh against today. Conformance gate, not advisor: a requirement
# nobody controls, a control citing a requirement nobody wrote, dead
# evidence, and a lapsed clock are all refused.
compliance-gate:
	@test -f "$(CONTROLS)" || test -f "$(REQUIREMENTS)" || { echo "usage: make compliance-gate [CONTROLS=... REQUIREMENTS=...] [TODAY=YYYY-MM-DD]"; exit 2; }
	@mkdir -p build
	yq -o=json '.' '$(CONTROLS)' '$(REQUIREMENTS)' \
		| jq -cs --arg today "$(TODAY)" --arg controlsFile "$(CONTROLS)" --arg requirementsFile "$(REQUIREMENTS)" \
			'{controls: .[0], requirements: .[1], today: $$today, controlsFile: $$controlsFile, requirementsFile: $$requirementsFile}' \
		| $(OPA) eval -d policies -I 'data.compliance.gate' --format=pretty | tee build/compliance-gate.json
	@jq -e '.valid == true' build/compliance-gate.json > /dev/null \
		|| { echo "compliance-gate: the requirements catalog is not in conformance — findings above"; exit 1; }

# The done-when proof for book issue #107: the compliance
# controls-as-data gate refuses. Runs the control pair end to end,
# then proves every drift variant bites — the unmapped requirement,
# the dead evidence, the lapsed clock, the unknown requirement — and
# that the unreadable variants refuse to answer, each naming its rule.
compliance-demo:
	@echo "--- 1. the controls manifest validates ---"
	@$(MAKE) check-compliance TODAY=$(ANCHOR_TODAY)
	@echo "--- 2. the control pair passes the gate and renders consistent ---"
	@$(MAKE) compliance-gate TODAY=$(ANCHOR_TODAY)
	@grep -q '"verdict": "consistent"' build/compliance-gate.json \
		|| { echo "FAIL: the control gate did not render the consistent verdict"; cat build/compliance-gate.json; exit 1; }
	@jq -e '.requirements | length == 4' build/compliance-gate.json > /dev/null \
		|| { echo "FAIL: the control did not render one card per declared requirement"; cat build/compliance-gate.json; exit 1; }
	@echo "control verdict: consistent — every requirement covered by a sound control, one card per declaration"
	@echo "--- 3. a requirement nobody controls is caught at the join ---"
	@if $(MAKE) compliance-gate REQUIREMENTS=examples/compliance/broken/requirements.unmapped.yaml TODAY=$(ANCHOR_TODAY) > build/compliance-unmapped.txt 2>&1; \
		then echo "FAIL: the unmapped requirement passed the gate"; cat build/compliance-unmapped.txt; exit 1; \
		else grep -q 'gate/requirement-unmapped' build/compliance-unmapped.txt \
			|| { echo "FAIL: the gate failed without the unmapped rule"; cat build/compliance-unmapped.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 1' build/compliance-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/compliance-gate.json; exit 1; }
	@grep -q '"verdict": "drifts"' build/compliance-gate.json \
		|| { echo "FAIL: the gate did not render the drifts verdict"; cat build/compliance-gate.json; exit 1; }
	@echo "caught as expected: gate/requirement-unmapped — a requirement nobody controls is a promise nobody keeps"
	@echo "--- 4. a control citing retired evidence is caught at the join ---"
	@if $(MAKE) compliance-gate CONTROLS=examples/compliance/broken/controls.evidence-dead.yaml TODAY=$(ANCHOR_TODAY) > build/compliance-evidence-dead.txt 2>&1; \
		then echo "FAIL: the retired evidence passed the gate"; cat build/compliance-evidence-dead.txt; exit 1; \
		else grep -q 'gate/evidence-dead' build/compliance-evidence-dead.txt \
			|| { echo "FAIL: the gate failed without the evidence-dead rule"; cat build/compliance-evidence-dead.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 1' build/compliance-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/compliance-gate.json; exit 1; }
	@grep -q '"verdict": "drifts"' build/compliance-gate.json \
		|| { echo "FAIL: the gate did not render the drifts verdict"; cat build/compliance-gate.json; exit 1; }
	@echo "caught as expected: gate/evidence-dead — a control pointing at evidence nobody collects is a control nobody can audit"
	@echo "--- 5. a control whose review clock lapsed is caught at the join ---"
	@if $(MAKE) compliance-gate CONTROLS=examples/compliance/broken/controls.review-expired.yaml TODAY=$(ANCHOR_TODAY) > build/compliance-review-expired.txt 2>&1; \
		then echo "FAIL: the lapsed clock passed the gate"; cat build/compliance-review-expired.txt; exit 1; \
		else grep -q 'gate/review-expired' build/compliance-review-expired.txt \
			|| { echo "FAIL: the gate failed without the review-expired rule"; cat build/compliance-review-expired.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 1' build/compliance-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/compliance-gate.json; exit 1; }
	@grep -q '"verdict": "drifts"' build/compliance-gate.json \
		|| { echo "FAIL: the gate did not render the drifts verdict"; cat build/compliance-gate.json; exit 1; }
	@echo "caught as expected: gate/review-expired — a control nobody re-reviews is a control nobody operates"
	@echo "--- 6. a control mapping onto a requirement nobody wrote is caught at the join ---"
	@if $(MAKE) compliance-gate CONTROLS=examples/compliance/broken/controls.requirement-unknown.yaml TODAY=$(ANCHOR_TODAY) > build/compliance-requirement-unknown.txt 2>&1; \
		then echo "FAIL: the unknown requirement passed the gate"; cat build/compliance-requirement-unknown.txt; exit 1; \
		else grep -q 'gate/requirement-unknown' build/compliance-requirement-unknown.txt \
			|| { echo "FAIL: the gate failed without the requirement-unknown rule"; cat build/compliance-requirement-unknown.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 2' build/compliance-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite honestly twice — the unknown requirement and the requirement it orphaned"; cat build/compliance-gate.json; exit 1; }
	@grep -q 'gate/requirement-unmapped' build/compliance-requirement-unknown.txt \
		|| { echo "FAIL: the orphaned requirement went unreported"; cat build/compliance-requirement-unknown.txt; exit 1; }
	@grep -q '"verdict": "drifts"' build/compliance-gate.json \
		|| { echo "FAIL: the gate did not render the drifts verdict"; cat build/compliance-gate.json; exit 1; }
	@echo "caught as expected: gate/requirement-unknown — and the requirement it orphaned bites too, honestly"
	@echo "--- 7. a control without evidence makes the gate refuse to answer ---"
	@if $(MAKE) compliance-gate CONTROLS=examples/compliance/broken/controls.no-evidence.yaml TODAY=$(ANCHOR_TODAY) > build/compliance-no-evidence.txt 2>&1; \
		then echo "FAIL: the evidence-less control passed the gate"; cat build/compliance-no-evidence.txt; exit 1; \
		else grep -q 'control/evidence-required' build/compliance-no-evidence.txt \
			|| { echo "FAIL: the gate failed without the evidence rule"; cat build/compliance-no-evidence.txt; exit 1; }; \
		fi
	@grep -q '"verdict": "unreadable"' build/compliance-gate.json \
		|| { echo "FAIL: the gate did not render the unreadable verdict"; cat build/compliance-gate.json; exit 1; }
	@echo "caught as expected: control/evidence-required, verdict unreadable — a control without evidence is an assertion, not a control"
	@echo "--- 8. a manifest nobody re-reads makes the gate refuse to answer ---"
	@if $(MAKE) compliance-gate CONTROLS=examples/compliance/broken/controls.stale-review.yaml TODAY=$(ANCHOR_TODAY) > build/compliance-stale-review.txt 2>&1; \
		then echo "FAIL: the stale manifest passed the gate"; cat build/compliance-stale-review.txt; exit 1; \
		else grep -q 'controls/reviewed-stale' build/compliance-stale-review.txt \
			|| { echo "FAIL: the gate failed without the stale-review rule"; cat build/compliance-stale-review.txt; exit 1; }; \
		fi
	@grep -q '"verdict": "unreadable"' build/compliance-gate.json \
		|| { echo "FAIL: the gate did not render the unreadable verdict"; cat build/compliance-gate.json; exit 1; }
	@echo "caught as expected: controls/reviewed-stale, verdict unreadable — a manifest nobody refreshed is a map of an estate that no longer exists"
	@echo "--- 9. two controls sharing one id make the gate refuse to answer ---"
	@if $(MAKE) compliance-gate CONTROLS=examples/compliance/broken/controls.duplicate-id.yaml TODAY=$(ANCHOR_TODAY) > build/compliance-duplicate-id.txt 2>&1; \
		then echo "FAIL: the duplicated id passed the gate"; cat build/compliance-duplicate-id.txt; exit 1; \
		else grep -q 'control/id-duplicate' build/compliance-duplicate-id.txt \
			|| { echo "FAIL: the gate failed without the duplicate rule"; cat build/compliance-duplicate-id.txt; exit 1; }; \
		fi
	@grep -q '"verdict": "unreadable"' build/compliance-gate.json \
		|| { echo "FAIL: the gate did not render the unreadable verdict"; cat build/compliance-gate.json; exit 1; }
	@echo "caught as expected: control/id-duplicate, verdict unreadable — a control declared twice is evidence nobody can count"
	@echo "--- 10. a control mapping onto nothing makes the gate refuse to answer ---"
	@if $(MAKE) compliance-gate CONTROLS=examples/compliance/broken/controls.no-requirements.yaml TODAY=$(ANCHOR_TODAY) > build/compliance-no-requirements.txt 2>&1; \
		then echo "FAIL: the unmapped control passed the gate"; cat build/compliance-no-requirements.txt; exit 1; \
		else grep -q 'control/requirements-required' build/compliance-no-requirements.txt \
			|| { echo "FAIL: the gate failed without the requirements rule"; cat build/compliance-no-requirements.txt; exit 1; }; \
		fi
	@grep -q '"verdict": "unreadable"' build/compliance-gate.json \
		|| { echo "FAIL: the gate did not render the unreadable verdict"; cat build/compliance-gate.json; exit 1; }
	@echo "caught as expected: control/requirements-required, verdict unreadable — an unmapped control is busywork with no compliance meaning"
	@echo "--- compliance demo: all done-when proofs passed ---"

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

# Validate the component lifecycle record alone — the component's
# paper trail: versioned transitions, each carrying the evidence its
# type demands (a bake its sha256 image digest, a patch its provenance
# source and commit, an upgrade the date its rollback was rehearsed),
# a review that is fresh and covers every transition on it.
check-lifecycle:
	@test -f "$(LIFECYCLE_RECORD)" || { echo "usage: make check-lifecycle [LIFECYCLE_RECORD=...] [TODAY=YYYY-MM-DD]"; exit 2; }
	@mkdir -p build
	yq -o=json '.' '$(LIFECYCLE_RECORD)' \
		| jq -cs --arg today "$(TODAY)" --arg lifecycleFile "$(LIFECYCLE_RECORD)" '{lifecycle: .[0], today: $$today, lifecycleFile: $$lifecycleFile}' \
		| $(OPA) eval -d policies -I 'data.lifecycle.validate' --format=pretty | tee build/check-lifecycle.json
	@jq -e '.valid == true' build/check-lifecycle.json > /dev/null \
		|| { echo "check-lifecycle: the lifecycle record is not in conformance — findings above"; exit 1; }

# Gate the lifecycle record against the component package manifest —
# the join runs on the component name. Conformance gate, not advisor:
# a record documenting a component the manifest never packaged, a
# transition without its evidence, a review that never saw a
# transition recorded after it, and a record nobody has re-read in a
# year are all refused, not advised.
lifecycle-gate:
	@test -f "$(COMPONENT_PACKAGE)" || { echo "usage: make lifecycle-gate [LIFECYCLE_RECORD=... COMPONENT_PACKAGE=...] [TODAY=YYYY-MM-DD]"; exit 2; }
	@mkdir -p build
	yq -o=json '.' '$(COMPONENT_PACKAGE)' '$(LIFECYCLE_RECORD)' \
		| jq -cs --arg today "$(TODAY)" --arg packageFile "$(COMPONENT_PACKAGE)" --arg lifecycleFile "$(LIFECYCLE_RECORD)" \
			'{package: .[0], lifecycle: .[1], today: $$today, packageFile: $$packageFile, lifecycleFile: $$lifecycleFile}' \
		| $(OPA) eval -d policies -I 'data.lifecycle.audit' --format=pretty | tee build/lifecycle-gate.json
	@jq -e '.valid == true' build/lifecycle-gate.json > /dev/null \
		|| { echo "lifecycle-gate: the lifecycle record is not in conformance — findings above"; exit 1; }

# The done-when proof for book issue #105: the lifecycle evidence
# gate refuses. Runs the control record end to end, then proves
# every broken variant bites with its named rule — three at
# transition evidence, one after the review, one at the type stamp,
# one at the review clock, and one at the join — and that each bite
# renders its verdict honestly.
lifecycle-demo:
	@echo "--- 1. the lifecycle record validates ---"
	@$(MAKE) check-lifecycle TODAY=$(ANCHOR_TODAY)
	@echo "--- 2. the control passes the gate and renders consistent ---"
	@$(MAKE) lifecycle-gate TODAY=$(ANCHOR_TODAY)
	@grep -q '"verdict": "consistent"' build/lifecycle-gate.json \
		|| { echo "FAIL: the control gate did not render the consistent verdict"; cat build/lifecycle-gate.json; exit 1; }
	@jq -e '.transitions | length == 3' build/lifecycle-gate.json > /dev/null \
		|| { echo "FAIL: the control did not render one card per recorded transition"; cat build/lifecycle-gate.json; exit 1; }
	@echo "control verdict: consistent — one card per recorded transition, every one evidenced"
	@echo "--- 3. a bake without its image digest is caught ---"
	@if $(MAKE) lifecycle-gate LIFECYCLE_RECORD=examples/lifecycle/broken/lifecycle.bake-no-digest.yaml TODAY=$(ANCHOR_TODAY) > build/lifecycle-bake-no-digest.txt 2>&1; \
		then echo "FAIL: the bake without its digest passed the gate"; cat build/lifecycle-bake-no-digest.txt; exit 1; \
		else grep -q 'transition/bake-digest-required' build/lifecycle-bake-no-digest.txt \
			|| { echo "FAIL: the gate failed without the digest rule"; cat build/lifecycle-bake-no-digest.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 1' build/lifecycle-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/lifecycle-gate.json; exit 1; }
	@grep -q '"verdict": "unreadable"' build/lifecycle-gate.json \
		|| { echo "FAIL: the gate did not render the unreadable verdict"; cat build/lifecycle-gate.json; exit 1; }
	@echo "caught as expected: transition/bake-digest-required — an image nobody can pin to what actually runs"
	@echo "--- 4. a patch with no provenance is caught ---"
	@if $(MAKE) lifecycle-gate LIFECYCLE_RECORD=examples/lifecycle/broken/lifecycle.patch-no-provenance.yaml TODAY=$(ANCHOR_TODAY) > build/lifecycle-patch-no-provenance.txt 2>&1; \
		then echo "FAIL: the patch without provenance passed the gate"; cat build/lifecycle-patch-no-provenance.txt; exit 1; \
		else grep -q 'transition/patch-provenance-required' build/lifecycle-patch-no-provenance.txt \
			|| { echo "FAIL: the gate failed without the provenance rule"; cat build/lifecycle-patch-no-provenance.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 1' build/lifecycle-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/lifecycle-gate.json; exit 1; }
	@grep -q '"verdict": "unreadable"' build/lifecycle-gate.json \
		|| { echo "FAIL: the gate did not render the unreadable verdict"; cat build/lifecycle-gate.json; exit 1; }
	@echo "caught as expected: transition/patch-provenance-required — a change nobody authored"
	@echo "--- 5. an upgrade nobody rehearsed the rollback for is caught ---"
	@if $(MAKE) lifecycle-gate LIFECYCLE_RECORD=examples/lifecycle/broken/lifecycle.upgrade-unrehearsed.yaml TODAY=$(ANCHOR_TODAY) > build/lifecycle-upgrade-unrehearsed.txt 2>&1; \
		then echo "FAIL: the unrehearsed upgrade passed the gate"; cat build/lifecycle-upgrade-unrehearsed.txt; exit 1; \
		else grep -q 'transition/upgrade-rollback-required' build/lifecycle-upgrade-unrehearsed.txt \
			|| { echo "FAIL: the gate failed without the rollback rule"; cat build/lifecycle-upgrade-unrehearsed.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 1' build/lifecycle-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/lifecycle-gate.json; exit 1; }
	@grep -q '"verdict": "unreadable"' build/lifecycle-gate.json \
		|| { echo "FAIL: the gate did not render the unreadable verdict"; cat build/lifecycle-gate.json; exit 1; }
	@echo "caught as expected: transition/upgrade-rollback-required — a way back nobody walked"
	@echo "--- 6. a transition the review never saw is caught ---"
	@if $(MAKE) lifecycle-gate LIFECYCLE_RECORD=examples/lifecycle/broken/lifecycle.unreviewed-transition.yaml TODAY=$(ANCHOR_TODAY) > build/lifecycle-unreviewed.txt 2>&1; \
		then echo "FAIL: the unreviewed transition passed the gate"; cat build/lifecycle-unreviewed.txt; exit 1; \
		else grep -q 'transition/recorded-after-review' build/lifecycle-unreviewed.txt \
			|| { echo "FAIL: the gate failed without the review-coverage rule"; cat build/lifecycle-unreviewed.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 1' build/lifecycle-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/lifecycle-gate.json; exit 1; }
	@grep -q '"verdict": "unreadable"' build/lifecycle-gate.json \
		|| { echo "FAIL: the gate did not render the unreadable verdict"; cat build/lifecycle-gate.json; exit 1; }
	@echo "caught as expected: transition/recorded-after-review — a fact nobody re-checked"
	@echo "--- 7. a transition whose type the gate cannot vouch for is caught ---"
	@if $(MAKE) lifecycle-gate LIFECYCLE_RECORD=examples/lifecycle/broken/lifecycle.type-unknown.yaml TODAY=$(ANCHOR_TODAY) > build/lifecycle-type-unknown.txt 2>&1; \
		then echo "FAIL: the unknown type passed the gate"; cat build/lifecycle-type-unknown.txt; exit 1; \
		else grep -q 'transition/type-unknown' build/lifecycle-type-unknown.txt \
			|| { echo "FAIL: the gate failed without the type rule"; cat build/lifecycle-type-unknown.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 1' build/lifecycle-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/lifecycle-gate.json; exit 1; }
	@grep -q '"verdict": "unreadable"' build/lifecycle-gate.json \
		|| { echo "FAIL: the gate did not render the unreadable verdict"; cat build/lifecycle-gate.json; exit 1; }
	@echo "caught as expected: transition/type-unknown — a fact this gate cannot judge"
	@echo "--- 8. a record nobody has re-read in two years is caught ---"
	@if $(MAKE) lifecycle-gate LIFECYCLE_RECORD=examples/lifecycle/broken/lifecycle.stale-record.yaml TODAY=$(ANCHOR_TODAY) > build/lifecycle-stale.txt 2>&1; \
		then echo "FAIL: the stale record passed the gate"; cat build/lifecycle-stale.txt; exit 1; \
		else grep -q 'lifecycle/reviewed-stale' build/lifecycle-stale.txt \
			|| { echo "FAIL: the gate failed without the staleness rule"; cat build/lifecycle-stale.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 1' build/lifecycle-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/lifecycle-gate.json; exit 1; }
	@grep -q '"verdict": "unreadable"' build/lifecycle-gate.json \
		|| { echo "FAIL: the gate did not render the unreadable verdict"; cat build/lifecycle-gate.json; exit 1; }
	@echo "caught as expected: lifecycle/reviewed-stale, verdict unreadable — a trail nobody still believes"
	@echo "--- 9. a record for a component the manifest never packaged is caught at the join ---"
	@if $(MAKE) lifecycle-gate LIFECYCLE_RECORD=examples/lifecycle/broken/lifecycle.wrong-component.yaml TODAY=$(ANCHOR_TODAY) > build/lifecycle-wrong-component.txt 2>&1; \
		then echo "FAIL: the other component passed the gate"; cat build/lifecycle-wrong-component.txt; exit 1; \
		else grep -q 'gate/component-mismatch' build/lifecycle-wrong-component.txt \
			|| { echo "FAIL: the gate failed without the component rule"; cat build/lifecycle-wrong-component.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 1' build/lifecycle-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/lifecycle-gate.json; exit 1; }
	@grep -q '"verdict": "drifts"' build/lifecycle-gate.json \
		|| { echo "FAIL: the gate did not render the drifts verdict"; cat build/lifecycle-gate.json; exit 1; }
	@jq -e '[.transitions[] | .verdict] | all(. == "drifts")' build/lifecycle-gate.json > /dev/null \
		|| { echo "FAIL: the cards did not render the drift verdict"; cat build/lifecycle-gate.json; exit 1; }
	@echo "caught as expected: gate/component-mismatch — a paper trail answering for somebody else's component"
	@echo "--- lifecycle demo: all done-when proofs passed ---"

# Validate the data contract alone: the enforceable-data-contracts
# chapter's contract-as-data — the schema it is bound to, the
# freshness SLA its consumers may rely on, the quality thresholds
# it must not fall below, the owner who answers for it, the
# consumers who rely on it, the named checks that enforce it in
# CI, and the change methodology that governs its evolution.
# Conformance gate, not advisor: any finding fails.
check-datacontract:
	@test -f "$(DATACONTRACT)" || { echo "usage: make check-datacontract [DATACONTRACT=...] [TODAY=YYYY-MM-DD]"; exit 2; }
	@mkdir -p build
	yq -o=json '.' '$(DATACONTRACT)' \
		| jq -cs --arg today "$(TODAY)" --arg contractFile "$(DATACONTRACT)" '{contract: .[0], today: $$today, contractFile: $$contractFile}' \
		| $(OPA) eval -d policies -I 'data.datacontract.validate' --format=pretty | tee build/check-datacontract.json
	@jq -e '.valid == true' build/check-datacontract.json > /dev/null \
		|| { echo "check-datacontract: the data contract is not in conformance — findings above"; exit 1; }

# Gate the data contract against the enforcement record — the CI's
# word: the checks it actually ran, for one dataset, and the day
# each ran. Conformance gate, not advisor: evidence for a dataset
# the contract never names, a declared check the record never
# shows running, and evidence for a check the contract never
# declared are all refused, not advised.
datacontract-gate:
	@test -f "$(DATACONTRACT)" || { echo "usage: make datacontract-gate [DATACONTRACT=... DATACONTRACT_ENFORCEMENT=...] [TODAY=YYYY-MM-DD]"; exit 2; }
	@mkdir -p build
	yq -o=json '.' '$(DATACONTRACT)' '$(DATACONTRACT_ENFORCEMENT)' \
		| jq -cs --arg today "$(TODAY)" --arg contractFile "$(DATACONTRACT)" --arg enforcementFile "$(DATACONTRACT_ENFORCEMENT)" \
			'{contract: .[0], enforcement: .[1], today: $$today, contractFile: $$contractFile, enforcementFile: $$enforcementFile}' \
		| $(OPA) eval -d policies -I 'data.datacontract.gate' --format=pretty | tee build/datacontract-gate.json
	@jq -e '.valid == true' build/datacontract-gate.json > /dev/null \
		|| { echo "datacontract-gate: the data contract is not in conformance — findings above"; exit 1; }

# The done-when proof for book issue #106: the data contract
# conformance gate refuses. Runs the control pair end to end, then
# proves every broken variant bites exactly once with its named
# rule — five at validation, three at the join — and that each
# bite renders its verdict honestly.
datacontract-demo:
	@echo "--- 1. the data contract validates ---"
	@$(MAKE) check-datacontract TODAY=$(ANCHOR_TODAY)
	@echo "--- 2. the control passes the gate and renders consistent ---"
	@$(MAKE) datacontract-gate TODAY=$(ANCHOR_TODAY)
	@grep -q '"verdict": "consistent"' build/datacontract-gate.json \
		|| { echo "FAIL: the control gate did not render the consistent verdict"; cat build/datacontract-gate.json; exit 1; }
	@jq -e '.cards | length == 3' build/datacontract-gate.json > /dev/null \
		|| { echo "FAIL: the control did not render one card per declared check"; cat build/datacontract-gate.json; exit 1; }
	@echo "control verdict: consistent — the whole board says so, one card per declared check"
	@echo "--- 3. a contract without enforcement evidence is caught at validation ---"
	@if $(MAKE) check-datacontract DATACONTRACT=examples/datacontract/broken/datacontract.no-enforcement.yaml TODAY=$(ANCHOR_TODAY) > build/datacontract-no-enforcement.txt 2>&1; \
		then echo "FAIL: the unenforced contract passed validation"; cat build/datacontract-no-enforcement.txt; exit 1; \
		else grep -q 'enforcement/required' build/datacontract-no-enforcement.txt \
			|| { echo "FAIL: the validator failed without the enforcement rule"; cat build/datacontract-no-enforcement.txt; exit 1; }; \
		fi
	@test $$(jq '[.findings[] | select(.severity == "error")] | length' build/check-datacontract.json) -eq 1 \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/datacontract-no-enforcement.txt; exit 1; }
	@echo "caught as expected: enforcement/required — an unenforced contract is a promise nobody keeps"
	@echo "--- 4. a freshness clause without an SLA is caught at validation ---"
	@if $(MAKE) check-datacontract DATACONTRACT=examples/datacontract/broken/datacontract.freshness-no-sla.yaml TODAY=$(ANCHOR_TODAY) > build/datacontract-freshness.txt 2>&1; \
		then echo "FAIL: the SLA-less freshness clause passed validation"; cat build/datacontract-freshness.txt; exit 1; \
		else grep -q 'freshness/sla-required' build/datacontract-freshness.txt \
			|| { echo "FAIL: the validator failed without the SLA rule"; cat build/datacontract-freshness.txt; exit 1; }; \
		fi
	@test $$(jq '[.findings[] | select(.severity == "error")] | length' build/check-datacontract.json) -eq 1 \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/datacontract-freshness.txt; exit 1; }
	@echo "caught as expected: freshness/sla-required — a promise of freshness with no number to breach"
	@echo "--- 5. an unversioned contract is caught, and the gate refuses to answer ---"
	@if $(MAKE) check-datacontract DATACONTRACT=examples/datacontract/broken/datacontract.unversioned.yaml TODAY=$(ANCHOR_TODAY) > build/datacontract-unversioned.txt 2>&1; \
		then echo "FAIL: the unversioned contract passed validation"; cat build/datacontract-unversioned.txt; exit 1; \
		else grep -q 'contract/version-required' build/datacontract-unversioned.txt \
			|| { echo "FAIL: the validator failed without the version rule"; cat build/datacontract-unversioned.txt; exit 1; }; \
		fi
	@test $$(jq '[.findings[] | select(.severity == "error")] | length' build/check-datacontract.json) -eq 1 \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/datacontract-unversioned.txt; exit 1; }
	@if $(MAKE) datacontract-gate DATACONTRACT=examples/datacontract/broken/datacontract.unversioned.yaml TODAY=$(ANCHOR_TODAY) > build/datacontract-unversioned-gate.txt 2>&1; \
		then echo "FAIL: the unversioned contract passed the gate"; cat build/datacontract-unversioned-gate.txt; exit 1; \
		else grep -q '"verdict": "unreadable"' build/datacontract-unversioned-gate.txt \
			|| { echo "FAIL: the gate did not render the unreadable verdict"; cat build/datacontract-unversioned-gate.txt; exit 1; }; \
		fi
	@echo "caught as expected: contract/version-required, verdict unreadable — a question the gate refuses to answer on a contract it cannot read"
	@echo "--- 6. a check declared twice is caught at validation ---"
	@if $(MAKE) check-datacontract DATACONTRACT=examples/datacontract/broken/datacontract.duplicate-check.yaml TODAY=$(ANCHOR_TODAY) > build/datacontract-duplicate.txt 2>&1; \
		then echo "FAIL: the duplicate check passed validation"; cat build/datacontract-duplicate.txt; exit 1; \
		else grep -q 'check/duplicate' build/datacontract-duplicate.txt \
			|| { echo "FAIL: the validator failed without the duplicate rule"; cat build/datacontract-duplicate.txt; exit 1; }; \
		fi
	@test $$(jq '[.findings[] | select(.severity == "error")] | length' build/check-datacontract.json) -eq 1 \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/datacontract-duplicate.txt; exit 1; }
	@echo "caught as expected: check/duplicate — one check, one row"
	@echo "--- 7. a methodology the validator never modeled is caught at validation ---"
	@if $(MAKE) check-datacontract DATACONTRACT=examples/datacontract/broken/datacontract.methodology-unknown.yaml TODAY=$(ANCHOR_TODAY) > build/datacontract-methodology.txt 2>&1; \
		then echo "FAIL: the unknown methodology passed validation"; cat build/datacontract-methodology.txt; exit 1; \
		else grep -q 'changes/methodology-unknown' build/datacontract-methodology.txt \
			|| { echo "FAIL: the validator failed without the methodology rule"; cat build/datacontract-methodology.txt; exit 1; }; \
		fi
	@test $$(jq '[.findings[] | select(.severity == "error")] | length' build/check-datacontract.json) -eq 1 \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/datacontract-methodology.txt; exit 1; }
	@echo "caught as expected: changes/methodology-unknown — consumers negotiate against a discipline, not against hope"
	@echo "--- 8. a declared check the record never shows running is caught at the join ---"
	@if $(MAKE) datacontract-gate DATACONTRACT_ENFORCEMENT=examples/datacontract/broken/enforcement.check-never-run.yaml TODAY=$(ANCHOR_TODAY) > build/datacontract-never-run.txt 2>&1; \
		then echo "FAIL: the never-run check passed the gate"; cat build/datacontract-never-run.txt; exit 1; \
		else grep -q 'gate/check-never-run' build/datacontract-never-run.txt \
			|| { echo "FAIL: the gate failed without the never-run rule"; cat build/datacontract-never-run.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 1' build/datacontract-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/datacontract-gate.json; exit 1; }
	@grep -q '"verdict": "drifts"' build/datacontract-gate.json \
		|| { echo "FAIL: the gate did not render the drifts verdict"; cat build/datacontract-gate.json; exit 1; }
	@grep -q 'quality-thresholds' build/datacontract-never-run.txt \
		|| { echo "FAIL: the finding does not name the check that never ran"; cat build/datacontract-never-run.txt; exit 1; }
	@echo "caught as expected: gate/check-never-run naming quality-thresholds — enforcement evidence that does not exist"
	@echo "--- 9. evidence for a dataset the contract never names is caught at the join ---"
	@if $(MAKE) datacontract-gate DATACONTRACT_ENFORCEMENT=examples/datacontract/broken/enforcement.wrong-dataset.yaml TODAY=$(ANCHOR_TODAY) > build/datacontract-wrong-dataset.txt 2>&1; \
		then echo "FAIL: the other dataset's evidence passed the gate"; cat build/datacontract-wrong-dataset.txt; exit 1; \
		else grep -q 'gate/dataset-mismatch' build/datacontract-wrong-dataset.txt \
			|| { echo "FAIL: the gate failed without the dataset rule"; cat build/datacontract-wrong-dataset.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 1' build/datacontract-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/datacontract-gate.json; exit 1; }
	@grep -q '"verdict": "drifts"' build/datacontract-gate.json \
		|| { echo "FAIL: the gate did not render the drifts verdict"; cat build/datacontract-gate.json; exit 1; }
	@echo "caught as expected: gate/dataset-mismatch — evidence for somebody else's promises is not evidence here"
	@echo "--- 10. evidence for a check the contract never declared is caught at the join ---"
	@if $(MAKE) datacontract-gate DATACONTRACT_ENFORCEMENT=examples/datacontract/broken/enforcement.extra-check.yaml TODAY=$(ANCHOR_TODAY) > build/datacontract-extra-check.txt 2>&1; \
		then echo "FAIL: the undeclared check's run passed the gate"; cat build/datacontract-extra-check.txt; exit 1; \
		else grep -q 'gate/check-undeclared' build/datacontract-extra-check.txt \
			|| { echo "FAIL: the gate failed without the undeclared rule"; cat build/datacontract-extra-check.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 1' build/datacontract-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/datacontract-gate.json; exit 1; }
	@grep -q '"verdict": "drifts"' build/datacontract-gate.json \
		|| { echo "FAIL: the gate did not render the drifts verdict"; cat build/datacontract-gate.json; exit 1; }
	@echo "caught as expected: gate/check-undeclared — run rows the contract cannot vouch for are logs, not enforcement"
	@echo "--- datacontract demo: all done-when proofs passed ---"


# Validate the identity manifest alone — the platform's
# identities as data: every identity named, every reference
# narrowed to one scope, no wildcards, no duplicate identities,
# every grant dated. The manifest's own completeness, before
# the join.
check-identity:
	@test -f "$(IDENTITY_MANIFEST)" || { echo "usage: make check-identity [IDENTITY_MANIFEST=...] [TODAY=YYYY-MM-DD]"; exit 2; }
	@mkdir -p build
	yq -o=json '.' '$(IDENTITY_MANIFEST)' \
		| jq -cs --arg today "$(TODAY)" --arg manifestFile "$(IDENTITY_MANIFEST)" '{manifest: .[0], today: $$today, manifestFile: $$manifestFile}' \
		| $(OPA) eval -d policies -I 'data.identity.validate' --format=pretty | tee build/check-identity.json
	@jq -e '.valid == true' build/check-identity.json > /dev/null \
		|| { echo "check-identity: the identity manifest is not valid — findings above"; exit 1; }

# Gate the identity manifest against the secrets catalog — the
# platform's word for the secrets that exist, the scope each
# grants, and the rotation clock each must answer to. Scope gate,
# not advisor, deny-by-default: a reference the catalog cannot
# vouch for, an identity the catalog never admitted among a
# secret's consumers, a scope the catalog never wrote, and a
# rotation clock that ran out are all refused, not advised.
identity-gate:
	@test -f "$(IDENTITY_MANIFEST)" || { echo "usage: make identity-gate [IDENTITY_MANIFEST=... IDENTITY_CATALOG=...] [TODAY=YYYY-MM-DD]"; exit 2; }
	@mkdir -p build
	yq -o=json '.' '$(IDENTITY_MANIFEST)' '$(IDENTITY_CATALOG)' \
		| jq -cs --arg today "$(TODAY)" --arg manifestFile "$(IDENTITY_MANIFEST)" --arg catalogFile "$(IDENTITY_CATALOG)" \
			'{manifest: .[0], catalog: .[1], today: $$today, manifestFile: $$manifestFile, catalogFile: $$catalogFile}' \
		| $(OPA) eval -d policies -I 'data.identity.gate' --format=pretty | tee build/identity-gate.json
	@jq -e '.valid == true' build/identity-gate.json > /dev/null \
		|| { echo "identity-gate: the identity manifest is not in conformance — findings above"; exit 1; }

# The done-when proof for book issue #108: the identity and
# secrets scope gate refuses. Runs the control pair end to end,
# then proves every broken variant bites exactly once with its
# named rule — two at validation, five at the join — and that
# each bite renders its verdict honestly.
identity-demo:
	@echo "--- 1. the identity manifest validates ---"
	@$(MAKE) check-identity TODAY=$(ANCHOR_TODAY)
	@echo "--- 2. the control passes the gate and renders consistent ---"
	@$(MAKE) identity-gate TODAY=$(ANCHOR_TODAY)
	@grep -q '"verdict": "consistent"' build/identity-gate.json \
		|| { echo "FAIL: the control gate did not render the consistent verdict"; cat build/identity-gate.json; exit 1; }
	@jq -e '.cards | length == 4' build/identity-gate.json > /dev/null \
		|| { echo "FAIL: the control did not render one card per declared reference"; cat build/identity-gate.json; exit 1; }
	@echo "control verdict: consistent — the whole board says so, one card per declared reference"
	@echo "--- 3. a wildcard scope is caught at validation ---"
	@if $(MAKE) check-identity IDENTITY_MANIFEST=examples/identity/broken/manifest.wildcard-scope.yaml TODAY=$(ANCHOR_TODAY) > build/identity-wildcard.txt 2>&1; \
		then echo "FAIL: the wildcard scope passed validation"; cat build/identity-wildcard.txt; exit 1; \
		else grep -q 'reference/scope-wildcard' build/identity-wildcard.txt \
			|| { echo "FAIL: the validator failed without the wildcard rule"; cat build/identity-wildcard.txt; exit 1; }; \
		fi
	@test $$(jq '[.findings[] | select(.severity == "error")] | length' build/check-identity.json) -eq 1 \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/identity-wildcard.txt; exit 1; }
	@echo "caught as expected: reference/scope-wildcard — a scope that means everything means the platform granted nothing it can name"
	@echo "--- 4. an identity declared twice is caught at validation ---"
	@if $(MAKE) check-identity IDENTITY_MANIFEST=examples/identity/broken/manifest.duplicate-identity.yaml TODAY=$(ANCHOR_TODAY) > build/identity-duplicate.txt 2>&1; \
		then echo "FAIL: the duplicate identity passed validation"; cat build/identity-duplicate.txt; exit 1; \
		else grep -q 'identity/name-duplicate' build/identity-duplicate.txt \
			|| { echo "FAIL: the validator failed without the duplicate rule"; cat build/identity-duplicate.txt; exit 1; }; \
		fi
	@test $$(jq '[.findings[] | select(.severity == "error")] | length' build/check-identity.json) -eq 1 \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/identity-duplicate.txt; exit 1; }
	@echo "caught as expected: identity/name-duplicate — one identity, one row"
	@echo "--- 5. a reference the catalog cannot vouch for is caught at the join ---"
	@if $(MAKE) identity-gate IDENTITY_MANIFEST=examples/identity/broken/manifest.phantom-secret.yaml TODAY=$(ANCHOR_TODAY) > build/identity-phantom.txt 2>&1; \
		then echo "FAIL: the phantom reference passed the gate"; cat build/identity-phantom.txt; exit 1; \
		else grep -q 'gate/reference-unresolved' build/identity-phantom.txt \
			|| { echo "FAIL: the gate failed without the unresolved rule"; cat build/identity-phantom.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 1' build/identity-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/identity-gate.json; exit 1; }
	@grep -q '"verdict": "drifts"' build/identity-gate.json \
		|| { echo "FAIL: the gate did not render the drifts verdict"; cat build/identity-gate.json; exit 1; }
	@grep -q 'integration-webhook-secret' build/identity-phantom.txt \
		|| { echo "FAIL: the finding does not name the secret the catalog never declared"; cat build/identity-phantom.txt; exit 1; }
	@echo "caught as expected: gate/reference-unresolved naming integration-webhook-secret — a secret outside the platform's word"
	@echo "--- 6. an identity the catalog never admitted is caught at the join ---"
	@if $(MAKE) identity-gate IDENTITY_MANIFEST=examples/identity/broken/manifest.undeclared-identity.yaml TODAY=$(ANCHOR_TODAY) > build/identity-undeclared.txt 2>&1; \
		then echo "FAIL: the undeclared identity passed the gate"; cat build/identity-undeclared.txt; exit 1; \
		else grep -q 'gate/identity-undeclared' build/identity-undeclared.txt \
			|| { echo "FAIL: the gate failed without the undeclared rule"; cat build/identity-undeclared.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 1' build/identity-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/identity-gate.json; exit 1; }
	@grep -q '"verdict": "drifts"' build/identity-gate.json \
		|| { echo "FAIL: the gate did not render the drifts verdict"; cat build/identity-gate.json; exit 1; }
	@grep -q 'billing-read-token' build/identity-undeclared.txt \
		|| { echo "FAIL: the finding does not name the token the identity was never granted"; cat build/identity-undeclared.txt; exit 1; }
	@echo "caught as expected: gate/identity-undeclared naming billing-read-token — permission is granted by the catalog, never assumed by the manifest"
	@echo "--- 7. a scope the catalog never wrote is caught at the join ---"
	@if $(MAKE) identity-gate IDENTITY_MANIFEST=examples/identity/broken/manifest.scope-mismatch.yaml TODAY=$(ANCHOR_TODAY) > build/identity-mismatch.txt 2>&1; \
		then echo "FAIL: the ambitious scope passed the gate"; cat build/identity-mismatch.txt; exit 1; \
		else grep -q 'gate/scope-mismatch' build/identity-mismatch.txt \
			|| { echo "FAIL: the gate failed without the mismatch rule"; cat build/identity-mismatch.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 1' build/identity-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/identity-gate.json; exit 1; }
	@grep -q '"verdict": "drifts"' build/identity-gate.json \
		|| { echo "FAIL: the gate did not render the drifts verdict"; cat build/identity-gate.json; exit 1; }
	@grep -q 'payments:refunds' build/identity-mismatch.txt \
		|| { echo "FAIL: the finding does not name the scope the catalog never wrote"; cat build/identity-mismatch.txt; exit 1; }
	@echo "caught as expected: gate/scope-mismatch naming payments:refunds — scope minimality is the catalog's word, not the manifest's ambition"
	@echo "--- 8. a secret with no rotation clock is caught, and the gate refuses to answer ---"
	@if $(MAKE) identity-gate IDENTITY_CATALOG=examples/identity/broken/catalog.no-rotation-clock.yaml TODAY=$(ANCHOR_TODAY) > build/identity-no-clock.txt 2>&1; \
		then echo "FAIL: the clockless secret passed the gate"; cat build/identity-no-clock.txt; exit 1; \
		else grep -q 'secret/rotated-on-required' build/identity-no-clock.txt \
			|| { echo "FAIL: the gate failed without the rotation-clock rule"; cat build/identity-no-clock.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 1' build/identity-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/identity-gate.json; exit 1; }
	@grep -q '"verdict": "unreadable"' build/identity-gate.json \
		|| { echo "FAIL: the gate did not render the unreadable verdict"; cat build/identity-gate.json; exit 1; }
	@grep -q 'billing-read-token' build/identity-no-clock.txt \
		|| { echo "FAIL: the finding does not name the secret with no rotation clock"; cat build/identity-no-clock.txt; exit 1; }
	@echo "caught as expected: secret/rotated-on-required naming billing-read-token, verdict unreadable — a credential the platform holds forever"
	@echo "--- 9. a rotation clock that ran out is caught at the join ---"
	@if $(MAKE) identity-gate IDENTITY_CATALOG=examples/identity/broken/catalog.rotation-overdue.yaml TODAY=$(ANCHOR_TODAY) > build/identity-overdue.txt 2>&1; \
		then echo "FAIL: the overdue clock passed the gate"; cat build/identity-overdue.txt; exit 1; \
		else grep -q 'gate/rotation-overdue' build/identity-overdue.txt \
			|| { echo "FAIL: the gate failed without the overdue rule"; cat build/identity-overdue.txt; exit 1; }; \
		fi
	@jq -e '[.findings[]] | length == 1' build/identity-gate.json > /dev/null \
		|| { echo "FAIL: the variant must bite exactly once"; cat build/identity-gate.json; exit 1; }
	@grep -q '"verdict": "drifts"' build/identity-gate.json \
		|| { echo "FAIL: the gate did not render the drifts verdict"; cat build/identity-gate.json; exit 1; }
	@grep -q 'settlement-signing-key' build/identity-overdue.txt \
		|| { echo "FAIL: the finding does not name the secret past its clock"; cat build/identity-overdue.txt; exit 1; }
	@echo "caught as expected: gate/rotation-overdue naming settlement-signing-key — a credential attackers get extra time with"
	@echo "--- identity demo: all done-when proofs passed ---"


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
	$(MAKE) check-policy TODAY=$(ANCHOR_TODAY)
	$(MAKE) policy-gate TODAY=$(ANCHOR_TODAY)
	$(MAKE) check-compliance TODAY=$(ANCHOR_TODAY)
	$(MAKE) compliance-gate TODAY=$(ANCHOR_TODAY)
	$(MAKE) check-broker TODAY=$(ANCHOR_TODAY)
	$(MAKE) broker-gate TODAY=$(ANCHOR_TODAY)
	$(MAKE) check-lifecycle TODAY=$(ANCHOR_TODAY)
	$(MAKE) lifecycle-gate TODAY=$(ANCHOR_TODAY)
	$(MAKE) check-datacontract TODAY=$(ANCHOR_TODAY)
	$(MAKE) datacontract-gate TODAY=$(ANCHOR_TODAY)
	$(MAKE) check-identity TODAY=$(ANCHOR_TODAY)
	$(MAKE) identity-gate TODAY=$(ANCHOR_TODAY)

# Everything CI runs, in order.
ci: check test examples e2e obs-demo alerts-demo actions-demo erasure-demo segment-demo ingress-demo citizen-demo component-demo matrix-demo policy-demo compliance-demo broker-demo lifecycle-demo datacontract-demo identity-demo
	$(OPA) fmt --fail -l policies
