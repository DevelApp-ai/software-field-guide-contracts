# software-field-guide-contracts

Contract validators for **The Software Field Guide** (DevelApp-ai/software-field-guide). This repo implements the estate and seam contract validator from the chapter **“Segmenting the Estate”** ([book issue #57](https://github.com/DevelApp-ai/software-field-guide/issues/57)): the chapter tells you which answers an enclave and a seam contract must record; this repo checks that you actually recorded them — in CI, in the browser, or on the command line.

It also implements the **authorization policy compiler** from [book issue #59](https://github.com/DevelApp-ai/software-field-guide/issues/59): one versioned policy set answers who can do what, explains every 403 with a named trace, proves the kill switch fails closed, and doubles as a retrospective audit substrate.

And it implements the **observability vocabulary and cardinality linter** from [book issue #61](https://github.com/DevelApp-ai/software-field-guide/issues/61): telemetry names and labels are versioned contracts, a scanner lints instrumentation code against them, and a cardinality gate catches the label that breeds a metrics budget breach — citing the budget file it breaches.

And it implements the **alert-to-record linkage gate** from [book issue #69](https://github.com/DevelApp-ai/software-field-guide/issues/69): alert rules are a versioned contract (a severity ladder with dated rungs, runbooks with escalation clocks, owners, and record destinations), and the gate answers the incident-to-action question — every fired alert must be claimed by a record in the incident register, or it pages nobody.

And it implements the **action scope validator** from [book issue #70](https://github.com/DevelApp-ai/software-field-guide/issues/70): the micro-action vocabulary is a versioned registry — named, typed, parameter-checked actions with execution envelopes under platform ceilings — and an agent permission manifest is judged against it, default-deny: no phantom grants, no scopes on undeclared parameters, no stage that contradicts the effects it grants, no Critical action that no longer asks before it acts.

And it implements the **deletion evidence validator** from [book issue #79](https://github.com/DevelApp-ai/software-field-guide/issues/79): a per-tenant right-to-be-forgotten case is judged against the DEK registry and its own sweep records — every store in the inventory swept, aged out by a declared backup window, or honestly pending; the tenant's keys destroyed with their evidence records; nothing is forgotten without a record.

And it implements the **segment render-consistency and flow-evidence gate** from [book issue #80](https://github.com/DevelApp-ai/software-field-guide/issues/80): one segment contract, rendered to N fabrics — and a gate that proves every fabric rendered every rule, no fabric rendered a rule the contract never had, and no audit rule was promoted to enforce without the flow evidence its PR cites. A rule is not enforced until every fabric says so; promotion is evidence, not assertion.

And it implements the **ingress hardening conformance validator** from [book issue #82](https://github.com/DevelApp-ai/software-field-guide/issues/82): the edge's posture as data — the DNS containment boundary, default-deny, the allowed domain patterns held inside the zone, certificate rotation clocks, SLOs with pagers behind them, audited route classes, and the kill path the platform swears it can pull — judged against a drill record. A wildcard is contained or it is too broad; an expired certificate is exposed; a kill path declared but never rehearsed fails the gate.

And it implements the **citizen spec-rails conformance linter** from [book issue #84](https://github.com/DevelApp-ai/software-field-guide/issues/84): the citizen-built app as data — a manifest judged at the citizen's own PR gate against the app's spec (the rails it grants and the behaviors its coverage declares) and the platform guardrail registry (the rails a binding may ride and the floor each guardrail must meet). An escape hatch, an action outside the rails, a behavior without coverage, a guardrail below the floor: all advised, never blocked — the gate stays green with the advice on the record. A document the advisor cannot read is the one red it can show.

And it implements the **component package conformance validator** from [book issue #101](https://github.com/DevelApp-ai/software-field-guide/issues/101): the component package as data — its name, version, and tier, the sha256 artifact digest it publishes, the signature and attestation recorded over that digest, its provenance, and the dependencies it pins by digest — judged at the package's own release gate against the component registry (the estate's admitted packages). An unregistered package, an artifact drifted from its registration, an unresolved dependency, a stale pin, a customer-tier package depending downward: all refused — a conformance gate, not an advisor, and the package does not ship until the drift is fixed. The validator is honest about what it models: it checks the evidence facts are recorded and internally consistent, not that signatures are cryptographically valid.

And it implements the **render-matrix consistency gate** from [book issue #102](https://github.com/DevelApp-ai/software-field-guide/issues/102): one component package, rendered to N fabrics — and a gate that proves every fabric renders the manifest's version, its pinned digest, and every policy binding it declares, no fabric quietly running a different release and no fabric enforcing a policy the package never shipped. A component is not deployed until every declared fabric agrees.

And it implements the **compliance controls-as-data gate** from [book issue #107](https://github.com/DevelApp-ai/software-field-guide/issues/107): the estate's compliance obligations and the controls that satisfy them, both as documents — a **requirements catalog** declaring every obligation by id, and a **controls manifest** declaring the named evidence sources and every control that maps onto a requirement, cites one of those sources, and carries its own review clock. The gate joins the two both ways: a requirement no control maps to, a control citing a requirement the catalog never declared, a control pointing at evidence the manifest retired, and a control whose review clock has lapsed are all refused — a conformance gate, not an advisor, and a requirement is not believed covered until a sound control backs it.

Everything is [Open Policy Agent](https://www.openpolicyagent.org/) Rego, compiled from the same source:

| Entry point | Judges | Input |
| --- | --- | --- |
| `estate.enclave` | one enclave contract | `{"contract": {...}, "today": "YYYY-MM-DD"}` |
| `estate.seam` | one seam contract | `{"contract": {...}, "today": "YYYY-MM-DD"}` |
| `estate.cross` | the estate as a whole | `{"enclaves": [...], "seams": [...]}` |
| `authz/validate` | one authorization policy set | `{"policySet": {...}, "today": "YYYY-MM-DD"}` |
| `authz/decide` | one request against the set | `{"request": {...}, "policySet": {...}}` |
| `authz/who_could_access` | who could touch a resource in a window | `{"resource": "...", "window": {"from": "...", "to": "..."}, "policySet": {...}}` |
| `authz/disabled_check` | the set with `disabled: true` overlaid | `{"policySet": {...}}` |
| `obs/validate` | the three observability contracts together | `{"vocabulary": {...}, "labels": {...}, "budget": {...}, "today": "YYYY-MM-DD"}` |
| `obs/lint` | an instrumentation scan against both vocabularies | `{"vocabulary": {...}, "labels": {...}, "scan": {...}}` |
| `obs/gate` | a metrics export against the cardinality budget | `{"labels": {...}, "budget": {...}, "observations": [...], "budgetFile": "..."}` |
| `obs/audit` | all three at once — one verdict, one findings list | the superset of the above (plus `"today"`) |
| `alerts/validate` | one alerting contract alone | `{"alerting": {...}, "today": "YYYY-MM-DD"}` |
| `alerts/gate` | an incident register against the alerting contract | `{"alerting": {...}, "register": {...}, "today": "YYYY-MM-DD"}` |
| `alerts/audit` | both at once — one verdict, one findings list, one linkage map | the superset of the above |
| `actions/validate` | one action registry | `{"registry": {...}, "today": "YYYY-MM-DD"}` |
| `actions/gate` | an agent manifest against the registry | `{"registry": {...}, "manifest": {...}, "today": "YYYY-MM-DD"}` |
| `actions/audit` | both at once — one verdict, the per-agent scoping | the superset of the above |
| `erasure/validate` | one DEK registry | `{"keys": {...}, "today": "YYYY-MM-DD"}` |
| `erasure/gate` | an erasure case against the DEK registry | `{"keys": {...}, "case": {...}, "today": "YYYY-MM-DD"}` |
| `erasure/audit` | both at once — one verdict, the per-store evidence | the superset of the above |
| `segment/validate` | one segment contract alone | `{"contract": {...}, "today": "YYYY-MM-DD"}` |
| `segment/gate` | fabric renders, flow evidence, and a promotion PR against the contract | `{"contract": {...}, "renders": {...}, "flows": {...}, "promotion": {...}, "today": "YYYY-MM-DD"}` |
| `segment/audit` | all of it at once — one verdict, the per-rule cards | the superset of the above |
| `ingress/validate` | one ingress posture case alone | `{"case": {...}, "today": "YYYY-MM-DD"}` |
| `ingress/gate` | a drill record against the posture case | `{"case": {...}, "drill": {...}, "today": "YYYY-MM-DD"}` |
| `ingress/audit` | both at once — one verdict, the posture cards | the superset of the above |
| `citizen/validate` | one citizen app manifest alone | `{"manifest": {...}, "today": "YYYY-MM-DD"}` |
| `citizen/gate` | the app's spec and the platform guardrail registry against the manifest | `{"manifest": {...}, "spec": {...}, "registry": {...}, "today": "YYYY-MM-DD"}` |
| `citizen/audit` | all of it at once — one verdict, the advice cards | the superset of the above |
| `component/validate` | one component package manifest alone | `{"package": {...}, "today": "YYYY-MM-DD"}` |
| `component/gate` | the component registry against the manifest | `{"package": {...}, "registry": {...}, "today": "YYYY-MM-DD"}` |
| `component/audit` | all of it at once — one verdict, the conformance cards | the superset of the above |
| `matrix/validate` | one render matrix alone | `{"matrix": {...}, "today": "YYYY-MM-DD"}` |
| `matrix/gate` | the fabric renders against the component package manifest | `{"package": {...}, "matrix": {...}, "today": "YYYY-MM-DD"}` |
| `matrix/audit` | all of it at once — one verdict, the fabric cards | the superset of the above |
| `compliance/validate` | one controls manifest alone | `{"controls": {...}, "today": "YYYY-MM-DD"}` |
| `compliance/gate` | the requirements catalog against the controls manifest | `{"controls": {...}, "requirements": {...}, "today": "YYYY-MM-DD"}` |
| `compliance/audit` | all of it at once — one verdict, the requirement cards | the superset of the above |

The same policies run in CI (native OPA), on the command line, and in the browser playground (compiled to WebAssembly) — one source of truth, no drift between what CI accepts and what the playground says.

Status: **v1.0** — the estate/seam formats, the authorization compiler, the observability linter, the action scope validator, the alert-to-record gate, the deletion evidence validator, the segment render-consistency gate, the ingress hardening conformance validator, the citizen spec-rails conformance linter, the component package conformance validator, the render-matrix consistency gate, and the compliance controls-as-data gate work; thresholds and rule names may still sharpen as the book’s companion tools grow (see the book’s issue #53 roadmap).

## The contracts

### Enclave contract — four answers plus a review date

```yaml
enclave: checkout
owner: Checkout team
trustedIdentityPlanes:        # at least one
  - plane: customer-web
    provider: opaque-token
borderInventory:             # at least one seam name
  - checkout-web-tier
blastRadius:
  data: Cart contents and customer profile cache
  statedLimit: Cart rows for one storefront, one hour
reviewedOn: 2026-09-15
```

### Seam contract — six answers plus a rehearsal date

```yaml
seam: checkout-web-tier
enclave: checkout
entry: >-                  # how traffic and identity arrive
  Internet-facing endpoint behind the edge gateway; mTLS terminates at the
  gateway and requests continue with a forwarded identity token.
decision: Default deny at the gateway; each route is an explicit allow.
monitoring: >-             # how you watch the seam
  Gateway access logs, p99 latency metric, alert on 5xx rate.
blastRadius: A spoofed session can read one customer's cart
killPath: Drop the gateway route; the edge fails closed
lastRehearsed: 2026-08-30
reviewDate: 2026-12-01
```

See [schemas/](schemas/) for JSON Schema versions of all three formats and [examples/](examples/) for complete, valid examples.

### What the validator judges

- **Errors** (contract is `valid: false`): missing or empty required fields, malformed dates, enclaves or seams that go unnamed twice, seams pointing at enclaves that do not exist, border inventory entries with no seam contract behind them, and contracts that have gone stale — `reviewedOn` older than **365 days**, `lastRehearsed` older than **180 days**, `reviewDate` already in the past.
- **Warnings** (contract stays `valid: true`): an `entry` that names no identity mechanism (auth, mTLS, SVID, token, identity), a `decision` that states no deny rule, `monitoring` that names no observation (log, metric, alert, monitor), and a seam contract no enclave claims in its border inventory.

Every finding carries a severity, a rule name, a message, and a path back into the document:

```json
{
  "valid": false,
  "findings": [
    {
      "severity": "error",
      "rule": "contract/reviewed-stale",
      "message": "reviewedOn is more than 365 days before today: this enclave contract is stale",
      "path": "$.contract.reviewedOn"
    }
  ]
}
```

## The authorization compiler

Where the contract validators judge documents, the authorization compiler judges *decisions*: it turns one versioned policy set into four provable answers — who may do what today, why a request was denied, what the kill switch does, and who could touch something last quarter.

### The policy set — an audit substrate, not a config file

```yaml
name: storefront
currentVersion: 3        # answers today; explicit, never the clock
subjects:                # who can appear in a rule
  - id: bob
    roles: [checkout-clerk]
    flags: [mfa-verified]
versions:                # rule history: unique numbers, non-overlapping windows
  - version: 3
    effectiveFrom: 2026-09-01
    rules:
      - id: clerk-charge-mfa
        effect: allow
        subject: {role: checkout-clerk}
        action: order.charge
        resource: orders-*
        condition: {mfa: true}   # equality on scalars only
      - id: offboarded-deny
        effect: deny
        subject: {flag: offboarded}
        action: "*"
        resource: "*"
probes:                  # requests the current version must answer as promised
  - id: clerk-charge-without-mfa
    subject: carol
    action: order.charge
    resource: orders-1041
    context: {mfa: false}
    expect: deny
```

See [examples/authz/storefront.yaml](examples/authz/storefront.yaml) for the full example and [schemas/authz-policy.schema.json](schemas/authz-policy.schema.json) for the shape.

### What the compiler enforces and proves

- **Loud validation with rule names** (`authz/validate`): missing or malformed fields, duplicate subject or rule ids, selectors that don’t name exactly one of `id`/`role`/`flag`, wildcards that aren’t trailing-`*`, overlapping version windows, a `currentVersion` that doesn’t exist or isn’t in effect — and every probe’s expectation replayed against the current version, so the set can’t claim to allow what it actually denies.
- **A 403 that explains itself** (`authz/decide`): deny beats allow, nothing matching is default deny, and every failure mode fails closed under its own named rule (`policy/default-deny`, `policy/disabled-fail-closed`, `policy/version-missing-fail-closed`, `policy/invalid-fail-closed`). The trace is deterministic — same request and set, same numbered steps — and names the criterion each non-firing rule failed on.
- **Deny, not silent permit, when disabled** (`authz/disabled_check`): the target list is generated from the set’s own probes, then every probe is run against the set with `disabled: true` overlaid — the proof fails unless each answer is `deny` by `policy/disabled-fail-closed`.
- **Who could have touched this** (`authz/who_could_access`): a retrospective question answered from the version history — allow grants in any version overlapping the window, minus same-version deny exclusions — so “who could read order-1041 in Q1?” is a query, not an archaeology project.

The CLI answers one real 403 from the tool alone:

```sh
make explain-authz FILE=examples/authz/storefront.yaml \
     SUBJECT=bob ACTION=order.charge RESOURCE=orders-1041 CONTEXT='{"mfa": false}'
# → deny, and the trace names the unmet condition:
#   "condition context.mfa=true is not met (context has mfa=false)" (rule clerk-charge-mfa)

make authz-disabled FILE=examples/authz/storefront.yaml
# → all 6 probes deny by policy/disabled-fail-closed

make who-could-access FILE=examples/authz/storefront.yaml RESOURCE=orders-1041 FROM=2026-01-01 TO=2026-12-31
```

## The observability linter

Where the authorization compiler judges decisions, the observability linter judges *telemetry shape*: which event names exist, which labels a metric may carry, and how many distinct values each label may take — all three written down as versioned contracts before the cardinality bill arrives.

### Three contracts, one vocabulary of telemetry

```yaml
# vocabulary.yaml — event names are a versioned fact, not folklore
version: 1
reviewedOn: 2026-10-01
events:
  - {name: order.placed, description: An order was accepted and awaits settlement}

# label-schema.yaml — a metric's labels are declared, reviewed, and bounded
version: 1
reviewedOn: 2026-10-01
metrics:
  - name: storefront_requests_total
    description: Storefront HTTP requests
    labels: [method, route, status]

# cardinality-budget.yaml — per-label allocations and a per-metric total
owner: Storefront team
reviewedOn: 2026-10-01
metrics:
  - name: storefront_requests_total
    total: 4000
    allocations:
      - {label: method, maxValues: 2}
      - {label: route, maxValues: 2}
      - {label: status, maxValues: 100}
```

See [examples/observability/](examples/observability/) for complete examples and [schemas/](schemas/) for the three JSON Schema drafts. Note what is where: high-cardinality facts (order ids) ride in event payloads, never in labels — the vocabulary governs names, the schema governs labels.

### What the linter enforces and proves

- **Loud validation of the contracts** (`obs/validate`): missing fields, unversioned documents, stale review stamps, duplicate names, budget metrics the label schema doesn’t declare, allocations for labels the schema doesn’t declare, and a static check that the product of allocation maxima stays under the metric’s total.
- **Instrumentation linting at PR time** (`obs/lint`): [scan/scan_instrumentation.py](scan/scan_instrumentation.py) extracts every `telemetry.event(...)` and `telemetry.metric(...)` call from source (file, line, kind, name, labels) and the policies flag every undeclared event name, undeclared metric, and undeclared label — citing the file and line that introduced it.
- **The cardinality gate** (`obs/gate`): a metrics export (observed distinct values per metric+label) is judged against the budget three ways — a label observed past its allocation, a label observed with no allocation at all, and the honest product of observed distinct values past the metric total. Every budget finding cites the budget file it breaches.
- **One audit** (`obs/audit`): the composed entrypoint for CI and the playground — contracts validated, scan linted, export gated, one verdict, the per-metric cardinalities alongside.

The done-when proof from book issue #61 — a budget-breeding label caught with the budget file cited — runs as a single target:

```sh
make obs-demo
# → 1. the three contracts validate
#   2. the demo instrumentation lints clean
#   3. the demo export passes the cardinality gate
#   4. an undeclared label in code is caught at PR time:
#      lint/label-undeclared — "label 'order_id' on metric
#      'storefront_requests_total' emitted at storefront.undeclared.py:11
#      is not in the metric's label schema (method, route, status)"
#   5. an over-budget label breaches the gate, budget file cited:
#      budget/label-over-allocation — "label 'order_id' … shows 1204
#      distinct values in the metrics export; the cardinality budget
#      allocates 50 (cardinality-budget.with-order-id.yaml)"
#      budget/metric-total-exceeded — "metric 'storefront_requests_total'
#      multiplies observed distinct values to 178192 label combinations;
#      the cardinality budget total is 4000 (cardinality-budget.with-order-id.yaml)"
```

## The alert-to-record linkage gate

Where the observability linter judges telemetry shape, the alert gate judges the **incident-to-action loop**: an alert that fires and lands in no record is a page nobody answered, and a postmortem action nobody verified closed is a promise nobody kept. Both the alerting contract and the incident register are versioned, owned, reviewed documents — like the budget and the policy set before them.

### The alerting contract and the register

```yaml
# alerting.yaml — alert rules are versioned, like code
version: 1
reviewedOn: 2026-10-01
severityLadder:            # each rung is dated: defined before it fires
  - {name: sev-3, description: Low-impact degradation, definedOn: 2026-01-15}
  - {name: sev-2, description: A customer-visible promise is degraded, definedOn: 2026-01-15}
  - {name: sev-1, description: Estate-wide incident, definedOn: 2026-06-01}
runbooks:                  # each runbook carries its escalation clock
  - id: rb-storefront-5xx
    link: https://example/runbooks/storefront-5xx.md
    escalationClock: Acknowledge in 15 minutes; escalate to the storefront on-call lead at 60
alerts:                   # every alert has an owner, a rung, a runbook, and a destination
  - {id: storefront-5xx-rate, owner: Storefront team, severity: sev-2,
     runbook: rb-storefront-5xx, recordDestination: register.yaml}

# register.yaml — the incident register is owned and reviewed, like the budget
owner: Storefront team
reviewedOn: 2026-10-19
firedAlerts:              # what actually fired
  - {alert: storefront-5xx-rate, firedOn: 2026-09-30}
incidents:                # what the fires landed in
  - id: INC-2026-038
    detectedOn: 2026-09-30
    severity: sev-1
    record: INC-2026-038 in the incident register
    alerts: [storefront-5xx-rate]
    postmortem:           # every action closed AND verified
      - {id: act-038-1, action: Remove order_id from the labels,
         closedOn: 2026-10-11, verifiedBy: "PR #2141 merged; the export shows no order_id label"}
```

See [examples/alerting/](examples/alerting/) for the complete example pair and [schemas/](schemas/) for the two JSON Schema drafts.

### What the gate enforces and proves

- **Contract validation** (`alerts/validate`): a versioned, reviewed alerting document; a severity ladder of dated, described, uniquely named rungs; runbooks with links and escalation clocks; alert rules with owners, on-ladder severities, known runbooks, and a record destination. A runbook no alert references is a warning, not an error — it may be a runbook waiting for its alert.
- **Alert-to-record linkage** (`alerts/gate`): every alert that fired must be claimed by an incident — `alerts/no-record-linkage` names the alert that landed in no record. The result carries a linkage map, one row per distinct fired alert: the alert and the record it landed in, or no record.
- **Severity honesty** (`alerts/gate`): an incident's severity must be a rung on the ladder (`gate/severity-off-ladder`), and a rung only counts if it was defined *before* the incident was detected (`gate/severity-defined-after-detection`) — you cannot file an incident as sev-1 when sev-1 was invented after the fire.
- **Closure verification** (`alerts/gate`): every postmortem action is closed on a real date *and* verified by named evidence (`gate/action-unverified`). An empty postmortem is honest — an open incident is still being worked — the gate verifies the actions that exist, it does not demand a postmortem on day one.
- **Owned and re-read** (both): the register carries an owner and a `reviewedOn` stamp within 365 days, like every other owned document in this repo.

The done-when proof from book issue #69 — an unlinked alert caught by construction — runs as a single target:

```sh
make alerts-demo
# → 1. the alerting contract validates
#   2. the seeded register passes the alert-to-record gate
#   3. a runbook without its escalation clock is caught at contract time:
#      runbook/escalation-clock-required
#   4. an alert that fired without a record is caught:
#      alerts/no-record-linkage — "alert 'storefront-latency' fired on
#      2026-10-15 but links to no record in the incident register:
#      nothing pages without creating a record"
#   5. a severity off the ladder is caught: gate/severity-off-ladder
#   6. a severity defined after the incident is caught:
#      gate/severity-defined-after-detection
#   7. a postmortem action without closure verification is caught:
#      gate/action-unverified
```

## The action scope validator

Where the authorization compiler judges *people*, the action scope validator judges *agents*: the micro-actions an AI agent may perform are a versioned vocabulary, and the manifest that grants them is judged against it, default-deny. A grant for an action the registry never declared is a hope wearing a permission's clothes — the validator catches it at PR time.

### Two documents, one judgment

```yaml
# registry.yaml — the vocabulary: named, typed, parameter-checked actions
version: 1
reviewedOn: 2026-10-01
platformCeilings: {maxTimeoutSeconds: 600, maxMemoryMB: 2048}
servers:
  - {name: invoice-service, approved: true}
actions:
  - id: send-invoice-email
    name: Send invoice email
    description: Send one invoice to one recipient through the registered invoice service
    type: ExternalServer
    parameters:
      - {name: invoiceId, type: string, validation: {minLength: 1}}
    outputs: {messageId: string}
    envelope: {timeoutSeconds: 60, maxMemoryMB: 256, useIsolation: false}
    securityLevel: Critical
    confirmation: confirm
    effect: write
    server: {name: invoice-service, operation: sendInvoiceEmail,
             mappings: {invoiceId: invoiceId, recipient: recipient}}

# manifest.yaml — the claim: agents on the autonomy ladder, granted from
# the registry above, every argument scoped
owner: Billing team
reviewedOn: 2026-10-15
agents:
  - agent: archive-reader
    stage: read-only
    grants:
      - action: fetch-invoice
        argumentScopes:
          - {parameter: invoiceId, pattern: "INV-2026-*"}
```

See [examples/actions/](examples/actions/) for the complete pair and [schemas/](schemas/) for the two JSON Schema drafts. Note what is where: the registry owns the vocabulary and its envelopes; the manifest owns only claims, and every claim is judged against the registry.

### What the validator enforces and proves

- **Loud validation of the registry** (`actions/validate`): missing fields, unversioned documents, stale review stamps, duplicate ids, and the anatomy rules — parameters with known types *and* validation objects (an untyped parameter cannot be checked, only stringly-trusted; `enumValues`, when declared, a non-empty array), outputs declared, envelopes inside the platform ceilings and demanding isolation for scripted types, confirmation pinned to the severity classification (a High or Critical action must demand `confirm`, never `auto-confirm`), and external calls naming an operation on a registered, approved server with a mapping for every parameter.
- **The manifest gate** (`actions/gate`): every grant names a registry-declared action (a phantom grant fails), every argument scope names a parameter the granted action actually declares, no stage contradicts the effects it grants (a read-only agent holds no write; a quarantined agent holds nothing), and the owner and review stamp are present and honest.
- **One audit** (`actions/audit`): the composed entrypoint for CI and the playground — registry validated, manifest gated, one verdict, and the per-agent scoping alongside: each agent, its stage, and the actions it may perform.

The done-when proof from book issue #70 — a phantom grant caught with the agent and the undeclared action cited — runs as a single target:

```sh
make actions-demo
# → 1. the action registry validates
#   2. the seeded manifest passes the action scope gate
#   3. an untyped parameter is caught at contract time:
#      action/parameter-untyped — naming invoiceId
#   4. an envelope that exceeds the platform ceiling is caught:
#      envelope/exceeds-ceiling — naming compile-quarterly-report
#   5. a Critical action that no longer asks is caught:
#      action/confirm-required-at-level — naming send-invoice-email
#   6. a grant for an action the registry never declared is caught:
#      manifest/action-unknown — naming purge-invoice-archive
#   7. a read-only agent granted a write is caught:
#      manifest/stage-contradiction — naming archive-reader
```

## The deletion evidence validator

The right to be forgotten is evidence, not an assertion ([book issue #79](https://github.com/DevelApp-ai/software-field-guide/issues/79)). Two documents enter: the **DEK registry** — the per-tenant data-encryption-key table, where a destroyed key carries the day it died and what destroyed it — and the **erasure case** — the per-tenant record of the request that opened it, the storage inventory, the sweep records, and the backup windows still open. Key destruction is the book's strongest verified deletion primitive; the case is the evidence that every other copy followed the key into the dark.

```yaml
# keys.yaml — the registry: a destruction without its evidence record
# is a deletion asserted, not evidenced
version: 1
reviewedOn: 2026-10-01
keys:
  - {dek: tenant-acme-dek-004, tenant: tenant-acme, state: destroyed,
     destroyedAt: 2026-10-02,
     destroyedBy: "KMS DestroyKey in change CHG-4471; key material unrecoverable, cf. runbook RB-014"}
  - {dek: tenant-initech-dek-001, tenant: tenant-initech, state: active}

# case-forgotten.yaml — the per-tenant evidence: request, inventory,
# sweep records, backup windows
owner: Platform team
reviewedOn: 2026-10-19
tenant: tenant-acme
requestedOn: 2026-10-01
requestedBy: "DSR-2026-041 (tenant offboarding erasure request)"
status: closed
stores:
  - {name: postgres-primary, kind: primary}
  - {name: postgres-replica-eu, kind: replica}
  - {name: corpus-vector-index, kind: vector-store}
  - {name: nightly-backups, kind: backup, expiresOn: 2026-10-15}
sweeps:
  - {store: postgres-primary, sweptOn: 2026-10-02,
     sweptBy: "DELETE cascade from the tenant row; 412 rows removed, count verified by the tenant-id scan"}
  - {store: postgres-replica-eu, sweptOn: 2026-10-03,
     sweptBy: "replica catch-up confirmed; the tenant-id scan returns zero rows on the replica"}
```

See [examples/erasure/](examples/erasure/) for the complete pair (the destroyed-DEK control and the unexpired-backup pending case) and [schemas/](schemas/) for the two JSON Schema drafts. Note what is where: the registry owns the crypto-erasure primitive; the case owns the evidence that everything else followed — and every claim in the case is judged against the registry.

### What the validator enforces and proves

- **Loud validation of the registry** (`erasure/validate`): missing fields, unversioned documents, stale review stamps, duplicate deks, states limited to `active`/`destroyed`, destruction dates real and not in the future — and the evidence rules: a destroyed key without its `destroyedBy` record is a deletion asserted, not evidenced; an active key with destruction evidence attached is a registry contradicting itself.
- **The case gate** (`erasure/gate`): every store in the inventory is swept (`sweep/store-unswept` — nothing is forgotten without a record), an aged-out backup (`expired`), or honestly pending (an open window or an explicit `pendingReason`); backups declare their expiry windows; sweep records postdate the request, predate the clock, and cover declared stores only; the tenant is registered (`keys/tenant-unregistered`) with every key destroyed (`keys/dek-not-destroyed` — with the key alive the ciphertext is readable); a case closed while a store can still produce the data fails (`case/closed-early`), and a case left open with no remaining work earns the `case/closable` warning. An empty inventory is itself a finding — the gate can only judge the stores the case declares.
- **One audit** (`erasure/audit`): the composed entrypoint for CI and the playground — registry validated, case gated, one verdict (`forgotten`, `pending, honest`, or `incomplete`), and the per-store evidence alongside: each store swept, expired, pending, or unswept, with the record that resolved it.

The done-when proof from book issue #79 — a replica without its sweep record caught citing the store — runs as a single target:

```sh
make erasure-demo
# → 1. the DEK registry validates
#   2. the destroyed-DEK control passes and renders forgotten
#   3. the unexpired-backup case renders pending, honest and stays open
#   4. a replica without its sweep record is caught citing the store:
#      sweep/store-unswept — naming postgres-replica-eu
#   5. a case closed while a backup window is still open is caught:
#      case/closed-early
#   6. a tenant whose key the registry still holds live is caught:
#      keys/dek-not-destroyed
#   7. a sweep dated before the erasure request is caught:
#      sweep/before-request
#   8. a case for a tenant the registry never listed is caught:
#      keys/tenant-unregistered
#   9. a backup without its expiry window is caught:
#      store/backup-expiry-required
#  10. a destroyed key without its evidence record is caught at registry time:
#      key/destroyed-by-required
```

## The segment render-consistency and flow-evidence gate

One contract, N fabrics, promotion by evidence. The chapter's microsegmentation YAML becomes a **segment contract** — the segments of the estate and the named rules between them, each with its direction, type, and port inside the modeled subset (`ingress`/`egress`, `tcp`/`udp` — the gate is honest about what it models, not pretending to full eBPF or CIL semantics), its mode (`audit` or `enforce`), and TTL-bound exceptions that carry their reason and the date they expire. Every fabric renders the same contract, and the gate verifies every join both ways:

```yaml
# contract.yaml — the segments and the rules between them
version: 1
reviewedOn: 2026-10-01
owner: Platform team
segments: [web, api, db, worker, external]
rules:
  - {id: R1, from: web, to: api, type: tcp, port: 443, direction: egress, mode: enforce}
  - {id: R3, from: worker, to: api, type: tcp, port: 443, direction: egress, mode: audit}
  - id: R4
    from: external
    to: web
    type: tcp
    port: 443
    direction: ingress
    mode: enforce
    exceptions:
      - reason: pen-test window — the load generator's traffic is expected until the contract is re-rendered
        expiresOn: 2026-12-01

# renders.yaml — one row per contract rule per fabric, citing the rule id
version: 1
reviewedOn: 2026-10-18
fabrics: [cloud, host-firewall]
rules:
  - {fabric: cloud, rule: R1, direction: egress, type: tcp, port: 443}
  - {fabric: host-firewall, rule: R1, direction: egress, type: tcp, port: 443}
  # … R2, R3, R4 on both fabrics

# flows.yaml — the observed flows of the window, aggregated per tuple
reviewedOn: 2026-10-16
window: {from: 2026-10-01, to: 2026-10-15}
flows:
  - {from: worker, to: api, type: tcp, port: 443, count: 14}

# promotion.yaml — the PR moving an audit rule to enforce, citing its evidence
pr: PR-512
rule: R3
to: enforce
evidenceFile: flows.yaml
window: {from: 2026-10-01, to: 2026-10-15}
```

See [examples/segment/](examples/segment/) for the complete control and the eight broken variants, and [schemas/](schemas/) for the four JSON Schema drafts. The estate, the renders, and the flows are seeded after the chapter's example estate — labeled as seeded, because pretending to a real estate's policy history would be dishonest.

### What the gate enforces and proofs

- **Loud validation of the contract** (`segment/validate`): missing fields, unversioned documents, stale review stamps, duplicate rule ids, rules between undeclared segments (`rule/segment-undeclared`), unknown directions, types, ports, and modes — and the exception rules: an exception without a reason or an expiry is not an exception, it is the rule; an expired exception is caught by the injected clock (`exception/ttl-expired`).
- **The render-consistency gate** (`segment/gate`): every contract rule appears once per declared fabric (`render/rule-missing`, citing both the contract file and the renders file), no render carries a rule the contract never had (`render/rule-unknown`), the modeled subset agrees (`render/direction-mismatch`, `render/type-mismatch`, `render/port-mismatch`), no fabric renders the same rule twice, and every fabric in a render row is declared.
- **Promotion by evidence**: a PR moving an audit rule to enforce must cite a flow-evidence file the gate holds (`promotion/no-flow-evidence`), the evidence must show matched flows for the rule inside the window (`promotion/no-matched-flows`), and the claimed window must fall inside the evidence's window (`promotion/window-outside-evidence`). A PR may only claim flows its evidence actually observed — promotion is evidence, not assertion.
- **The dead-rule review** (`flows/dead-rule`): a rule that matched zero flows across the window is flagged for review, not failed — a warning, and the verdict says `review`. A rule nobody exercised is a question, not an incident.
- **One audit** (`segment/audit`): the composed entrypoint for CI and the playground — contract validated, renders and evidence gated, one verdict (`consistent`, `review`, or `inconsistent`), and the per-rule cards alongside: each rule consistent, audit, mismatched, missing, or dead, with the record that resolved it.

The done-when proof from book issue #80 — a render-mismatch caught citing both files — runs as a single target:

```sh
make segment-demo
# → 1. the segment contract validates
#   2. the control passes the gate and renders consistent
#   3. a rule missing from one render is caught citing BOTH files:
#      render/rule-missing — examples/segment/contract.yaml and
#      renders.missing-in-render.yaml
#   4. a render carrying a rule the contract never had is caught:
#      render/rule-unknown naming R9
#   5. a direction disagreement inside the modeled subset is caught:
#      render/direction-mismatch
#   6. a type disagreement inside the modeled subset is caught:
#      render/type-mismatch
#   7. a promotion without flow evidence fails:
#      promotion/no-flow-evidence naming R3
#   8. a promotion claiming a window its evidence never covered is caught:
#      promotion/window-outside-evidence
#   9. a rule nothing exercised is flagged for review, not failed:
#      flows/dead-rule naming R2 — the verdict is review
#  10. a TTL-expired exception is caught at contract time:
#      exception/ttl-expired
```

## The ingress hardening conformance validator

The edge's posture, as data. The secure-developer-ingress chapter's YAML becomes an **ingress posture case** — the DNS containment boundary (`zone`), the request policy (default-deny and the decision that backs it), the allowed domain patterns (concrete hosts and wildcards the zone can contain), the TLS certificates with their rotation clocks, the service level objectives with the pagers behind them, the route classes the edge carries and the ones the audit logs, and the kill path the platform swears it can pull. A **drill record** holds the rehearsal evidence, and the gate joins the two — a kill path declared but never rehearsed is a kill path that has drifted. The validator is honest about what it models: pattern breadth, certificate windows, pager wiring, audit coverage, and rehearsal staleness — not pretending to full managed-gateway semantics.

```yaml
# case.yaml — the edge's posture as data
version: 1
reviewedOn: 2026-10-01
owner: Platform team
zone: dev.internal          # the DNS containment boundary

requestPolicy:
  defaultDeny: true         # an allow list stays an allow list
  decision: deny every request the allowed domains do not admit

domains:
  - pattern: "*.dev.internal"     # a wildcard, contained
    intent: every developer app tenant, inside the platform zone
  - pattern: "partner.example.com"
    intent: the one external partner host the storefront fronts

certs:
  - serves: edge.dev.internal     # well outside its rotation window
    notBefore: 2026-08-01
    notAfter: 2027-01-15
    rotateByDays: 30

slos:
  - name: edge availability
    target: 99.9% of requests served inside 200ms
    pager: platform on-call       # an SLO nobody pages is a promise nobody keeps

routes: [developer-app, partner-api, health-check]
loggedRouteClasses: [developer-app, partner-api, health-check]

killPath:
  name: seal-edge
  effect: the edge denies all ingress and the platform seals inside its zone
```

```yaml
# drill.yaml — the rehearsal evidence, joined against the case
version: 1
reviewedOn: 2026-10-15
owner: Platform team
maxStalenessDays: 180    # the staleness clock, declared next to the evidence

drills:
  - killPath: seal-edge
    drilledOn: 2026-10-10
    evidence: "drill log 2026-10-10: seal-edge pulled, all ingress denied for 90 seconds, recovery clean"
```

### What the validator enforces and proofs

- **Loud validation of the case** (`ingress/validate`): missing fields, unversioned documents, stale review stamps, a zone without its owner, and the domain patterns — a wildcard must be concrete or a `*.`-prefixed suffix of at least two labels *inside the declared zone* (`domain/too-broad`), and every pattern carries its intent.
- **The posture rules**: an allow list without default-deny is not an allow list (`requestpolicy/default-deny-required`), an expired certificate is an exposure (`cert/expired`, ERROR — the verdict is `exposed`), a certificate inside its rotation window flags honestly, not fatally (`cert/near-expiry`, WARNING — the verdict is `review`), an SLO without its pager is a promise nobody keeps (`slo/pager-required`), and every route class the case declares must be logged (`audit/class-unlogged`).
- **The kill-path gate** (`ingress/gate`): the drill record is validated on its own clock (`maxStalenessDays`, 180 by default), and every kill path the case declares must be rehearsed — a declared kill path with no rehearsal on the record fails (`killpath/never-rehearsed`, citing the drill file), a rehearsal grown stale flags for review (`killpath/stale-rehearsal`), a future-dated drill never counts (`drill/future-dated`), and a drill row for a kill path the case never declared is caught citing both files (`drill/killpath-unknown`).
- **One audit** (`ingress/audit`): the composed entrypoint for CI and the playground — case validated, drill gated, one verdict (`hardened`, `review`, or `exposed`), and the posture cards alongside: one card per judged item across the six areas (request policy, allowed domains, tls certificates, service level objectives, audit coverage, kill path), each hardened, review, or exposed, with the record that resolved it.

The done-when proof from book issue #82 runs as a single target:

```sh
make ingress-demo
# → 1. the posture case validates
#   2. the control passes the gate and renders hardened
#   3. a wildcard the zone cannot hold is caught:
#      domain/too-broad — the wildcard escaped dev.internal
#   4. a missing default-deny is caught:
#      requestpolicy/default-deny-required — an allow list without the default is not an allow list
#   5. an expired certificate is caught naming the host:
#      cert/expired naming edge.dev.internal
#   6. a certificate inside its rotation window flags honestly, not fatally:
#      cert/near-expiry — the case stays valid, the rotation is late
#   7. an SLO without its pager is caught:
#      slo/pager-required — an SLO nobody pages is a promise nobody keeps
#   8. an unlogged route class is caught naming the class:
#      audit/class-unlogged naming partner-api
#   9. a kill path never rehearsed is caught citing the drill record:
#      killpath/never-rehearsed citing drill.never-rehearsed.yaml
#  10. a rehearsal grown stale flags for review, not failure:
#      killpath/stale-rehearsal — the verdict is review, the gate stays green
```

## The citizen spec-rails conformance linter

The citizen-development chapter's YAML becomes three documents. The **citizen app manifest** is the app the citizen built, as data: the components it ships and the behavior each declares, the data bindings it opens and the rail each rides, the platform actions it uses, and the guardrails it builds against with their versions. The **app spec** is the agreement — the action rails the spec grants and the behaviors its coverage declares. The **platform guardrail registry** is the platform's word — the data rails a binding may ride and the platform floor each guardrail must meet. The linter joins all three at the citizen's PR gate and is honest about the role: an advisor, not a blocker — every drift it finds is an advisory, the gate stays green, the advice lands on the record. The one red it can show is a document it cannot read.

```yaml
# manifest.yaml — the citizen-built app as data
version: 1
reviewedOn: 2026-10-01
owner: Storefront team
app: expense-approver

components:            # every behavior declared here needs spec coverage
  - name: claim-form
    behavior: submits an expense claim
  - name: claim-rules
    behavior: approves a claim inside its policy

dataBindings:          # every binding rides a rail the registry declares
  - name: claims-store
    mode: read
    via: platform-data-api
  - name: audit-log
    mode: write
    via: platform-data-api

actions: [expense.submit, expense.approve]   # all rails the spec grants

guardrails:            # the registry's floor is the word on whether they are current
  - { name: data-guardrail, version: 3 }
  - { name: action-guardrail, version: 2 }
```

```yaml
# spec.yaml — the rails the spec grants and the coverage it declares
version: 1
reviewedOn: 2026-10-01
owner: Storefront team
actions: [expense.submit, expense.approve]
coverage:
  - submits an expense claim
  - approves a claim inside its policy
```

```yaml
# guardrails.yaml — the platform's word, not the citizen's
version: 1
reviewedOn: 2026-10-15
owner: Platform team
dataRails: [platform-data-api]
platformFloor:
  - { name: data-guardrail, floor: 3 }
  - { name: action-guardrail, floor: 2 }
```

### What the linter enforces and proofs

- **Loud validation of the manifest** (`citizen/validate`): missing fields, unversioned documents, stale review stamps, an app without its owner — and the shapes: components with names and behaviors, bindings with modes the platform knows (`read` or `write`) and a rail to ride, actions as strings without duplicates, guardrails with versions.
- **The four advisories** (`citizen/gate`, severity `advisory` — the gate stays green, `valid: true`, verdict `advises changes`): a binding that goes around the registry's rails is an escape hatch the platform cannot see (`binding/escape-hatch`, citing the manifest and the registry), an action the spec never granted is a rail the app runs on anyway (`action/outside-rails`), a behavior the coverage never declared is behavior nobody agreed to (`behavior/uncovered-by-spec`), and a guardrail built below the registry's floor is guardrail drift after a platform upgrade (`guardrail/below-floor`) — a guardrail the registry never heard of advises the same (`guardrail/unknown`).
- **The unreadable tier** (severity `error` — verdict `unreadable`): a document the advisor cannot read. Malformed manifests, specs, and registries fail honestly; drift never does.
- **One audit** (`citizen/audit`): the composed entrypoint for CI and the playground — one verdict (`aligned`, `advises changes`, or `unreadable`) and the advice cards alongside: one card per judged item across the four areas (data bindings, actions, spec coverage, guardrails), each aligned or advises, with the record that resolved it.

The done-when proof from book issue #84 runs as a single target:

```sh
make citizen-demo
# → 1. the app manifest validates
#   2. the control passes the gate and renders aligned
#      control verdict: aligned — the whole board says so, one card per judged item
#   3. an escape hatch is caught advising:
#      binding/escape-hatch — the gate stays green, the advice is on the record
#   4. an action outside the spec's rails is caught advising:
#      action/outside-rails — the gate stays green, the advice is on the record
#   5. a behavior without spec coverage is caught advising:
#      behavior/uncovered-by-spec — the gate stays green, the advice is on the record
#   6. a guardrail below the platform floor is caught advising:
#      guardrail/below-floor — the gate stays green, the advice is on the record
#   7. a manifest the advisor cannot read fails honestly:
#      caught as expected: manifest/version-required — the advisor refuses
#      to answer on a document it cannot read
```
## The component package conformance validator

The component-package chapter's YAML becomes two documents. The **component package manifest** is the package as data: its component, version, and tier, the sha256 artifact digest it publishes, the signature and attestation recorded over that digest, its provenance, and the packages it pins as dependencies by digest. The **component registry** is the estate's word — the packages it has admitted, each as a component, version, tier, and digest row. The validator joins the two at the package's own release gate and is honest about the role: a conformance gate, not an advisor — every drift it finds is an error, the gate refuses, and the package does not ship until the drift is fixed. The verdict ladder separates the failures honestly: `unreadable` (a document the gate cannot read), `drifts` (the join found drift), `consistent`.

```yaml
# package.yaml — the package as data
component: payments-checkout
version: 1.4.0
hierarchy: customer          # general, customer, or project — the tier ladder
reviewedOn: 2026-10-01
owner: Payments team

artifactDigest: 5766fab530f684e9ba8da7695939a9d13b278ffda31a1ea05bd825fc549d300c

signature:                  # recorded over the artifact digest, not beside it
  keyId: key-2026-q4
  signedDigest: 5766fab530f684e9ba8da7695939a9d13b278ffda31a1ea05bd825fc549d300c

attestation:                 # what the artifact claims to be, and who checked
  statement: the checkout artifact was built by the release pipeline
  by: release pipeline

provenance:                  # where it came from, and which commit built it
  source: payments/checkout.git
  commit: 9f31c0e

dependencies:               # pinned by digest, never by name alone
  - package: platform-baseline
    digest: d6545bd91e241a29c789035968856b675b8987840191a5211d6f0fdfae60be44
```

```yaml
# registry.yaml — the estate's word, not the package's
version: 1
reviewedOn: 2026-10-15
owner: Platform team
packages:
  - { component: payments-checkout, version: 1.4.0, hierarchy: customer, digest: 5766fab530f684e9ba8da7695939a9d13b278ffda31a1ea05bd825fc549d300c }
  - { component: platform-baseline, version: 2.1.0, hierarchy: general, digest: d6545bd91e241a29c789035968856b675b8987840191a5211d6f0fdfae60be44 }
  - { component: storefront-theme, version: 0.3.0, hierarchy: project, digest: 6053401fe5190a3153158f3173dd0f0212e3d0270be5ff30289a76495988e875 }
```

### What the validator enforces and proofs

- **Loud validation of the package manifest** (`component/validate`): the shapes — component, version, and tier present and known (`component/name-required`, `package/version-required`, `hierarchy/required`, `hierarchy/unknown`), review stamps fresh (`package/reviewed-stale`, `package/reviewed-in-future`), the owner recorded, the artifact digest a real sha256 (`artifact/digest-required`, `artifact/digest-malformed`), the signature recorded over the digest it signs (`signature/required`, `signature/digest-mismatch`), the attestation with its statement and its author, the provenance with source and commit, and every dependency pinned by name and digest with no duplicates — plus the tier honesty that a general-tier package depends on nothing (`dependency/general-forbidden`), because the baseline everything else builds on cannot itself lean on something.
- **The five drifts** (`component/gate`, severity `error` — the gate refuses, `valid: false`, verdict `drifts`): a package the registry never admitted (`gate/package-unregistered`, citing the package and the registry), an artifact drifted from its registered digest (`gate/package-digest-drift`), a dependency the registry cannot resolve (`gate/dependency-unresolved`), a stale pin — a digest that matches no admitted version of the named package (`gate/dependency-digest-mismatch`), and a downward dependency — the tiers are one-way, customer may build on general and project, never the reverse (`gate/dependency-hierarchy-violation`).
- **The unreadable tier** (severity `error` — verdict `unreadable`): a document the gate cannot read. Malformed manifests and registries fail honestly; and an artifact drifted from its registration and re-signed over the drift bites twice — the signature stops matching before the drift is judged, so the evidence itself is unreadable.
- **One audit** (`component/audit`): the composed entrypoint for CI and the playground — one verdict (`consistent`, `drifts`, or `unreadable`) and the conformance cards alongside: one card for the package registration and one per pinned dependency, each `consistent` or `drifts`, with the record that resolved it.

The validator is honest about what it models: it checks that the evidence facts are recorded and internally consistent — the signed digest equals the artifact digest, the pins equal the registry's digests — not that signatures are cryptographically valid. The key ceremony is the signing infrastructure's word, not policy's.

The done-when proof from book issue #101 runs as a single target:

```sh
make component-demo
# → 1. the package manifest validates
#   2. the control passes the gate and renders consistent
#      control verdict: consistent — the whole board says so, one card per judged item
#   3. an unsigned artifact is caught at validation:
#      caught as expected: signature/required — an unsigned artifact is an artifact nobody vouches for
#   4. an inconsistent signature is caught at validation:
#      caught as expected: signature/digest-mismatch — the recorded evidence is not even internally consistent
#   5. a general-tier package with a dependency is caught at validation:
#      caught as expected: dependency/general-forbidden — the baseline everything else builds on depends on nothing
#   6. a stale pin is caught at the join:
#      caught as expected: gate/dependency-digest-mismatch — a pin to something the estate never admitted
#   7. a downward tier is caught at the join:
#      caught as expected: gate/dependency-hierarchy-violation — the tiers are one-way, and this dependency points down
#   8. an unregistered package is caught at the join:
#      caught as expected: gate/package-unregistered — a package the estate never admitted is a package the estate never vouched for
```

## The render-matrix consistency gate

The render-matrix chapter's YAML joins two documents the component validator already knows. The **component package manifest** gains one field: the policy bindings the package ships, each a policy and the exact path it renders from — absent, the package declares none. The **render matrix** is the estate's word on where that package actually runs: the fabrics it must cover, and each fabric's rendered copy of the package — the version it renders, the digest it rendered, and the bindings it holds in force. The gate joins the two and is honest about the role: a conformance gate, not an advisor — every drift it finds is an error, the gate refuses, and the renders are not believed until every fabric agrees. The verdict ladder separates the failures honestly: `unreadable` (a document the gate cannot read), `drifts` (the join found drift), `consistent`.

```yaml
# package.yaml — the join field, appended to the manifest from #101
policyBindings:                  # the policies that must be in force wherever
  - { policy: pci-scan, path: /policies/pci-scan.rego }
  - { policy: tier-egress, path: /policies/tier-egress.rego }
```

```yaml
# matrix.yaml — one component, N fabrics, each fabric's rendered copy
version: 1
reviewedOn: 2026-10-18
owner: Platform team
component: payments-checkout      # the join runs on this name

fabrics:                         # the N — every fabric here needs a render
  - azure-west-europe
  - aws-eu-central
  - onprem-vsphere

renders:
  - fabric: azure-west-europe
    version: 1.4.0               # the manifest's own version
    digest: 5766fab530f684e9ba8da7695939a9d13b278ffda31a1ea05bd825fc549d300c
    bindings:                    # every binding the manifest declares
      - { policy: pci-scan, path: /policies/pci-scan.rego }
      - { policy: tier-egress, path: /policies/tier-egress.rego }

  - fabric: aws-eu-central
    version: 1.4.0
    digest: 5766fab530f684e9ba8da7695939a9d13b278ffda31a1ea05bd825fc549d300c
    bindings:
      - { policy: pci-scan, path: /policies/pci-scan.rego }
      - { policy: tier-egress, path: /policies/tier-egress.rego }

  - fabric: onprem-vsphere
    version: 1.4.0
    digest: 5766fab530f684e9ba8da7695939a9d13b278ffda31a1ea05bd825fc549d300c
    bindings:
      - { policy: pci-scan, path: /policies/pci-scan.rego }
      - { policy: tier-egress, path: /policies/tier-egress.rego }
```

### What the gate enforces and proofs

- **Loud validation of the render matrix** (`matrix/validate`): the shapes — a version and a fresh review stamp (a matrix nobody re-reads is a matrix the fabrics silently left behind: `matrix/version-required`, `matrix/reviewed-stale`, `matrix/reviewed-in-future`), the owner and component recorded (`matrix/owner-required`, `matrix/component-required`), fabrics declared, named, and unique (`fabrics/required`, `fabric/name-required`, `fabric/name-duplicate`), render rows well-formed (`render/row-invalid`: a fabric, a version, a real sha256 digest, and an array of bindings), each row on a declared fabric (`render/fabric-undeclared`), no fabric rendered twice (`render/row-duplicate`), and every binding a policy at a path, with no duplicates (`render/binding-*`).
- **The package preconditions** (`matrix/gate`): the manifest must be readable before the join is asked — the same component, version, and digest rules the component gate owns (`package/missing`, `component/name-required`, `package/version-required`, `artifact/digest-required`, `artifact/digest-malformed`), plus the bindings readable as pairs (`package/bindings-must-be-array`, `package/binding-policy-required`, `package/binding-path-required`, `package/binding-duplicate`). The package's own conformance remains the component gate's word, not this one's.
- **The six drifts** (`matrix/gate`, severity `error` — the gate refuses, `valid: false`, verdict `drifts`): a matrix for another component (`gate/component-mismatch`, citing both files), a fabric with no render at all (`gate/fabric-unrendered`), a fabric on another release (`gate/render-version-skew`), a re-render that swapped the artifact (`gate/render-digest-drift`), a declared binding a fabric never ran (`gate/binding-missing`, once per fabric), and a binding in force the package never declared (`gate/binding-undeclared`) — each citing the fabric and the divergent field, and the binding drifts compared as policy+path pairs, so a path disagreement bites both ways.
- **The unreadable tier** (severity `error` — verdict `unreadable`): a document the gate cannot read. A stale review stamp and a render on an undeclared fabric both stop the gate before the join is judged — a question the gate refuses to answer on inputs it cannot trust.
- **One audit** (`matrix/audit`): the composed entrypoint for CI and the playground — one verdict and the fabric cards alongside: one card per declared fabric, each `consistent` or `drifts`, with the finding that resolved it.

The done-when proof from book issue #102 runs as a single target:

```sh
make matrix-demo
# → 1. the render matrix validates
#   2. the control passes the gate and renders consistent
#      control verdict: consistent — the whole board says so, one card per declared fabric
#   3. a fabric on another release is caught at the join:
#      caught as expected: gate/render-version-skew — one fabric quietly running a different release
#   4. a re-render that swapped the artifact is caught at the join:
#      caught as expected: gate/render-digest-drift — a digest the package never published
#   5. a declared binding two fabrics never ran is caught at the join:
#      caught as expected: gate/binding-missing × 2 — a policy the package shipped that two fabrics never ran
#   6. a binding the package never declared is caught at the join:
#      caught as expected: gate/binding-undeclared — a policy in force the package never shipped
#   7. a fabric with no render at all is caught at the join:
#      caught as expected: gate/fabric-unrendered — coverage claimed and never delivered
#   8. a matrix for another component is caught at the join:
#      caught as expected: gate/component-mismatch — renders judged against somebody else's package
#   9. a matrix nobody re-reads is caught at validation, and the gate refuses to answer:
#      caught as expected: matrix/reviewed-stale, verdict unreadable — a question the gate refuses to answer on stale inputs
#  10. a render on a fabric the matrix never declared is caught at validation:
#      caught as expected: render/fabric-undeclared, verdict unreadable — the fabric list and the render rows disagree
```

## The compliance controls-as-data gate

