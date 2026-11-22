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

And it implements the **policy-component validation gate** from [book issue #103](https://github.com/DevelApp-ai/software-field-guide/issues/103): the estate's policy component catalog — the platform's word on which policies exist, each a versioned, signed row on the audit→warn→enforce ladder, pinned by sha256 digest and bound to one exact path — joined to the policy bindings a component package ships. A binding to a policy the catalog never declared, and a binding rendered at a path the catalog never named: both refused — a conformance gate, not an advisor. The gate is honest about what it models: the posture is recorded, not proven; the signature facts are checked for presence and internal consistency, not cryptographic validity; a shared catalog is judged by pair agreement, so a row no package currently binds is a policy available, not a drift.

And it implements the **compliance controls-as-data gate** from [book issue #107](https://github.com/DevelApp-ai/software-field-guide/issues/107): compliance controls as data — a controls manifest declaring the estate's named evidence sources (each live or retired) and every control with its requirement mappings, its cited evidence source, and its review clock — joined to the requirements catalog of the obligations the estate owes. A requirement no control maps to, a control citing a requirement the catalog never declared, a control pointing at retired evidence, and a control whose review clock has lapsed: all refused — a conformance gate, not an advisor, because compliance is coverage, not paperwork, and coverage is a join, not a claim. The gate is honest about what it models: it checks that citations resolve inside the manifest and that clocks have not lapsed, not that the evidence store still holds its logs.

And it implements the **supply-chain IAM-broker scope gate** from [book issue #104](https://github.com/DevelApp-ai/software-field-guide/issues/104): the broker's grants as data — every grant naming one declared consumer principal, one component pinned by sha256 digest, an exact allowed action set, and an expiry — judged at the broker gate against the component package manifest (the component gate's word, book issue #101). A wildcard or glob action, a principal the broker never declared, a component the manifest neither packages nor pins, a grant pinned at a digest the package never published, and an expired grant still on the books are all refused — minimality is a judgment the estate makes, not a hope, and the grants are not believed until the manifest vouches for every one.
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
| `policy/validate` | one policy component catalog alone | `{"catalog": {...}, "today": "YYYY-MM-DD"}` |
| `policy/gate` | the component package manifest's policy bindings against the catalog | `{"catalog": {...}, "package": {...}, "today": "YYYY-MM-DD"}` |
| `policy/audit` | all of it at once — one verdict, the policy cards | the superset of the above |
| `compliance/validate` | one controls manifest alone | `{"controls": {...}, "today": "YYYY-MM-DD"}` |
| `compliance/gate` | the requirements catalog against the controls manifest | `{"controls": {...}, "requirements": {...}, "today": "YYYY-MM-DD"}` |
| `compliance/audit` | all of it at once — one verdict, the requirement cards | the superset of the above |
| `broker/validate` | one broker grant document alone | `{"broker": {...}, "today": "YYYY-MM-DD"}` |
| `broker/gate` | the issued grants against the component package manifest | `{"broker": {...}, "package": {...}, "today": "YYYY-MM-DD"}` |
| `broker/audit` | all of it at once — one verdict, the grant cards | the superset of the above |

The same policies run in CI (native OPA), on the command line, and in the browser playground (compiled to WebAssembly) — one source of truth, no drift between what CI accepts and what the playground says.

Status: **v1.1** — the estate/seam formats, the authorization compiler, the observability linter, the action scope validator, the alert-to-record gate, the deletion evidence validator, the segment render-consistency gate, the ingress hardening conformance validator, the citizen spec-rails conformance linter, the component package conformance validator, the render-matrix consistency gate, the policy-component validation gate, the compliance controls-as-data gate, and the supply-chain IAM-broker scope gate work; thresholds and rule names may still sharpen as the book’s companion tools grow (see the book’s issue #53 roadmap).

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

## The policy-component validation gate

The policy-component chapter's YAML joins two documents the earlier gates already half-know. The **policy component catalog** is the platform's word on which policies exist: one row per policy, each with a version, a sha256 digest pinned over the policy artifact, a signature recorded over that digest, a posture on the audit→warn→enforce ladder, and the one exact path the policy renders from — no globs, either side, because a binding that can match anything is a binding the join refuses to guess. The **component package manifest** carries the bindings the package holds in force — the same `policyBindings` field the render-matrix gate reads — each a policy and the exact path it renders from. The gate joins the two and is honest about the role: a conformance gate, not an advisor — every drift it finds is an error and the package does not pass until the drift is fixed. The verdict ladder separates the failures honestly: `unreadable` (a document the gate cannot read), `drifts` (the join found drift), `consistent`.

```yaml
# catalog.yaml — the platform's word: which policies exist, and where
version: 1
reviewedOn: 2026-10-18
owner: Platform team
policies:
  - policy: pci-scan
    version: 3.2.0
    digest: b09dcc492429e5e410c918a3d27911639f00759d86cd5d87612a23e15e11c324
    signature: { keyId: key-2026-q4, signedDigest: b09dcc492429e5e410c918a3d27911639f00759d86cd5d87612a23e15e11c324 }
    posture: enforce              # the rung the policy sits on
    path: /policies/pci-scan.rego  # the one exact path — no globs
  - policy: tier-egress
    version: 1.1.0
    digest: 54e34a23f2c451616380d3c5432537f6e7d3df96a88e3361cc2b9674f5c289fc
    signature: { keyId: key-2026-q4, signedDigest: 54e34a23f2c451616380d3c5432537f6e7d3df96a88e3361cc2b9674f5c289fc }
    posture: enforce
    path: /policies/tier-egress.rego
```

```yaml
# package.yaml — the join field, the same policyBindings from #102
policyBindings:
  - { policy: pci-scan, path: /policies/pci-scan.rego }
  - { policy: tier-egress, path: /policies/tier-egress.rego }
```

### What the gate enforces and proofs

- **Loud validation of the catalog** (`policy/validate`): the shapes — a version and a fresh review stamp (`catalog/version-required`, `catalog/reviewed-on-invalid`, `catalog/reviewed-in-future`, `catalog/reviewed-stale`), the owner recorded (`catalog/owner-required`), rows well-formed (`policies/rows-required`, `policies/must-be-array`, `policies/row-must-be-object`), and per row a named, unique policy at a real version (`policy/name-required`, `policy/name-duplicate`, `policy/version-required`) with a real sha256 digest (`policy/digest-required`, `policy/digest-malformed`), a signature whose recorded digest matches the published one (`policy/signature-required`, `policy/signature-key-required`, `policy/signature-digest-required`, `policy/signature-digest-mismatch`), a posture on the ladder — audit, warn, enforce — not a word that merely sounds like one (`policy/posture-required`, `policy/posture-unknown`), and one exact, non-glob path (`policy/path-required`, `policy/path-glob`).
- **The package preconditions** (`policy/gate`): the manifest must be readable before the join is asked — the bindings an array of policy+path pairs (`package/missing`, `package/bindings-must-be-array`, `package/binding-must-be-object`, `package/binding-policy-required`, `package/binding-path-required`), each binding path exact (`package/binding-path-glob` — the exactness check the component validator of #101 never made on this field), and no duplicate bindings (`package/binding-duplicate`). The package's own conformance remains the component gate's word, not this one's.
- **The two join drifts** (`policy/gate`, severity `error` — the gate refuses, `valid: false`, verdict `drifts`): a binding to a policy the catalog never declared (`gate/policy-unresolved`), and a binding rendered at a path the catalog never named (`gate/binding-path-drift`, citing both files) — the same policy at a different path is a different binding. Vice-versa is pair agreement, not inventory: an unbound catalog row is a policy available, not a drift, because the same catalog backs many packages.
- **The unreadable tier** (severity `error` — verdict `unreadable`): a document the gate cannot read. A glob-shaped path on either side stops the gate before the join is judged — a question the gate refuses to answer on inputs it cannot trust.
- **One audit** (`policy/audit`): the composed entrypoint for CI and the playground — one verdict and the policy cards alongside: one card per bound policy, each `consistent` or `drifts`, with the finding that resolved it.

The done-when proof from book issue #103 runs as a single target:

```sh
make policy-demo
# → 1. the policy component catalog validates
#   2. the control passes the gate and renders consistent
#      control verdict: consistent — two bound policies, both answering the catalog, one card per binding
#   3. a glob-shaped catalog path is caught at validation:
#      caught as expected: policy/path-glob — a binding that can match anything is a binding the join refuses to guess
#   4. an unsigned policy component is caught at validation:
#      caught as expected: policy/signature-required — an unsigned policy is a policy nobody vouches for
#   5. a signature that signed another digest is caught at validation:
#      caught as expected: policy/signature-digest-mismatch — the recorded evidence is not even internally consistent
#   6. a binding to a policy the catalog never declared is caught at the join:
#      caught as expected: gate/policy-unresolved — a deny-by-default claim about a policy the estate never admitted is a claim nobody can check
#   7. a binding rendered at a path the catalog never named is caught at the join:
#      caught as expected: gate/binding-path-drift citing both files — the same policy at a different path is a different binding
#   8. a glob-shaped package binding is caught, and the gate refuses to answer:
#      caught as expected: package/binding-path-glob, verdict unreadable — the exactness gap the component validator never checked
```

## The compliance controls-as-data gate

The compliance-as-code chapter's YAML joins two documents. The **controls manifest** is the estate's word on its own compliance work: the named evidence sources it collects — each declared live or retired — and one row per control with its owner, the requirement ids it maps onto, the evidence source it cites, and its review clock: the day it was last reviewed and the interval it promises. The **requirements catalog** is the obligations side: one row per requirement — id, title, source. The gate joins the two in both directions and is honest about the role: a conformance gate, not an advisor, because compliance is coverage, not paperwork, and coverage is a join, not a claim. The verdict ladder separates the failures honestly: `unreadable` (a document the gate cannot read), `drifts` (the join found drift), `consistent`.

```yaml
# controls.yaml — the estate's word: the controls, their evidence, their clocks
version: 1
reviewedOn: 2026-10-18
owner: Platform team
evidenceSources:
  - { id: edge-firewall-review, kind: review record, status: live }
  - { id: encryption-config-scan, kind: scanner output, status: live }
controls:
  - id: CTRL-01
    title: Edge firewall rule set reviewed and re-approved quarterly
    owner: Platform team
    requirements: [PCI-DSS-2.2.7]         # ids the catalog declares
    evidenceSource: edge-firewall-review  # a declared source, and not retired
    reviewedOn: 2026-09-15
    intervalDays: 180                     # the clock the control promises
```

```yaml
# requirements.yaml — the join document: what the estate owes
version: 1
reviewedOn: 2026-10-01
owner: Compliance team
requirements:
  - { id: PCI-DSS-2.2.7, title: Firewall and router rule sets are reviewed and re-approved at least every six months, source: PCI DSS v4.0 }
```

### What the gate enforces and proofs

- **Loud validation of the manifest** (`compliance/validate`): the shapes — a version and a fresh review stamp (`controls/version-required`, `controls/reviewed-on-invalid`, `controls/reviewed-in-future`, `controls/reviewed-stale`), the owner recorded (`controls/owner-required`), rows well-formed (`controls/missing`, `controls/must-be-array`, `control/row-must-be-object`), sources well-formed with an id, a kind, and a status on the live/retired ladder (`sources/must-be-array`, `source/row-must-be-object`, `source/id-required`, `source/kind-required`, `source/status-unknown`, `source/id-duplicate`), and per control a named, unique id and a title (`control/id-required`, `control/id-duplicate`, `control/title-required`), an owner (`control/owner-required`), requirement ids as an array of strings (`control/requirements-required`, `control/requirements-must-be-array`, `control/requirement-must-be-string`), a cited evidence source that resolves to a declared row (`control/evidence-required`, `control/evidence-source-unknown`), a real review date (`control/reviewed-on-invalid`, `control/reviewed-in-future`), and an interval that is a real number (`control/interval-required`, `control/interval-invalid`).
- **The catalog preconditions** (`compliance/gate`, verdict `unreadable` before the join is judged): the requirements catalog must be readable — rows an array of objects (`requirements/missing`, `requirements/must-be-array`, `requirements/required`, `requirements/row-must-be-object`), each requirement carrying an id (`requirement/id-required`). The catalog's stamps are the catalog's own word and are not re-judged here.
- **The four join drifts** (`compliance/gate`, severity `error` — the gate refuses, `valid: false`, verdict `drifts`): a requirement no control maps to (`gate/requirement-unmapped` — a promise nobody keeps), a control citing a requirement the catalog never declared (`gate/requirement-unknown` — compliance claimed with words nobody wrote), a control pointing at a source the manifest declared retired (`gate/evidence-dead` — evidence the estate itself retired), and a control whose review clock has lapsed (`gate/review-expired` — the boundary day is fresh, the day after is not).
- **The unreadable tier** (severity `error` — verdict `unreadable`): a document the gate cannot read — an unreadable control cannot vouch for any coverage, so the gate stops before the join is judged.
- **One audit** (`compliance/audit`): the composed entrypoint for CI and the playground — one verdict and the requirement cards alongside: one card per declared requirement, each `consistent` or `drifts`, with the control, the evidence, and the clock that resolved it.

The done-when proof from book issue #107 runs as a single target:

```sh
make compliance-demo
# → 1. the controls manifest validates
#   2. the control pair passes the gate and renders consistent
#      control verdict: consistent — every requirement covered by a sound control, one card per declaration
#   3. a requirement nobody controls is caught at the join:
#      caught as expected: gate/requirement-unmapped — a requirement nobody controls is a promise nobody keeps
#   4. a control citing retired evidence is caught at the join:
#      caught as expected: gate/evidence-dead — a control pointing at evidence nobody collects is a control nobody can audit
#   5. a control whose review clock lapsed is caught at the join:
#      caught as expected: gate/review-expired — a control nobody re-reviews is a control nobody operates
#   6. a control mapping onto a requirement nobody wrote is caught at the join:
#      caught as expected: gate/requirement-unknown — and the requirement it orphaned bites too, honestly
#   7. a control without evidence makes the gate refuse to answer:
#      caught as expected: control/evidence-required, verdict unreadable — a control without evidence is an assertion, not a control
#   8. a manifest nobody re-reads makes the gate refuse to answer:
#      caught as expected: controls/reviewed-stale, verdict unreadable — a manifest nobody refreshed is a map of an estate that no longer exists
#   9. two controls sharing one id make the gate refuse to answer:
#      caught as expected: control/id-duplicate, verdict unreadable — a control declared twice is evidence nobody can count
#  10. a control mapping onto nothing makes the gate refuse to answer:
#      caught as expected: control/requirements-required, verdict unreadable — an unmapped control is busywork with no compliance meaning
```

## The supply-chain IAM-broker scope gate

The supply-chain chapter's question is minimality: when a broker issues scoped grants over the estate's components, does any grant name more than the estate vouches for? Two documents answer it — the broker's grant document (the consumer identities it declares and every grant it issued) and the component package manifest from book issue #101 (the component, the sha256 artifact digest it publishes, and the dependencies it pins by digest):

```yaml
# examples/broker/grants.yaml — the broker's grants as data
version: 1
reviewedOn: 2026-10-18
owner: Platform team

principals:            # the consumer identities the broker declares
  - storefront-build
  - payments-build

grants:
  # the storefront build consumes the checkout package: pull only,
  # pinned to the digest the package publishes
  - principal: storefront-build
    component: payments-checkout
    digest: 5766fab530f684e9ba8da7695939a9d13b278ffda31a1ea05bd825fc549d300c
    actions: [pull]
    expires: 2026-12-31
```

The join resolves each grant's component against the package manifest: `payments-checkout` at the package's own published `artifactDigest`, `platform-baseline` at the dependency the manifest pins. Every resolution is the manifest's word, never the grant's — which is the point: a grant is not believed until the package vouches for it.

### What the gate enforces and proofs

- **Loud validation of the grant document** (`broker/validate`): the shapes — a version and a fresh review stamp (`broker/version-required`, `broker/reviewed-stale`, `broker/reviewed-in-future`, `broker/reviewed-on-invalid`), the owner recorded (`broker/owner-required`), the declared principals readable, named, and unique (`principals/must-be-array`, `principals/name-required`, `principal/name-duplicate`), the grants an array of objects (`grants/must-be-array`, `grants/rows-required`, `grants/row-must-be-object`), and each grant complete — one principal, one component, a real sha256 digest, a non-empty array of exact action names, and an expiry (`grant/principal-required`, `grant/component-required`, `grant/digest-required`, `grant/digest-malformed`, `grant/actions-required`, `grant/actions-must-be-array`, `grant/action-name-required`, `grant/expires-required`, `grant/expires-invalid`), with no grant issued twice (`grant/duplicate`).
- **Minimality is refused, not advised** (`broker/gate` and `broker/validate`, severity `error`): a grant that can do anything is the scope the broker exists to prevent (`grant/action-wildcard`), an action set with glob metacharacters is not an exact set (`grant/action-glob`), a grant naming a principal the broker never declared is a principal nobody granted (`grant/principal-undeclared`), and an expired grant still on the books is a grant the broker never revoked (`grant/expires-in-past`).
- **The two join drifts** (`broker/gate`, severity `error` — the gate refuses, `valid: false`, verdict `drifts`): a grant for a component the manifest neither packages nor pins (`gate/component-unresolved`), and a grant pinned at a digest the package never published (`gate/digest-drift`) — each citing the grant document and the manifest, because a mismatch without its documents is a mystery, not a finding. Resolutions are the package's own artifact plus its well-formed pinned dependencies.
- **The unreadable tier** (severity `error` — verdict `unreadable`): a document the gate cannot read, or a grant too malformed to join. The gate refuses to answer the join question on inputs it cannot trust.
- **One audit** (`broker/audit`): the composed entrypoint for CI and the playground — one verdict and the grant cards alongside: one card per readable grant, principal on component, each `consistent` or `drifts`, with the finding that resolved it.

The gate is honest about what it models: the action vocabulary is not judged (any exact, non-metacharacter action name is allowed — the gate refuses broad scopes, not unfamiliar verbs), the expiry has no maximum horizon (only not in the past), and the package manifest's own conformance remains the component gate's word, not this one's — the two gates compose (#101 then #104) without either pretending to own the other's judgment.

The done-when proof from book issue #104 runs as a single target:

```sh
make broker-demo
# → 1. the broker grant document validates
#   2. the control passes the gate and renders consistent
#      control verdict: consistent — two grants, two cards, the manifest vouches for both
#   3. a wildcard grant is caught at the gate:
#      caught as expected: grant/action-wildcard — a grant that can do anything is the scope the broker exists to prevent
#   4. a metacharacter action is caught at the gate:
#      caught as expected: grant/action-glob — an action set is exact names or it is not a set
#   5. an expired grant still on the books is caught at the gate:
#      caught as expected: grant/expires-in-past — an expired grant is a grant the broker never revoked
#   6. an identity the broker never declared is caught at the gate:
#      caught as expected: grant/principal-undeclared — an identity the broker never declared is a principal nobody granted
#   7. a grant for a component the manifest never named is caught at the join:
#      caught as expected: gate/component-unresolved — a grant for a component nobody packaged, citing both files
#   8. a grant pinned at a digest the package never published is caught at the join:
#      caught as expected: gate/digest-drift — a grant for bytes the package never published, citing both files
```
## Command line

Requirements: [OPA](https://www.openpolicyagent.org/docs/) v1.21+, [yq](https://github.com/mikefarah/yq) v4, [jq](https://jqlang.github.io/jq/).

```sh
make check-enclave FILE=examples/enclaves/checkout.yaml TODAY=2026-10-20
make check-seam    FILE=examples/seams/checkout-web-tier.yaml
make check-bundle  FILE=examples/bundle.yaml
make check-authz   FILE=examples/authz/storefront.yaml TODAY=2026-10-20
make check-obs     TODAY=2026-10-20          # vocabulary + label schema + budget
make obs-lint                               # scan demo sources against the contracts
make obs-gate                               # gate the demo metrics export
make check-alerts TODAY=2026-10-20          # the alerting contract alone
make alerts-gate   TODAY=2026-10-20         # the register against the contract
make check-actions TODAY=2026-10-20         # the action registry alone
make actions-gate  TODAY=2026-10-20         # the demo manifest against the registry
make check-erasure TODAY=2026-10-20         # the DEK registry alone
make erasure-gate  TODAY=2026-10-20         # the demo erasure case against the registry
make check-segment TODAY=2026-10-20         # the segment contract alone
make segment-gate  TODAY=2026-10-20         # renders + flows + promotion against the contract
make check-ingress TODAY=2026-10-20         # the ingress posture case alone
make ingress-gate  TODAY=2026-10-20         # the drill record against the posture case
make check-citizen TODAY=2026-10-20         # the citizen app manifest alone
make citizen-gate  TODAY=2026-10-20         # the spec + the guardrail registry against the manifest
make check-component TODAY=2026-10-20         # the component package manifest alone
make component-gate TODAY=2026-10-20          # the component registry against the manifest
make check-matrix TODAY=2026-10-20            # the render matrix alone
make matrix-gate TODAY=2026-10-20             # the fabric renders against the package manifest
make check-policy TODAY=2026-10-20            # the policy component catalog alone
make policy-gate  TODAY=2026-10-20            # the package manifest's policy bindings against the catalog
make check-compliance TODAY=2026-10-20        # the controls manifest alone
make compliance-gate TODAY=2026-10-20         # the requirements catalog against the controls manifest
make check-broker TODAY=2026-10-20            # the broker grant document alone
make broker-gate  TODAY=2026-10-20            # the issued grants against the package manifest
```

`TODAY` defaults to the current date. `make examples` validates everything in [examples/](examples/) against the pinned anchor date `2026-10-20` so CI stays deterministic. Every `check-*` and `obs-*` target exits non-zero when the verdict is invalid — safe for CI and pre-commit hooks; the findings print above the failure line. To validate an estate split across directories, paste the JSON form directly:

```sh
opa eval -d policies -I 'data.estate.cross.validate' < bundle.json
```

## Playground

The browser playground validates contracts and explains authorization decisions entirely client-side — the Rego is compiled to WebAssembly and evaluated in your browser; nothing is uploaded. The **Authz explainer** tab answers a request against a policy set and renders the decision trace: every rule considered, the criterion each non-firing rule failed on, and the rule that decided. The **Obs linter** tab runs the whole observability audit — contracts, scan, and metrics export — and renders the findings plus the per-metric cardinality arithmetic. The **Alert gate** tab runs the alerting contract and the incident register together and renders the findings plus the linkage map — one row per fired alert, each showing the record it landed in or NO RECORD. The **Action scope** tab gates an agent manifest against the action registry and renders the findings plus the per-agent scoping: what each agent may do, at which stage. The **Erasure gate** tab judges a right-to-be-forgotten case against the DEK registry and renders the verdict — forgotten, pending, honest, or incomplete — plus one row per inventory store: swept, expired, pending, or unswept. The **Segment gate** tab gates fabric renders, flow evidence, and a promotion PR against the segment contract and renders the verdict — consistent, review, or inconsistent — plus one card per contract rule: consistent, audit, mismatched, missing, or dead. The **Ingress gate** tab gates a drill record against the ingress posture case and renders the verdict — hardened, review, or exposed — plus the posture cards: one per judged item across the six areas, each with the record that resolved it. The **Citizen gate** tab gates the app's spec and the platform guardrail registry against the citizen app manifest and renders the verdict — aligned, advises changes, or unreadable — plus the advice cards: one per judged item across the four areas, aligned or advises, because the gate is an advisor, not a blocker. The **Component gate** tab gates a component package manifest against the component registry and renders the verdict — consistent, drifts, or unreadable — plus the conformance cards: one for the package registration, one per pinned dependency, because the package does not ship until every drift is fixed. The **Matrix gate** tab gates every fabric's rendered copy of the package against the component package manifest and renders the verdict — consistent, drifts, or unreadable — plus the fabric cards: one per declared fabric, because the renders are not believed until every fabric agrees. The **Policy gate** tab gates the package manifest's policy bindings against the policy component catalog and renders the verdict — consistent, drifts, or unreadable — plus the policy cards: one per bound policy, because the same catalog backs many packages and no row is a drift by inventory. The **Compliance gate** tab gates the requirements catalog against the controls manifest — evidence sources, controls, and their review clocks — and renders the verdict — consistent, drifts, or unreadable — plus the requirement cards: one per declared requirement, because compliance is coverage and coverage is a join, not a claim. The **IAM Broker gate** tab gates the broker's issued grants against the component package manifest and renders the verdict — consistent, drifts, or unreadable — plus the grant cards: one per issued grant, principal on component, because the grants are not believed until the manifest vouches for every one.

- **Deployed:** CI builds the playground and deploys it on every push to `main` through the official GitHub Pages actions. Make sure Settings → Pages → Build and deployment → Source is set to **GitHub Actions** (the repo started from the Jekyll scaffold; if Pages was set up that way, this already matches).
- **Locally from a checkout:** run `make site`, then serve the `site-build/` folder over http (WebAssembly does not load over `file://`), e.g. `python3 -m http.server 8000 -d site-build`.

The playground imports the opa-wasm runtime from [site/vendor/](site/vendor/) — a vendored copy of [@open-policy-agent/opa-wasm](https://www.npmjs.com/package/@open-policy-agent/opa-wasm) (Apache-2.0) — so there is no CDN dependency and the page works offline.

## Repository layout

```
policies/estate/    enclave.rego, seam.rego, cross.rego, lib.rego
policies/authz/     lib, model, policy, decide, retro, disabled
policies/obs/       lib, model, policy, lint, gate, audit
policies/alerts/    lib, model, policy, gate, audit
policies/actions/   lib, model, policy, gate, audit
policies/erasure/   lib, model, policy, gate, audit
policies/segment/   lib, model, policy, gate, audit
policies/ingress/   lib, model, policy, gate, audit
policies/citizen/  lib, model, policy, gate, audit
policies/component/ lib, model, policy, gate, audit
policies/matrix/    lib, model, policy, gate, audit
policies/policy/   lib, model, policy, gate, audit
policies/compliance/ lib, model, policy, gate, audit
policies/broker/    lib, model, policy, gate, audit
policies/tests/     Rego unit tests with embedded fixtures (estate + authz + obs + alerts + actions + erasure + segment + ingress + citizen + component + matrix + policy + compliance + broker)
schemas/            JSON Schema (draft-07) for every contract format + the policy set
examples/           valid YAML contracts, a bundle, an authz policy set, the action
                    registry/manifest pair, the observability demo (contracts +
                    instrumented sources), the alerting demo (contract + incident
                    register), the erasure demo (DEK registry + cases), and the segment
                    demo (contract + renders + flows + promotion, plus broken variants),
                    and the ingress demo (posture case + drill record, plus broken variants),
                    and the citizen demo (app manifest + spec + guardrail registry, plus broken variants),
                    and the component demo (package manifest + component registry, plus broken variants),
                    and the render-matrix demo (package manifest with policy bindings + the
                    fabric render matrix, plus broken variants), and the policy-component demo
                    (policy component catalog + the package manifest's bindings, plus broken
                    variants), and the compliance demo (controls manifest + requirements
                    catalog, plus broken variants), and the IAM-broker demo
                    (grant document + package manifest, plus broken variants)
scan/               instrumentation scanner feeding the obs linter
site/               single-page playground (plus vendored opa-wasm)
test/e2e.mjs        node smoke test: wasm builds + vendored browser bundle
Makefile            check/test/build/site/e2e/check-*/explain-authz/obs-*/alerts-*/actions-*/erasure-*/segment-*/ingress-*/citizen-*/component-*/matrix-*/policy-*/compliance-*/broker-* targets
.github/workflows/  CI: fmt, check, tests, examples, obs demo, alerts demo, actions demo, erasure demo, segment demo, ingress demo, citizen demo, component demo, matrix demo, policy demo, compliance demo, broker demo, wasm build, e2e, Pages deploy
```

## Design notes

- **The clock is injected.** Policies never call `time.*` builtins; `today` arrives with the input. The same contract validates identically in CI, on the command line, in the browser, and in 2027 — and tests stay deterministic.
- **Dates are arithmetic, not parsing.** User-supplied dates are regex- and calendar-checked (including month lengths and leap years) before any arithmetic runs. The policies never parse strings into time values, so malformed input can produce findings but never a runtime error — which matters because a WASM evaluation traps on builtin errors.
- **The bundle policy judges relations, not fields.** `estate.cross` checks names, ownership, and coverage; per-contract field quality is the job of `estate.enclave` and `estate.seam`. Keeping them separate keeps each report focused.
- **Authorization fails closed, loudly, and by name.** Every authz failure mode has its own rule (`policy/default-deny`, `policy/disabled-fail-closed`, …), a matching deny beats every allow, and among the rules that fire the alphabetically-first id is reported — so the same inputs always produce the same trace, which is what makes it usable as audit evidence.
- **Versions are the audit substrate.** Rule ids carry across versions; `currentVersion` is explicit and never derived from the clock; windows may not overlap. Who-could-access questions are answered by replaying the history, not by remembering it.
- **CI proves the browser path.** `make e2e` runs the sixteen `policy.wasm` builds through the exact opa-wasm bundle the playground uses (in Node, which shares the browser’s WebAssembly stack), so “green in CI” means the playground actually works, not just the native policies.
- **The allowlist is data, and it is judged against the vocabulary, not beside it.** An agent manifest may only grant actions the registry declares; argument scopes may only constrain parameters the action declares; a stage may not contradict the effects it grants. Keeping the registry and the manifest as two documents means the same registry can back many manifests, and the manifest can be re-judged every time the registry changes — default-deny is a judgment, not a hope.
- **Cardinality is arithmetic, not vibes.** The gate multiplies the observed distinct values per label and compares the product to the budget total; it also checks each label against its own allocation and against the schema. A static product check on the budget itself (maxima vs. total) catches a budget that is born over-committed, before any export exists. Budget findings cite the budget file, because a breach without the document it breaches is a mystery, not a finding.
- **Nothing pages without a record.** The alert gate is the loop-closer the other validators lack: the alerting contract declares where an alert must land, and the gate replays every fired alert against the register to prove it landed there. Severity rungs are dated because severity is a historical fact — a rung invented after the fire never fired — and postmortem actions carry verification evidence because "we fixed it" is a claim, not a closure.
- **Nothing is forgotten without a record.** The #69 rule, moved from alerting to erasure: a store in the inventory needs a sweep record, an aged-out backup window, or an explicit pending reason — and an unexpired backup is an honest pending state, not a failure. The case stays open until the window closes; the registry's destroyed keys carry their evidence records, because a destruction asserted is not a destruction evidenced.
- **A rule is not enforced until every fabric says so.** The segment gate verifies every join both ways — a rule missing from one render drifts silently, and a render carrying a rule the contract never had drifts just as silently — and cites both files when it bites, because a mismatch without its documents is a mystery, not a finding. Promotion is evidence, not assertion: an audit rule moves to enforce only by a PR citing flow evidence the gate holds, with matched flows inside a window the evidence actually covered. The gate models a stated subset — direction, type, port, mode — and says so, rather than pretending to full eBPF or CIL semantics. And a rule nothing exercised is flagged for review, not failed: a dead rule is a question, not an incident.
- **The linter is an advisor, not a blocker.** Citizen development is judged at the citizen's own PR gate, against the citizen's own spec: escape hatches the platform cannot see, actions outside the rails the spec grants, behaviors without coverage, guardrails below the registry's floor — all advisories, because the point is to surface drift before it ships, not to gate the citizen on the platform's behalf. The red is reserved for the unreadable: a document the advisor cannot parse fails honestly, while drift never fails the build. The spec is the agreement and the app drifts; the floor is the registry's word, not the citizen's. Keeping manifest, spec, and registry as three documents means the same registry can back many apps and every app is re-judged when the platform upgrades. The composed audit dedupes the shared conditions, so the same broken manifest reports once, whichever lens caught it.
- **Posture is data, and a kill path is rehearsed or it is a hope.** The ingress case records the edge's posture as checkable facts — the zone that contains every wildcard, the default-deny that keeps the allow list an allow list, the rotation clocks on the certificates, the pagers behind the SLOs, the audit coverage of the route classes — and the gate joins the drill record to it, because a kill path declared but never rehearsed is a lever nobody has proven they can pull. Rehearsal staleness is a warning, not an error: a kill path rehearsed once and never again is a question, not an incident. The composed audit dedupes the shared conditions, so the same broken case reports once, whichever lens caught it.
- **A package is admitted or it does not ship.** The component gate is the conformance mirror of the citizen's advisor: judged at the package's own release gate against a registry the estate owns — an unregistered package, an artifact drifted from its registered digest, an unresolved dependency, a stale pin, and a downward tier all refused, because the estate vouches for what it ships and nothing else. Keeping manifest and registry as two documents means the same registry backs many packages and every package is re-judged when the registry changes — the tiers are the registry's word, not the package's. The verdict ladder dedupes the shared conditions honestly: `unreadable` means a document could not be read, `drifts` means the join found drift — and a drifted artifact re-signed over its drift bites twice, the signature failing before the drift is judged. And the gate says what it models: it checks that the evidence facts are recorded and internally consistent, not that signatures are cryptographically valid — the key ceremony is outside what a policy can check.
- **One component, N fabrics, one word.** The render-matrix gate is the segment pattern (#80) generalized from network rules to component packages: the package manifest declares what every fabric must render — the version, the pinned digest, and the policy bindings, as policy+path pairs — and the matrix is the estate's word on what each fabric actually rendered. The join runs both ways, like the segment gate's: a declared binding a fabric never ran drifts silently, and a binding in force the package never declared drifts just as silently. Every join finding cites the fabric and the divergent field plus both files, because a mismatch without its documents is a mystery, not a finding. The cards are per declared fabric, not per render row — coverage is claimed by the fabrics list, so a fabric with no render gets a card that says so, and a render row on an undeclared fabric stops the gate as unreadable before the join is judged. And the package's own conformance stays the component gate's word: this gate reads only the manifest's identity, digest, and bindings, so the two gates compose (#101 then #102) without either pretending to own the other's judgment.

- **A binding is a pair, and the catalog is shared.** The policy-component gate joins the package manifest's `policyBindings` to the platform's policy component catalog, and the join judges pairs — a binding to a policy the catalog never declared, and a binding rendered at a path the catalog never named, are both refused, while an unbound catalog row is not a drift at all: the same catalog backs many packages, so inventory is availability, not conformance. Both sides demand one exact path, because a binding that can match anything is a binding the join refuses to guess — the exactness check closes the gap the component validator of #101 never made on this field. The ladder is honest arity, too: a posture is recorded, not proven, and the signature facts are checked for presence and internal consistency, never cryptographic validity. And the gates compose (#101, #102, #103) — this gate reads only the bindings and the catalog, so it neither repeats nor contradicts the component gate's word on the package itself or the matrix gate's word on the fabrics.

- **Compliance is coverage, not paperwork — and coverage is a join, not a claim.** The compliance gate joins the controls manifest to the requirements catalog in both directions: a requirement id no control maps to is a promise nobody keeps, and a control mapping onto an id the catalog never declared is compliance claimed with words nobody wrote. The manifest's evidence sources are declared live or retired, so a control citing retired evidence is a control nobody can audit, and each control carries its own review clock, so a control nobody re-reviews is a control nobody operates. The verdict ladder keeps the failures honest: an unreadable manifest cannot vouch for any coverage, so validation stops the gate before the join is judged. And the gate says what it models: it checks that citations resolve inside the manifest and that clocks have not lapsed — that the evidence store still holds its logs is outside what a policy can check.

- **A grant is not believed until the manifest vouches for it.** The IAM-broker gate is minimality as a join, not a request: the broker's grants are data — one declared consumer principal, one component pinned by sha256 digest, an exact action set, an expiry — and the package manifest (#101) is the estate's word on what exists and at which digest. Wildcard and glob actions, undeclared principals, and expired grants are refused outright, and the join's two drifts — a component nobody packaged, a grant pinned at bytes the package never published — cite both files, because a mismatch without its documents is a mystery, not a finding. The join reads only the manifest's identity, digest, and pinned dependencies, so the same package backs many brokers and every grant set is re-judged when the package changes — the package's own conformance stays the component gate's word. And the gate says what it models: the action vocabulary is not judged (any exact, non-metacharacter name is allowed — the gate refuses broad scopes, not unfamiliar verbs), and the expiry has no maximum horizon, only not in the past.
## License

[MIT](LICENSE) — same license as the book’s public tooling.
