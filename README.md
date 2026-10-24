# software-field-guide-contracts

Contract validators for **The Software Field Guide** (DevelApp-ai/software-field-guide). This repo implements the estate and seam contract validator from the chapter **“Segmenting the Estate”** ([book issue #57](https://github.com/DevelApp-ai/software-field-guide/issues/57)): the chapter tells you which answers an enclave and a seam contract must record; this repo checks that you actually recorded them — in CI, in the browser, or on the command line.

It also implements the **authorization policy compiler** from [book issue #59](https://github.com/DevelApp-ai/software-field-guide/issues/59): one versioned policy set answers who can do what, explains every 403 with a named trace, proves the kill switch fails closed, and doubles as a retrospective audit substrate.

And it implements the **observability vocabulary and cardinality linter** from [book issue #61](https://github.com/DevelApp-ai/software-field-guide/issues/61): telemetry names and labels are versioned contracts, a scanner lints instrumentation code against them, and a cardinality gate catches the label that breeds a metrics budget breach — citing the budget file it breaches.

And it implements the **alert-to-record linkage gate** from [book issue #69](https://github.com/DevelApp-ai/software-field-guide/issues/69): alert rules are a versioned contract (a severity ladder with dated rungs, runbooks with escalation clocks, owners, and record destinations), and the gate answers the incident-to-action question — every fired alert must be claimed by a record in the incident register, or it pages nobody.

And it implements the **action scope validator** from [book issue #70](https://github.com/DevelApp-ai/software-field-guide/issues/70): the micro-action vocabulary is a versioned registry — named, typed, parameter-checked actions with execution envelopes under platform ceilings — and an agent permission manifest is judged against it, default-deny: no phantom grants, no scopes on undeclared parameters, no stage that contradicts the effects it grants, no Critical action that no longer asks before it acts.

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

The same policies run in CI (native OPA), on the command line, and in the browser playground (compiled to WebAssembly) — one source of truth, no drift between what CI accepts and what the playground says.

Status: **v0.5** — the estate/seam formats, the authorization compiler, the observability linter, the action scope validator, and the alert-to-record gate work; thresholds and rule names may still sharpen as the book’s companion tools grow (see the book’s issue #53 roadmap).

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
```

`TODAY` defaults to the current date. `make examples` validates everything in [examples/](examples/) against the pinned anchor date `2026-10-20` so CI stays deterministic. Every `check-*` and `obs-*` target exits non-zero when the verdict is invalid — safe for CI and pre-commit hooks; the findings print above the failure line. To validate an estate split across directories, paste the JSON form directly:

```sh
opa eval -d policies -I 'data.estate.cross.validate' < bundle.json
```

## Playground

The browser playground validates contracts and explains authorization decisions entirely client-side — the Rego is compiled to WebAssembly and evaluated in your browser; nothing is uploaded. The **Authz explainer** tab answers a request against a policy set and renders the decision trace: every rule considered, the criterion each non-firing rule failed on, and the rule that decided. The **Obs linter** tab runs the whole observability audit — contracts, scan, and metrics export — and renders the findings plus the per-metric cardinality arithmetic. The **Alert gate** tab runs the alerting contract and the incident register together and renders the findings plus the linkage map — one row per fired alert, each showing the record it landed in or NO RECORD. The **Action scope** tab gates an agent manifest against the action registry and renders the findings plus the per-agent scoping: what each agent may do, at which stage.

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
policies/tests/     Rego unit tests with embedded fixtures (estate + authz + obs + alerts + actions)
schemas/            JSON Schema (draft-07) for every contract format + the policy set
examples/           valid YAML contracts, a bundle, an authz policy set, the action
                    registry/manifest pair, the observability demo (contracts +
                    instrumented sources), and the alerting demo (contract + incident
                    register)
scan/               instrumentation scanner feeding the obs linter
site/               single-page playground (plus vendored opa-wasm)
test/e2e.mjs        node smoke test: wasm builds + vendored browser bundle
Makefile            check/test/build/site/e2e/check-*/explain-authz/obs-*/alerts-*/actions-* targets
.github/workflows/  CI: fmt, check, tests, examples, obs demo, alerts demo, actions demo, wasm build, e2e, Pages deploy
```

## Design notes

- **The clock is injected.** Policies never call `time.*` builtins; `today` arrives with the input. The same contract validates identically in CI, on the command line, in the browser, and in 2027 — and tests stay deterministic.
- **Dates are arithmetic, not parsing.** User-supplied dates are regex- and calendar-checked (including month lengths and leap years) before any arithmetic runs. The policies never parse strings into time values, so malformed input can produce findings but never a runtime error — which matters because a WASM evaluation traps on builtin errors.
- **The bundle policy judges relations, not fields.** `estate.cross` checks names, ownership, and coverage; per-contract field quality is the job of `estate.enclave` and `estate.seam`. Keeping them separate keeps each report focused.
- **Authorization fails closed, loudly, and by name.** Every authz failure mode has its own rule (`policy/default-deny`, `policy/disabled-fail-closed`, …), a matching deny beats every allow, and among the rules that fire the alphabetically-first id is reported — so the same inputs always produce the same trace, which is what makes it usable as audit evidence.
- **Versions are the audit substrate.** Rule ids carry across versions; `currentVersion` is explicit and never derived from the clock; windows may not overlap. Who-could-access questions are answered by replaying the history, not by remembering it.
- **CI proves the browser path.** `make e2e` runs the seven `policy.wasm` builds through the exact opa-wasm bundle the playground uses (in Node, which shares the browser’s WebAssembly stack), so “green in CI” means the playground actually works, not just the native policies.
- **The allowlist is data, and it is judged against the vocabulary, not beside it.** An agent manifest may only grant actions the registry declares; argument scopes may only constrain parameters the action declares; a stage may not contradict the effects it grants. Keeping the registry and the manifest as two documents means the same registry can back many manifests, and the manifest can be re-judged every time the registry changes — default-deny is a judgment, not a hope.
- **Cardinality is arithmetic, not vibes.** The gate multiplies the observed distinct values per label and compares the product to the budget total; it also checks each label against its own allocation and against the schema. A static product check on the budget itself (maxima vs. total) catches a budget that is born over-committed, before any export exists. Budget findings cite the budget file, because a breach without the document it breaches is a mystery, not a finding.
- **Nothing pages without a record.** The alert gate is the loop-closer the other validators lack: the alerting contract declares where an alert must land, and the gate replays every fired alert against the register to prove it landed there. Severity rungs are dated because severity is a historical fact — a rung invented after the fire never fired — and postmortem actions carry verification evidence because "we fixed it" is a claim, not a closure.

## License

[MIT](LICENSE) — same license as the book’s public tooling.
