# software-field-guide-contracts

Contract validators for **The Software Field Guide** (DevelApp-ai/software-field-guide). This repo implements the estate and seam contract validator from the chapter **“Segmenting the Estate”** ([book issue #57](https://github.com/DevelApp-ai/software-field-guide/issues/57)): the chapter tells you which answers an enclave and a seam contract must record; this repo checks that you actually recorded them — in CI, in the browser, or on the command line.

It also implements the **authorization policy compiler** from [book issue #59](https://github.com/DevelApp-ai/software-field-guide/issues/59): one versioned policy set answers who can do what, explains every 403 with a named trace, proves the kill switch fails closed, and doubles as a retrospective audit substrate.

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

The same policies run in CI (native OPA), on the command line, and in the browser playground (compiled to WebAssembly) — one source of truth, no drift between what CI accepts and what the playground says.

Status: **v0.2** — the estate/seam formats and the authorization compiler work; thresholds and rule names may still sharpen as the book’s companion tools grow (see the book’s issue #53 roadmap).

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

## Command line

Requirements: [OPA](https://www.openpolicyagent.org/docs/) v1.21+, [yq](https://github.com/mikefarah/yq) v4, [jq](https://jqlang.github.io/jq/).

```sh
make check-enclave FILE=examples/enclaves/checkout.yaml TODAY=2026-10-20
make check-seam    FILE=examples/seams/checkout-web-tier.yaml
make check-bundle  FILE=examples/bundle.yaml
make check-authz   FILE=examples/authz/storefront.yaml TODAY=2026-10-20
```

`TODAY` defaults to the current date. `make examples` validates everything in [examples/](examples/) against the pinned anchor date `2026-10-20` so CI stays deterministic. To validate an estate split across directories, paste the JSON form directly:

```sh
opa eval -d policies -I 'data.estate.cross.validate' < bundle.json
```

## Playground

The browser playground validates contracts and explains authorization decisions entirely client-side — the Rego is compiled to WebAssembly and evaluated in your browser; nothing is uploaded. The **Authz explainer** tab answers a request against a policy set and renders the decision trace: every rule considered, the criterion each non-firing rule failed on, and the rule that decided.

- **Deployed:** CI builds the playground and deploys it on every push to `main` through the official GitHub Pages actions. Make sure Settings → Pages → Build and deployment → Source is set to **GitHub Actions** (the repo started from the Jekyll scaffold; if Pages was set up that way, this already matches).
- **Locally from a checkout:** run `make site`, then serve the `site-build/` folder over http (WebAssembly does not load over `file://`), e.g. `python3 -m http.server 8000 -d site-build`.

The playground imports the opa-wasm runtime from [site/vendor/](site/vendor/) — a vendored copy of [@open-policy-agent/opa-wasm](https://www.npmjs.com/package/@open-policy-agent/opa-wasm) (Apache-2.0) — so there is no CDN dependency and the page works offline.

## Repository layout

```
policies/estate/    enclave.rego, seam.rego, cross.rego, lib.rego
policies/authz/    lib, model, policy, decide, retro, disabled
policies/tests/    Rego unit tests with embedded fixtures (estate + authz)
schemas/           JSON Schema (draft-07) for both contract formats + the policy set
examples/          valid YAML contracts, a bundle example, and an authz policy set
site/              single-page playground (plus vendored opa-wasm)
test/e2e.mjs       node smoke test: wasm builds + vendored browser bundle
Makefile           check/test/build/site/e2e/check-*/explain-authz/... targets
.github/workflows/ CI: fmt, check, tests, examples, wasm build, e2e, Pages deploy
```

## Design notes

- **The clock is injected.** Policies never call `time.*` builtins; `today` arrives with the input. The same contract validates identically in CI, on the command line, in the browser, and in 2027 — and tests stay deterministic.
- **Dates are arithmetic, not parsing.** User-supplied dates are regex- and calendar-checked (including month lengths and leap years) before any arithmetic runs. The policies never parse strings into time values, so malformed input can produce findings but never a runtime error — which matters because a WASM evaluation traps on builtin errors.
- **The bundle policy judges relations, not fields.** `estate.cross` checks names, ownership, and coverage; per-contract field quality is the job of `estate.enclave` and `estate.seam`. Keeping them separate keeps each report focused.
- **Authorization fails closed, loudly, and by name.** Every authz failure mode has its own rule (`policy/default-deny`, `policy/disabled-fail-closed`, …), a matching deny beats every allow, and among the rules that fire the alphabetically-first id is reported — so the same inputs always produce the same trace, which is what makes it usable as audit evidence.
- **Versions are the audit substrate.** Rule ids carry across versions; `currentVersion` is explicit and never derived from the clock; windows may not overlap. Who-could-access questions are answered by replaying the history, not by remembering it.
- **CI proves the browser path.** `make e2e` runs the four `policy.wasm` builds through the exact opa-wasm bundle the playground uses (in Node, which shares the browser’s WebAssembly stack), so “green in CI” means the playground actually works, not just the native policies.

## License

[MIT](LICENSE) — same license as the book’s public tooling.
