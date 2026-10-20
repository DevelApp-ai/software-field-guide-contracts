# software-field-guide-contracts

Contract validators for **The Software Field Guide** (DevelApp-ai/software-field-guide). This repo implements the estate and seam contract validator from the chapter **“Segmenting the Estate”** ([book issue #57](https://github.com/DevelApp-ai/software-field-guide/issues/57)): the chapter tells you which answers an enclave and a seam contract must record; this repo checks that you actually recorded them — in CI, in the browser, or on the command line.

Everything is [Open Policy Agent](https://www.openpolicyagent.org/) Rego, compiled three ways from the same source:

| Entry point | Judges | Input |
| --- | --- | --- |
| `estate.enclave` | one enclave contract | `{"contract": {...}, "today": "YYYY-MM-DD"}` |
| `estate.seam` | one seam contract | `{"contract": {...}, "today": "YYYY-MM-DD"}` |
| `estate.cross` | the estate as a whole | `{"enclaves": [...], "seams": [...]}` |

The same policies run in CI (native OPA), on the command line, and in the browser playground (compiled to WebAssembly) — one source of truth, no drift between what CI accepts and what the playground says.

Status: **v0.1** — the formats, rules, and playground work; thresholds and rule names may still sharpen as the book’s companion tools grow (see the book’s issue #53 roadmap).

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

See [schemas/](schemas/) for JSON Schema versions of both formats and [examples/](examples/) for complete, valid examples.

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

## Command line

Requirements: [OPA](https://www.openpolicyagent.org/docs/) v1.21+, [yq](https://github.com/mikefarah/yq) v4, [jq](https://jqlang.github.io/jq/).

```sh
make check-enclave FILE=examples/enclaves/checkout.yaml TODAY=2026-10-20
make check-seam    FILE=examples/seams/checkout-web-tier.yaml
make check-bundle  FILE=examples/bundle.yaml
```

`TODAY` defaults to the current date. `make examples` validates everything in [examples/](examples/) against the pinned anchor date `2026-10-20` so CI stays deterministic. To validate an estate split across directories, paste the JSON form directly:

```sh
opa eval -d policies -I 'data.estate.cross.validate' < bundle.json
```

## Playground

The browser playground validates contracts entirely client-side — the Rego is compiled to WebAssembly and evaluated in your browser; nothing is uploaded.

- **Deployed:** CI builds the playground and deploys it on every push to `main` through the official GitHub Pages actions. Make sure Settings → Pages → Build and deployment → Source is set to **GitHub Actions** (the repo started from the Jekyll scaffold; if Pages was set up that way, this already matches).
- **Locally from a checkout:** run `make site`, then serve the `site-build/` folder over http (WebAssembly does not load over `file://`), e.g. `python3 -m http.server 8000 -d site-build`.

The playground imports the opa-wasm runtime from [site/vendor/](site/vendor/) — a vendored copy of [@open-policy-agent/opa-wasm](https://www.npmjs.com/package/@open-policy-agent/opa-wasm) (Apache-2.0) — so there is no CDN dependency and the page works offline.

## Repository layout

```
policies/estate/    enclave.rego, seam.rego, cross.rego, lib.rego
policies/tests/     57 Rego unit tests with embedded fixtures
schemas/            JSON Schema (draft-07) for both contract formats
examples/           valid YAML contracts + a full bundle example
site/               single-page playground (plus vendored opa-wasm)
test/e2e.mjs        node smoke test: wasm builds + vendored browser bundle
Makefile            check/test/build/site/e2e/check-* targets
.github/workflows/  CI: fmt, check, tests, examples, wasm build, e2e, Pages deploy
```

## Design notes

- **The clock is injected.** Policies never call `time.*` builtins; `today` arrives with the input. The same contract validates identically in CI, on the command line, in the browser, and in 2027 — and tests stay deterministic.
- **Dates are arithmetic, not parsing.** User-supplied dates are regex- and calendar-checked (including month lengths and leap years) before any arithmetic runs. The policies never parse strings into time values, so malformed input can produce findings but never a runtime error — which matters because a WASM evaluation traps on builtin errors.
- **The bundle policy judges relations, not fields.** `estate.cross` checks names, ownership, and coverage; per-contract field quality is the job of `estate.enclave` and `estate.seam`. Keeping them separate keeps each report focused.
- **CI proves the browser path.** `make e2e` runs the three `policy.wasm` builds through the exact opa-wasm bundle the playground uses (in Node, which shares the browser’s WebAssembly stack), so “green in CI” means the playground actually works, not just the native policies.

## License

TBD — license choice deliberately left to the repo owner.
