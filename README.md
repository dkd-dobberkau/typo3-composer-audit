# composer-audit

Three independent checks over a Composer lockfile: upgrade readiness,
known vulnerabilities, and a CycloneDX SBOM.

One file, no framework, no storage layer — the standard library plus `httpx`.
Both data sources are public and need no API key.

```bash
pip install -r requirements.txt
python composer_audit.py path/to/composer.lock --target 14 --sbom sbom.json
```

```
39 packages (0 dev)
Upgrade to 14: 32 ready, 0 already there, 1 pre-release only, 6 blocked
Vulnerabilities: 53 in 10 packages
SBOM written to sbom.json
```

Exit code is non-zero when a package blocks the upgrade or when either scan
could not be completed.

```bash
pip install -r requirements-dev.txt && pytest
```

## The three checks

### Upgrade readiness — `check_upgrade_batch(nodes, target_major)`

Asks Packagist whether each TYPO3 extension has a release whose
`typo3/cms-*` constraints admit the target major. Per package:

| Status | Meaning |
|---|---|
| `green` | a stable release supports the target |
| `yellow` | only a pre-release supports it |
| `current` | the installed version already supports it |
| `red` | no release supports it — this blocks the upgrade |
| `unknown` | Packagist answered: no such package (private packages land here) |
| `unverifiable` | no release declares any `typo3/cms-*` constraint |
| `unreachable` | no answer at all — the channel is broken, not the package |

The last three are not footnotes. They are the packages about which nothing was
learned, they are printed under the summary line, and `unreachable` makes the
exit code non-zero. A package nobody could check is not a package that is fine.

**Any `typo3/cms-*` requirement answers the question, and all of them must
admit the target.** The core's split packages are released in lockstep, and not
every extension names `typo3/cms-core`: `b13/container` 4.1.0 gets by with
`typo3/cms-backend: ^13.4 || ^14.3`. Reading only `cms-core` reported it as
blocking an upgrade it explicitly supports. Conversely, if `cms-core` admits 14
but `cms-fluid` does not, Composer could not resolve the install — so a single
failing requirement is enough to disqualify a release.

The interesting part is `_constraint_allows_major()`. Composer constraints are
not a simple string match: it handles `^N`, `~N.M`, `>=N`, `<N`, `N.*`, `*`,
exact pins, `||` alternates and whitespace/comma-separated AND-segments. A naive
substring check reports `^11.5.14` as supporting major 14 — this does not.

Versions at or below the installed one are filtered out, so the result is
always a genuine upgrade path rather than a sideways move.

Only packages of Composer type `typo3-cms-*` are queried.

**Privacy note:** every queried package name goes to packagist.org. A
`composer.lock` with packages from a private or path repository sends those
names too. Such packages have no `notification-url` in the lockfile, which makes
them straightforward to recognise — this tool does not yet filter on it.

### Vulnerabilities — `check_vulns_batch(nodes)`

Queries [OSV](https://osv.dev) via `/v1/querybatch` (chunked at 1000, which is
the API limit), then resolves every distinct advisory ID through `/v1/vulns/{id}`
for its summary and severity. Detail lookups run in a small thread pool and are
cached for the process lifetime — TYPO3 subpackages share most advisories, which
collapses the majority of those requests.

**The one thing worth copying even if you use nothing else:** the function
returns `{"ok": bool, "error": str}` and raises `OsvScanError` rather than
returning an empty list when OSV is unreachable. "No package is vulnerable" and
"the scan did not run" leave identical data behind, and reporting the second as
an all-clear is the failure mode that actually hurts. It also verifies that OSV
returned exactly as many results as packages sent — a short response would
silently shift every later package's vulnerabilities onto the wrong package.

### SBOM — `generate_sbom(nodes, edges)`

CycloneDX 1.5 JSON with `pkg:composer/...` purls, licences where the lockfile
carries them, and a full `dependencies` tree built from the `require` graph.
Dev-only packages get CycloneDX scope `optional`, everything else `required`.

## Data shape

`parse_lock_bytes()` returns the packages from both `packages` and
`packages-dev`, the latter flagged `dev: True` — dev dependencies carry real
CVEs and belong in the scan and the SBOM; filter on the flag if you need
production-only data.

`build_packages()` turns them into `nodes` and `edges`:

```python
node = {"id": 1, "label": "Package", "name": "typo3/cms-core",
        "props": {"version": "12.4.8", "type": "typo3-cms-framework", ...}}
edge = {"id": 1, "src": 1, "dst": 2, "rel": "REQUIRES",
        "props": {"constraint": "^12.4"}}
```

The two check functions mutate `node["props"]` in place, so they compose in any
order. `run_audit()` wires all three together and returns a summary dict.

## Licence

MIT — see [LICENSE](LICENSE).
