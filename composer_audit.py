"""
composer_audit.py — composer.lock audit: upgrade readiness, vulnerabilities, SBOM.

Three independent checks over a Composer lockfile, with no storage layer and no
framework: only the standard library plus httpx.

  * Upgrade readiness — asks Packagist whether each TYPO3 extension has a release
    that admits a given typo3/cms-core major.
  * Vulnerabilities — batch-queries OSV (osv.dev) and resolves each advisory.
  * SBOM — renders a CycloneDX 1.5 document including the dependency tree.

Both data sources are public and need no API key.

    pip install httpx
    python composer_audit.py path/to/composer.lock --target 14

Licensed under the MIT License — see LICENSE.
"""

import json
import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import httpx

PACKAGIST_PKG = "https://packagist.org/packages/{name}.json"

#: Every outcome of the upgrade check. `unknown` (Packagist answered, no such
#: package — private packages land here), `unverifiable` (no typo3/cms-*
#: constraint anywhere) and `unreachable` (no answer at all) are three
#: different things and must never collapse into one.
UPGRADE_STATUSES = (
    "green", "yellow", "current", "red", "unknown", "unverifiable", "unreachable",
)

#: Any requirement on one of the core's split packages answers the target
#: question — they are released in lockstep. typo3/cms-core is preferred as the
#: reported source when a package names it, because "^14.3 on cms-backend" is a
#: different promise from the same string on cms-core.
TYPO3_CORE_PREFIX = "typo3/cms"
TYPO3_CORE = "typo3/cms-core"
OSV_QUERY_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN_DETAIL = "https://api.osv.dev/v1/vulns/{vuln_id}"
REQUEST_DELAY = 0.15
# OSV rejects batches above 1000 queries, so large locks are sent in chunks.
OSV_BATCH_SIZE = 1000
# Detail lookups are one cheap GET each; fetch them concurrently.
VULN_DETAIL_WORKERS = 8


# ---------------------------------------------------------------------------
# Parse
# ---------------------------------------------------------------------------

def parse_lock_bytes(content: bytes) -> list[dict]:
    """Parse composer.lock from raw upload bytes and return packages list.

    Includes `packages-dev`, stamped with ``dev: True``. Dev dependencies carry
    real CVEs and belong in both the vulnerability scan and the SBOM; callers
    that need production-only data filter on the flag.
    """
    data = json.loads(content)
    packages = []
    seen: set[str] = set()
    for key, is_dev in (("packages", False), ("packages-dev", True)):
        for pkg in data.get(key) or []:
            name = pkg.get("name", "")
            if not name or name in seen:
                continue
            seen.add(name)
            packages.append({**pkg, "dev": is_dev})
    return packages


# ---------------------------------------------------------------------------
# Build graph-like node/edge dicts (no DB needed)
# ---------------------------------------------------------------------------

def build_packages(packages: list[dict]) -> tuple[list[dict], list[dict]]:
    """Build nodes and edges lists from composer.lock packages.

    Returns (nodes, edges) where each node is
    {"id": int, "label": str, "name": str, "props": dict}
    and each edge is
    {"id": int, "src": int, "dst": int, "rel": "REQUIRES", "props": dict}.
    """
    pkg_names = {p["name"] for p in packages}
    pkg_id_map: dict[str, int] = {}
    nodes: list[dict] = []
    edges: list[dict] = []
    edge_id = 0

    for i, pkg in enumerate(packages, start=1):
        name = pkg["name"]
        pkg_id_map[name] = i

        is_core = name == "typo3/cms-core"
        label = "Framework" if is_core else "Package"

        props: dict = {"version": pkg.get("version", "")}
        if pkg.get("dev"):
            props["dev"] = True
        if pkg.get("description"):
            props["description"] = pkg["description"]
        if pkg.get("type"):
            props["type"] = pkg["type"]
        license_info = pkg.get("license")
        if license_info:
            props["license"] = license_info[0] if isinstance(license_info, list) else license_info

        nodes.append({"id": i, "label": label, "name": name, "props": props})

    for pkg in packages:
        name = pkg["name"]
        if name not in pkg_id_map:
            continue
        src_id = pkg_id_map[name]
        for dep_name, constraint in pkg.get("require", {}).items():
            if dep_name in pkg_id_map:
                edge_id += 1
                edges.append({
                    "id": edge_id,
                    "src": src_id,
                    "dst": pkg_id_map[dep_name],
                    "rel": "REQUIRES",
                    "props": {"constraint": constraint},
                })

    return nodes, edges


# ---------------------------------------------------------------------------
# Upgrade readiness (Packagist API)
# ---------------------------------------------------------------------------

_PRE_TAGS = ("rc", "beta", "alpha", "dev", "x-dev")


def _parse_ver_tuple(ver: str) -> tuple[int, int, int]:
    """Best-effort version tuple for ordering. Strips 'v' prefix and pre-release suffix."""
    if not ver:
        return (0, 0, 0)
    m = re.match(r"v?(\d+)(?:\.(\d+))?(?:\.(\d+))?", ver)
    if not m:
        return (0, 0, 0)
    return (int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0))


def _constraint_allows_major(constraint: str, target_major: int) -> bool:
    """Return True if Composer constraint admits any version in the target major series.

    Handles common shapes: ``^N``, ``^N.M``, ``~N``, ``~N.M``, ``>=N``, ``>N``, ``<N``,
    ``<=N``, ``N.*``, exact ``N.M.P``, OR-alternates joined by ``||``, and AND-segments
    separated by whitespace or comma. Substring matches inside patch numbers (e.g.
    ``^11.5.14`` for target_major=14) are no longer false positives.
    """
    if not constraint:
        return False
    for alt in constraint.split("||"):
        if _segment_allows(alt.strip(), target_major):
            return True
    return False


def _segment_allows(seg: str, target_major: int) -> bool:
    parts = [p for p in re.split(r"[\s,]+", seg) if p]
    if not parts:
        return False
    return all(_part_allows(p, target_major) for p in parts)


def _part_allows(part: str, target_major: int) -> bool:
    # A bare "*" admits everything. apache-solr-for-typo3/solr lists six core
    # packages that way; under the all-must-allow rule below, failing to
    # understand it would report the package as blocked.
    if part.lstrip("v") in ("*", "*.*", "*.*.*"):
        return True
    m = re.match(r"^(\^|~|>=|<=|>|<|=)?\s*v?(\d+)(?:\.(\d+|\*|x))?", part)
    if not m:
        return False
    op = m.group(1) or "="
    major = int(m.group(2))
    if op == "^":
        return major == target_major
    if op == "~":
        return major == target_major
    if op in (">=", ">"):
        return target_major >= major
    if op == "<":
        return target_major < major
    if op == "<=":
        return target_major <= major
    return major == target_major


def _check_upgrade_single(
    client: httpx.Client,
    pkg_name: str,
    target_major: int,
    current_version: str = "",
) -> dict:
    """Check Packagist if a version exists supporting typo3/cms-core ^{target_major}.

    Filters out versions older than ``current_version`` and returns the highest
    stable match (falls back to highest pre-release if no stable match exists).
    """
    try:
        resp = client.get(PACKAGIST_PKG.format(name=pkg_name))
    except httpx.HTTPError as exc:
        # The failure mode that actually hurts: a dropped network used to look
        # exactly like a package Packagist has never heard of, and a whole
        # unreachable run came out as a list of dead extensions.
        return {"upgrade_status": "unreachable", "upgrade_note": str(exc)}
    if resp.status_code == 404:
        # A real answer: Packagist has no entry. Private packages land here.
        return {"upgrade_status": "unknown",
                "upgrade_note": "no entry on Packagist"}
    if resp.status_code != 200:
        return {"upgrade_status": "unreachable",
                "upgrade_note": f"HTTP {resp.status_code}"}
    try:
        versions = resp.json().get("package", {}).get("versions", {})
    except ValueError as exc:
        return {"upgrade_status": "unreachable",
                "upgrade_note": f"unreadable response: {exc}"}

    current_tuple = _parse_ver_tuple(current_version)
    stable: list[tuple] = []
    prerelease: list[tuple] = []
    current_supports_target = False
    foreign_requires = ""

    for ver_key, ver_data in versions.items():
        if ver_key.startswith("dev-"):
            continue
        ver_tuple = _parse_ver_tuple(ver_key)
        is_stable = not any(tag in ver_key.lower() for tag in _PRE_TAGS)
        is_current = current_tuple != (0, 0, 0) and ver_tuple == current_tuple

        if pkg_name == "typo3/cms-core":
            matches_target = bool(re.match(rf"v?{target_major}\.", ver_key))
            if is_current and matches_target:
                current_supports_target = True
            if not matches_target:
                continue
            if ver_tuple <= current_tuple:
                continue
            entry = (ver_tuple, ver_key, "self", TYPO3_CORE)
            (stable if is_stable else prerelease).append(entry)
            continue

        requires = ver_data.get("require", {})
        if not isinstance(requires, dict):
            requires = {}
        # The core's split packages are released in lockstep, so a requirement
        # on any typo3/cms-* package answers the question. Not every extension
        # names typo3/cms-core: b13/container 4.1.0 gets by with
        # typo3/cms-backend "^13.4 || ^14.3" and was reported as blocked
        # although it supports the target explicitly.
        core_requires = {
            k: str(v) for k, v in requires.items() if k.startswith(TYPO3_CORE_PREFIX)
        }
        if not core_requires:
            # No evidence either way. Remember what it does depend on — that is
            # the trail someone has to follow by hand.
            if not foreign_requires:
                foreign_requires = ", ".join(
                    f"{k} ({v})" for k, v in list(requires.items())[:3]
                )
            continue
        # ALL of them must allow the target: if cms-core admits 14 but
        # cms-fluid does not, Composer could not resolve the install at all.
        allows = all(
            _constraint_allows_major(c, target_major) for c in core_requires.values()
        )
        if is_current and allows:
            current_supports_target = True
        if not allows:
            continue
        if ver_tuple <= current_tuple:
            continue
        source = TYPO3_CORE if TYPO3_CORE in core_requires else sorted(core_requires)[0]
        entry = (ver_tuple, ver_key, core_requires[source], source)
        (stable if is_stable else prerelease).append(entry)

    if stable:
        stable.sort(reverse=True)
        _, ver_key, constraint, source = stable[0]
        return {"upgrade_status": "green", "upgrade_version": ver_key,
                "upgrade_constraint": constraint, "upgrade_source": source}
    if prerelease:
        prerelease.sort(reverse=True)
        _, ver_key, constraint, source = prerelease[0]
        return {"upgrade_status": "yellow", "upgrade_version": ver_key,
                "upgrade_constraint": constraint, "upgrade_source": source}
    if current_supports_target:
        return {"upgrade_status": "current", "upgrade_version": current_version,
                "upgrade_constraint": "current", "upgrade_source": TYPO3_CORE}
    if foreign_requires:
        # No release names a typo3/cms-* package at all. bk2k/iconset-typo3
        # depends only on bk2k/bootstrap-package; its compatibility is
        # transitive. "We do not know" is not "it does not work".
        return {"upgrade_status": "unverifiable",
                "upgrade_note": f"no typo3/cms-* constraint in any release — depends on {foreign_requires}"}
    return {"upgrade_status": "red"}


def check_upgrade_batch(nodes: list[dict], target_major: int) -> None:
    """Check Packagist upgrade readiness for all TYPO3-typed packages. Mutates nodes in-place."""
    typo3_pkgs = [n for n in nodes if n["props"].get("type", "").startswith("typo3-cms-")]
    if not typo3_pkgs:
        return

    with httpx.Client(timeout=30, follow_redirects=True) as client:
        for n in typo3_pkgs:
            current = n["props"].get("version", "")
            result = _check_upgrade_single(client, n["name"], target_major, current_version=current)
            n["props"].update(result)
            time.sleep(REQUEST_DELAY)


# ---------------------------------------------------------------------------
# Vulnerability scan (OSV batch API)
# ---------------------------------------------------------------------------

class OsvScanError(RuntimeError):
    """OSV could not be queried — the result is unknown, not 'nothing found'."""


# CVSS vector strings are the fallback when no human-readable rating exists;
# newest scheme first.
_CVSS_TYPES = ("CVSS_V4", "CVSS_V3", "CVSS_V2")

# Vulnerability details are immutable enough to cache for the process lifetime.
# Advisories are shared across packages (all typo3/cms-* subpackages carry the
# same GHSA entries), so this collapses most of the detail lookups.
_vuln_detail_cache: dict[str, dict] = {}


def _extract_summary(detail: dict) -> str:
    """Advisory headline. CVE-only records carry no summary, only `details`."""
    summary = detail.get("summary")
    if summary:
        return summary
    details = (detail.get("details") or "").strip()
    return details.split("\n", 1)[0][:200]


def _extract_severity(detail: dict) -> str:
    """Pick the most readable severity from an OSV vulnerability record."""
    rating = detail.get("database_specific", {}).get("severity")
    if rating:
        return str(rating).capitalize()  # "MODERATE" -> "Moderate"
    scores = {s.get("type"): s.get("score", "") for s in detail.get("severity", [])}
    for cvss_type in _CVSS_TYPES:
        if scores.get(cvss_type):
            return scores[cvss_type]
    return "unknown"


def _fetch_vuln_detail(client: httpx.Client, vuln_id: str) -> None:
    """Fetch one advisory into the cache. Failures cache as empty, not retried."""
    try:
        resp = client.get(OSV_VULN_DETAIL.format(vuln_id=vuln_id))
        detail = resp.json() if resp.status_code == 200 else {}
    except (httpx.HTTPError, json.JSONDecodeError):
        detail = {}
    _vuln_detail_cache[vuln_id] = detail


def _load_vuln_details(vuln_ids: set[str]) -> None:
    """Populate the cache for every ID not seen before."""
    missing = sorted(vuln_ids - _vuln_detail_cache.keys())
    if not missing:
        return
    with httpx.Client(timeout=15, follow_redirects=True) as client:
        with ThreadPoolExecutor(max_workers=VULN_DETAIL_WORKERS) as pool:
            for vuln_id in missing:
                pool.submit(_fetch_vuln_detail, client, vuln_id)


def _query_osv_batch(queries: list[dict]) -> list[dict]:
    """POST queries to OSV in chunks. Returns one result dict per query.

    Raises OsvScanError instead of returning empty results: "OSV is
    unreachable" and "no package is vulnerable" must never look alike.
    """
    results: list[dict] = []
    with httpx.Client(timeout=30, follow_redirects=True) as client:
        for start in range(0, len(queries), OSV_BATCH_SIZE):
            chunk = queries[start:start + OSV_BATCH_SIZE]
            try:
                resp = client.post(OSV_QUERY_BATCH, json={"queries": chunk})
            except httpx.HTTPError as exc:
                raise OsvScanError(f"OSV API unreachable: {exc}") from exc
            if resp.status_code != 200:
                raise OsvScanError(f"OSV API returned HTTP {resp.status_code}")
            try:
                chunk_results = resp.json().get("results", [])
            except json.JSONDecodeError as exc:
                raise OsvScanError("OSV API returned malformed JSON") from exc
            # A short response would silently shift every later package's vulns.
            if len(chunk_results) != len(chunk):
                raise OsvScanError(
                    f"OSV API returned {len(chunk_results)} results for {len(chunk)} packages"
                )
            results.extend(chunk_results)
    return results


def check_vulns_batch(nodes: list[dict]) -> dict:
    """Query OSV API for known vulnerabilities. Mutates nodes in-place.

    /v1/querybatch returns only vulnerability IDs, so every distinct ID is
    resolved via /v1/vulns/{id} to get its summary and severity.

    Returns the scan status as {"ok": bool, "error": str}. Callers must not
    read "no vulns on any node" as an all-clear without checking `ok` — a
    failed scan leaves the nodes untouched and looks identical.
    """
    # Kept in step with `queries`: nodes without a version are never queried,
    # so results must be mapped back through this list, not through `nodes`.
    queried_nodes = []
    queries = []
    for node in nodes:
        version = node["props"].get("version", "").lstrip("v")
        if not version:
            continue
        queried_nodes.append(node)
        queries.append({
            "package": {"name": node["name"], "ecosystem": "Packagist"},
            "version": version,
        })

    if not queries:
        return {"ok": True, "error": ""}

    try:
        results = _query_osv_batch(queries)
    except OsvScanError as exc:
        return {"ok": False, "error": str(exc)}

    ids_per_node = [
        [v.get("id", "") for v in result.get("vulns", []) if v.get("id")]
        for result in results
    ]
    _load_vuln_details({vuln_id for ids in ids_per_node for vuln_id in ids})

    for node, vuln_ids in zip(queried_nodes, ids_per_node):
        if not vuln_ids:
            continue
        vulns = []
        for vuln_id in vuln_ids:
            detail = _vuln_detail_cache.get(vuln_id, {})
            vulns.append({
                "id": vuln_id,
                "summary": _extract_summary(detail),
                "severity": _extract_severity(detail),
                "aliases": [a for a in detail.get("aliases", []) if a.startswith("CVE-")],
            })
        node["props"]["vulns"] = vulns

    return {"ok": True, "error": ""}


# ---------------------------------------------------------------------------
# SBOM generation (CycloneDX 1.5)
# ---------------------------------------------------------------------------

def _make_purl(name: str, version: str) -> str:
    vendor, pkg = name.split("/", 1) if "/" in name else ("", name)
    ver = version.lstrip("v")
    return f"pkg:composer/{vendor}/{pkg}@{ver}"


def generate_sbom(nodes: list[dict], edges: list[dict]) -> dict:
    """Generate CycloneDX 1.5 JSON SBOM from nodes/edges."""
    id_to_name = {n["id"]: n["name"] for n in nodes}
    dep_map: dict[str, list[str]] = {}
    for edge in edges:
        if edge["rel"] == "REQUIRES":
            src_name = id_to_name.get(edge["src"], "")
            dst_name = id_to_name.get(edge["dst"], "")
            if src_name and dst_name:
                dep_map.setdefault(src_name, []).append(dst_name)

    components = []
    for node in nodes:
        props = node.get("props", {})
        version = props.get("version", "")
        component = {
            "type": "library",
            "name": node["name"],
            "version": version.lstrip("v"),
            "purl": _make_purl(node["name"], version),
            # CycloneDX scope: dev-only dependencies are not required at runtime.
            "scope": "optional" if props.get("dev") else "required",
        }
        if props.get("description"):
            component["description"] = props["description"]
        if props.get("license"):
            component["licenses"] = [{"license": {"id": props["license"]}}]
        components.append(component)

    dependencies = []
    for node in nodes:
        ref = _make_purl(node["name"], node["props"].get("version", ""))
        dep_refs = []
        for dep_name in dep_map.get(node["name"], []):
            dep_node = next((n for n in nodes if n["name"] == dep_name), None)
            if dep_node:
                dep_refs.append(_make_purl(dep_name, dep_node["props"].get("version", "")))
        dependencies.append({"ref": ref, "dependsOn": dep_refs})

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "dkd", "name": "composer-audit", "version": "0.1.0"}],
        },
        "components": components,
        "dependencies": dependencies,
    }


# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run_audit(lock_bytes: bytes, target_major: int = 14) -> dict:
    """Run the full pipeline over composer.lock bytes and return a report dict."""
    packages = parse_lock_bytes(lock_bytes)
    if not packages:
        return {"error": "No packages found in composer.lock"}

    nodes, edges = build_packages(packages)

    check_upgrade_batch(nodes, target_major)
    vuln_scan = check_vulns_batch(nodes)
    sbom = generate_sbom(nodes, edges)

    upgrade_packages = []
    # Every status gets a counter. Previously `unknown` was counted nowhere and
    # printed nowhere: the summary line read "32 ready, 0 already there, 1
    # pre-release only, 6 blocked" for 39 packages, and the remainder simply
    # vanished. A package nobody could check is not a package that is fine.
    tally = {s: 0 for s in UPGRADE_STATUSES}
    for n in nodes:
        status = n["props"].get("upgrade_status")
        if not status:
            continue
        tally[status] = tally.get(status, 0) + 1
        upgrade_packages.append({
            "name": n["name"],
            "version": n["props"].get("version", ""),
            "upgrade_status": status,
            "upgrade_version": n["props"].get("upgrade_version", ""),
            "upgrade_constraint": n["props"].get("upgrade_constraint", ""),
            "upgrade_source": n["props"].get("upgrade_source", ""),
            "upgrade_note": n["props"].get("upgrade_note", ""),
            "type": n["props"].get("type", ""),
            "dev": n["props"].get("dev", False),
        })

    security_packages = []
    total_vulns = 0
    for n in nodes:
        vulns = n["props"].get("vulns", [])
        if vulns:
            total_vulns += len(vulns)
            security_packages.append({
                "name": n["name"],
                "version": n["props"].get("version", ""),
                "vulns": vulns,
                "dev": n["props"].get("dev", False),
            })

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "packages_total": len(nodes),
        "packages_dev": sum(1 for n in nodes if n["props"].get("dev")),
        "target_major": target_major,
        "upgrade": {
            "target": target_major,
            **tally,
            # True only when every package got a real answer. Same rule the
            # vulnerability scan already follows: "the scan did not run" must
            # never be reported as an all-clear.
            "scan_ok": tally["unreachable"] == 0,
            "packages": upgrade_packages,
        },
        "security": {
            "total_vulns": total_vulns,
            "packages": security_packages,
            # A failed scan leaves every node untouched and is indistinguishable
            # from a clean result — never report an all-clear without this flag.
            "scan_ok": vuln_scan["ok"],
            "scan_error": vuln_scan["error"],
        },
        "sbom": sbom,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Audit a composer.lock file.")
    parser.add_argument("lockfile", help="path to composer.lock")
    parser.add_argument("--target", type=int, default=14,
                        help="target typo3/cms-core major (default: 14)")
    parser.add_argument("--sbom", metavar="FILE",
                        help="also write the CycloneDX SBOM to this file")
    args = parser.parse_args(argv)

    with open(args.lockfile, "rb") as fh:
        report = run_audit(fh.read(), target_major=args.target)

    if "error" in report:
        print(report["error"])
        return 1

    up = report["upgrade"]
    sec = report["security"]
    print(f"{report['packages_total']} packages ({report['packages_dev']} dev)")
    print(f"Upgrade to {up['target']}: {up['green']} ready, {up['current']} already there, "
          f"{up['yellow']} pre-release only, {up['red']} blocked")
    # Not a footnote: these are the packages about which nothing was learned.
    if up["unknown"] or up["unverifiable"] or up["unreachable"]:
        print(f"  not answered: {up['unknown']} unknown to Packagist, "
              f"{up['unverifiable']} without a typo3/cms-* constraint, "
              f"{up['unreachable']} unreachable")
    if sec["scan_ok"]:
        print(f"Vulnerabilities: {sec['total_vulns']} in {len(sec['packages'])} packages")
    else:
        print(f"Vulnerability scan FAILED: {sec['scan_error']}")

    if args.sbom:
        with open(args.sbom, "w", encoding="utf-8") as fh:
            json.dump(report["sbom"], fh, indent=2)
        print(f"SBOM written to {args.sbom}")

    # Non-zero when something is blocked or either scan could not be completed.
    return 1 if up["red"] or not up["scan_ok"] or not sec["scan_ok"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
