"""Tests for the upgrade-readiness check.

Every case here is taken from a real composer.lock — the 14 public third-party
extensions of a production TYPO3 13.4 site, measured on 2026-09-27. Each one
made the previous version of this code report work that does not exist.

The network layer is exercised through httpx's MockTransport rather than a
hand-written fake, so the real client code runs.
"""
import httpx
import pytest

import composer_audit as audit


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler), timeout=5)


def _packagist(versions):
    """A response shaped like packagist.org/packages/<name>.json."""
    def handler(request):
        return httpx.Response(200, json={"package": {"versions": versions}})
    return handler


def _release(core_requires):
    return {"require": core_requires}


# --- constraint parsing ------------------------------------------------------

def test_star_allows_every_major():
    # apache-solr-for-typo3/solr lists six core packages as "*". Without this,
    # the package fails the all-must-allow rule and is reported as blocked.
    assert audit._constraint_allows_major("*", 14) is True


def test_patch_number_is_not_a_major():
    assert audit._constraint_allows_major("^11.5.14", 14) is False


# --- not every extension requires typo3/cms-core -----------------------------

def test_constraint_on_cms_backend_counts_too():
    """b13/container 4.1.0 requires typo3/cms-backend: ^13.4 || ^14.3 and no
    typo3/cms-core at all. The core packages are versioned in lockstep, so any
    typo3/cms-* requirement answers the question."""
    with _client(_packagist({
        "4.1.0": _release({"typo3/cms-backend": "^13.4 || ^14.3"}),
    })) as client:
        result = audit._check_upgrade_single(client, "b13/container", 14, "3.1.10")
    assert result["upgrade_status"] == "green"
    assert result["upgrade_source"] == "typo3/cms-backend"


def test_every_typo3_requirement_must_allow_the_target():
    # Composer could not resolve this: core admits 14, fluid does not.
    with _client(_packagist({
        "2.0.0": _release({"typo3/cms-core": "^13.4 || ^14.0", "typo3/cms-fluid": "^13.4"}),
    })) as client:
        result = audit._check_upgrade_single(client, "a/b", 14, "1.0.0")
    assert result["upgrade_status"] == "red"


def test_cms_core_is_the_preferred_source():
    with _client(_packagist({
        "2.0.0": _release({"typo3/cms-backend": "^14.0", "typo3/cms-core": "^14.0"}),
    })) as client:
        result = audit._check_upgrade_single(client, "a/b", 14, "1.0.0")
    assert result["upgrade_source"] == "typo3/cms-core"


def test_package_without_any_typo3_requirement_is_unverifiable():
    """bk2k/iconset-typo3 depends only on bk2k/bootstrap-package. We do not
    know — and "we do not know" is not "it does not work"."""
    with _client(_packagist({
        "1.0.3": _release({"bk2k/bootstrap-package": "^12 || ^13 || ^14"}),
    })) as client:
        result = audit._check_upgrade_single(client, "bk2k/iconset-typo3", 14, "1.0.3")
    assert result["upgrade_status"] == "unverifiable"
    assert "bk2k/bootstrap-package" in result["upgrade_note"]


# --- an unanswered request is not an answer ----------------------------------

def test_404_means_packagist_does_not_know_the_package():
    with _client(lambda request: httpx.Response(404)) as client:
        result = audit._check_upgrade_single(client, "private/thing", 14, "1.0.0")
    assert result["upgrade_status"] == "unknown"


def test_transport_failure_is_not_the_same_as_404():
    """The failure mode that actually hurts: a dropped network looked exactly
    like a package Packagist has never heard of."""
    def boom(request):
        raise httpx.ConnectError("Name or service not known")

    with _client(boom) as client:
        result = audit._check_upgrade_single(client, "a/b", 14, "1.0.0")
    assert result["upgrade_status"] == "unreachable"
    assert "Name or service not known" in result["upgrade_note"]


def test_malformed_json_is_unreachable_not_unknown():
    with _client(lambda request: httpx.Response(200, text="<html>502</html>")) as client:
        result = audit._check_upgrade_single(client, "a/b", 14, "1.0.0")
    assert result["upgrade_status"] == "unreachable"


# --- the summary must not drop packages --------------------------------------

def _lock(*pakete):
    import json
    return json.dumps({"packages": list(pakete), "packages-dev": []}).encode()



def _pkg(name, version="1.0.0"):
    return {"name": name, "version": version, "type": "typo3-cms-extension",
            "require": {}, "dist": {}, "source": {}}


def test_summary_counts_every_package(monkeypatch):
    """The printed line read '32 ready, 0 already there, 1 pre-release only,
    6 blocked' out of 39 packages — the rest were silently dropped."""
    zustaende = iter(["green", "unknown", "unverifiable", "unreachable"])
    monkeypatch.setattr(
        audit, "check_upgrade_batch",
        lambda nodes, target: [n["props"].update({"upgrade_status": next(zustaende)}) for n in nodes],
    )
    monkeypatch.setattr(audit, "check_vulns_batch", lambda nodes: {"ok": True, "error": ""})

    report = audit.run_audit(
        _lock(_pkg("a/one"), _pkg("a/two"), _pkg("a/three"), _pkg("a/four")),
        target_major=14,
    )
    up = report["upgrade"]
    assert (up["green"], up["unknown"], up["unverifiable"], up["unreachable"]) == (1, 1, 1, 1)
    assert up["green"] + up["yellow"] + up["red"] + up["current"] + up["unknown"] \
        + up["unverifiable"] + up["unreachable"] == len(up["packages"])


def test_an_incomplete_scan_does_not_exit_zero(monkeypatch, tmp_path):
    """Same rule the vulnerability scan already follows: 'the scan did not run'
    must never look like an all-clear."""
    monkeypatch.setattr(
        audit, "check_upgrade_batch",
        lambda nodes, target: [n["props"].update({"upgrade_status": "unreachable"}) for n in nodes],
    )
    monkeypatch.setattr(audit, "check_vulns_batch", lambda nodes: {"ok": True, "error": ""})

    lock = tmp_path / "composer.lock"
    lock.write_bytes(_lock(_pkg("a/one")))
    assert audit.main([str(lock)]) == 1




# --- private packages must not leave the machine -----------------------------
#
# Packagist is an external service. A composer.lock from a customer carries the
# names of their private extensions, and querying them sends those names out.
# The lockfile says which is which: packages pulled from Packagist carry a
# notification-url, packages from a path or private repository do not. On the
# production lockfile this separates 17 public from 10 private extensions.


def _lock_entry(name, private=False, typ="typo3-cms-extension"):
    entry = {"name": name, "version": "1.0.0", "type": typ, "require": {}}
    if not private:
        entry["notification-url"] = "https://packagist.org/downloads/"
    return entry


def test_public_origin_is_read_from_the_lockfile():
    nodes, _ = audit.build_packages(audit.parse_lock_bytes(
        _lock(_lock_entry("georgringer/news"))
    ))
    assert nodes[0]["props"]["public"] is True


def test_missing_notification_url_means_private():
    nodes, _ = audit.build_packages(audit.parse_lock_bytes(
        _lock(_lock_entry("acme/private-ext", private=True))
    ))
    assert nodes[0]["props"]["public"] is False


def test_private_package_name_is_never_sent(monkeypatch):
    """The promise this filter makes. Not believed — measured."""
    gesendet = []

    def spy(client, pkg_name, target_major, current_version=""):
        gesendet.append(pkg_name)
        return {"upgrade_status": "green"}

    monkeypatch.setattr(audit, "_check_upgrade_single", spy)
    nodes, _ = audit.build_packages(audit.parse_lock_bytes(_lock(
        _lock_entry("georgringer/news"),
        _lock_entry("acme/private-ext", private=True),
    )))
    audit.check_upgrade_batch(nodes, 14)

    assert gesendet == ["georgringer/news"]


def test_private_package_is_reported_not_dropped(monkeypatch):
    """Not querying it is not the same as it being fine — nor as it being
    broken. It needs a human, and it has to appear in the report to get one."""
    monkeypatch.setattr(
        audit, "_check_upgrade_single",
        lambda *a, **k: {"upgrade_status": "green"},
    )
    nodes, _ = audit.build_packages(audit.parse_lock_bytes(
        _lock(_lock_entry("acme/private-ext", private=True))
    ))
    audit.check_upgrade_batch(nodes, 14)

    assert nodes[0]["props"]["upgrade_status"] == "private"
    assert "not queried" in nodes[0]["props"]["upgrade_note"]


def test_private_packages_are_counted_in_the_summary(monkeypatch):
    monkeypatch.setattr(audit, "check_vulns_batch", lambda nodes: {"ok": True, "error": ""})
    monkeypatch.setattr(
        audit, "_check_upgrade_single",
        lambda *a, **k: {"upgrade_status": "green"},
    )
    report = audit.run_audit(
        _lock(_lock_entry("a/public"), _lock_entry("acme/another-private", private=True)),
        target_major=14,
    )
    up = report["upgrade"]
    assert (up["green"], up["private"]) == (1, 1)


def test_private_names_do_not_go_to_osv_either(monkeypatch):
    """Packagist is not the only way out. The vulnerability scan sends every
    package name to osv.dev, so a filter that only covers Packagist protects
    nothing."""
    gesendet = []

    def spy(queries):
        gesendet.extend(q["package"]["name"] for q in queries)
        return [{} for _ in queries]

    monkeypatch.setattr(audit, "_query_osv_batch", spy)
    nodes, _ = audit.build_packages(audit.parse_lock_bytes(_lock(
        _lock_entry("georgringer/news"),
        _lock_entry("acme/private-ext", private=True),
    )))
    audit.check_vulns_batch(nodes)

    assert gesendet == ["georgringer/news"]


def test_a_private_package_is_marked_as_not_scanned(monkeypatch):
    monkeypatch.setattr(audit, "_query_osv_batch", lambda queries: [{} for _ in queries])
    nodes, _ = audit.build_packages(audit.parse_lock_bytes(
        _lock(_lock_entry("acme/private-ext", private=True))
    ))
    audit.check_vulns_batch(nodes)

    assert nodes[0]["props"]["vuln_scan"] == "not scanned — private package"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
