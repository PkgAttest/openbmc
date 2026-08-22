"""IMA log parsing and cross-reference against package measurements."""

import json
import os
import subprocess
import sys

import pytest

from pkgintegrity import imalog

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
D_DOC = os.path.join(BASE, "artifacts", "D",
                     "obmc-phosphor-image-raspberrypi3-64.pkg-measurements.json")
B_DOC = os.path.join(BASE, "artifacts", "B",
                     "obmc-phosphor-image-raspberrypi3-64.pkg-measurements.json")

pytestmark = pytest.mark.skipif(not os.path.exists(D_DOC),
                                reason="image D artifacts not built here")


def line(digest, path, algo="sha256", pcr=10):
    return "%d %s ima-ng %s:%s %s" % (pcr, "ab" * 20, algo, digest, path)


def load(path=D_DOC):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------- parsing

def test_parses_the_ima_ng_template():
    ev = imalog.parse_log(line("aa" * 32, "/usr/bin/true"))
    assert len(ev) == 1
    assert ev[0]["pcr"] == 10
    assert ev[0]["algo"] == "sha256"
    assert ev[0]["digest"] == "aa" * 32
    assert ev[0]["path"] == "/usr/bin/true"


def test_pathname_may_contain_spaces():
    # The pathname is the last field and is not quoted or escaped, so a
    # greedy split on whitespace truncates it.
    ev = imalog.parse_log(line("aa" * 32, "/usr/share/x/My File.crt"))
    assert ev[0]["path"] == "/usr/share/x/My File.crt"


def test_blank_and_comment_lines_are_skipped():
    text = "\n".join(["# header", "", line("aa" * 32, "/bin/sh"), "  "])
    assert len(imalog.parse_log(text)) == 1


def test_an_unparseable_line_is_fatal_not_skipped():
    # Silently dropping a line in a verifier is how you miss the one event
    # that mattered.
    text = line("aa" * 32, "/bin/sh") + "\nnot a measurement at all\n"
    with pytest.raises(imalog.ImaParseError) as e:
        imalog.parse_log(text)
    assert "line 2" in str(e.value)


def test_digests_are_normalised_to_lowercase():
    ev = imalog.parse_log(line("AB" * 32, "/bin/sh"))
    assert ev[0]["digest"] == "ab" * 32


# ------------------------------------------------------------ cross-ref

def test_a_real_measured_file_matches():
    doc = load()
    index = imalog.file_index(doc)
    path, (digest, pkg) = next(iter(index.items()))
    r = imalog.cross_reference(imalog.parse_log(line(digest, path)), index)
    assert len(r["matched"]) == 1
    assert r["matched"][0]["package"] == pkg
    assert not imalog.findings(r)


def test_same_path_different_content_is_modified():
    doc = load()
    index = imalog.file_index(doc)
    path, (digest, pkg) = next(iter(index.items()))
    r = imalog.cross_reference(imalog.parse_log(line("cc" * 32, path)), index)
    assert len(r["modified"]) == 1
    assert r["modified"][0]["expected"] == digest
    assert r["modified"][0]["digest"] == "cc" * 32
    assert r["modified"][0]["package"] == pkg
    assert len(imalog.findings(r)) == 1


def test_a_path_no_package_owns_is_unmeasured():
    index = imalog.file_index(load())
    r = imalog.cross_reference(
        imalog.parse_log(line("dd" * 32, "/tmp/.x/kworkerd")), index)
    assert [e["path"] for e in r["unmeasured"]] == ["/tmp/.x/kworkerd"]
    assert len(imalog.findings(r)) == 1


def test_boot_aggregate_is_not_treated_as_a_file():
    index = imalog.file_index(load())
    r = imalog.cross_reference(
        imalog.parse_log(line("00" * 32, "boot_aggregate")), index)
    assert len(r["boot_aggregate"]) == 1
    assert not r["unmeasured"] and not imalog.findings(r)


def test_a_sha1_log_is_incomparable_not_an_accusation():
    # A sha1 IMA log cannot be compared with sha256 measurements. Reporting
    # those events as "unmeasured" would be a false accusation.
    doc = load()
    index = imalog.file_index(doc)
    path = next(iter(index))
    r = imalog.cross_reference(
        imalog.parse_log(line("ee" * 20, path, algo="sha1")), index)
    assert len(r["incomparable"]) == 1
    assert not r["unmeasured"] and not r["modified"]
    assert not imalog.findings(r)


def test_unowned_files_resolve_because_image_d_measures_them():
    # Image D added the "(unowned)" leaf. Without it these paths -- created
    # by postinst scripts, owned by no package -- would each be reported as
    # an intruder.
    doc = load()
    index = imalog.file_index(doc)
    unowned = [p["files"] for p in doc["packages"]
               if p["name"] == "(unowned)"]
    assert unowned, "image D must carry the (unowned) leaf"
    for f in unowned[0]:
        r = imalog.cross_reference(
            imalog.parse_log(line(f["sha256"], f["path"])), index)
        assert len(r["matched"]) == 1, f["path"]
        assert r["matched"][0]["package"] == "(unowned)"


def test_image_b_lacks_the_unowned_leaf_so_those_paths_look_like_intruders():
    # The converse, and the reason D exists: on B, /etc/passwd is an intruder.
    if not os.path.exists(B_DOC):
        pytest.skip("image B artifacts not built here")
    index = imalog.file_index(load(B_DOC))
    r = imalog.cross_reference(
        imalog.parse_log(line("11" * 32, "/etc/passwd")), index)
    assert [e["path"] for e in r["unmeasured"]] == ["/etc/passwd"]


def test_summarise_is_stable_and_covers_every_bucket():
    r = imalog.cross_reference([], {})
    names = [n for n, _, _ in imalog.summarise(r)]
    assert names == ["matched", "modified", "unmeasured", "incomparable",
                     "boot_aggregate"]
    # Every bucket cross_reference can fill must appear in the summary, or a
    # category of finding would be silently dropped from the report.
    assert set(names) == set(r)


# -------------------------------------------------------------- the CLI

def run(*args):
    return subprocess.run([sys.executable, "-m", "pkgintegrity.cli"] +
                          list(args), capture_output=True, text=True,
                          cwd=BASE)


def demo_log(tmp_path, *extra, doc=D_DOC):
    out = str(tmp_path / "ima.log")
    r = subprocess.run(
        [sys.executable, os.path.join(BASE, "tools", "make_demo_ima_log.py"),
         "--measurements", doc, "--limit", "40", "--out", out] + list(extra),
        capture_output=True, text=True, cwd=BASE)
    assert r.returncode == 0, r.stderr
    return out


def test_cli_clean_log_exits_zero(tmp_path):
    r = run("verify-ima", "--measurements", D_DOC, demo_log(tmp_path))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "OK:" in r.stdout


def test_cli_reports_both_finding_kinds(tmp_path):
    log = demo_log(tmp_path, "--modify", "/usr/sbin/dropbearmulti",
                   "--intruder", "/tmp/.x/kworkerd")
    r = run("verify-ima", "--measurements", D_DOC, "--json", log)
    assert r.returncode == 1
    out = json.loads(r.stdout)
    assert out["ok"] is False
    assert out["counts"]["modified"] == 1
    assert out["counts"]["unmeasured"] == 1
    assert out["modified"][0]["path"] == "/usr/sbin/dropbearmulti"
    assert out["modified"][0]["package"] == "dropbear"
    assert out["unmeasured"] == ["/tmp/.x/kworkerd"]


def test_cli_says_so_when_reference_values_are_unanchored(tmp_path):
    # Without --anchor the reference values are taken on trust. If the tool
    # ever stops saying that, a self-consistent forged document reads clean.
    r = run("verify-ima", "--measurements", D_DOC, demo_log(tmp_path))
    assert "UNANCHORED" in r.stdout
    assert "--anchor" in r.stdout


def test_cli_refuses_a_document_that_does_not_recompute(tmp_path):
    doc = load()
    doc["packages"][0]["leaf_hash"] = "00" * 32
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(doc))
    r = run("verify-ima", "--measurements", str(bad), demo_log(tmp_path))
    assert r.returncode == 2
    assert "refusing to judge" in r.stderr


def test_cli_rejects_a_log_it_cannot_parse(tmp_path):
    p = tmp_path / "junk.log"
    p.write_text("this is not an IMA log\n")
    r = run("verify-ima", "--measurements", D_DOC, str(p))
    assert r.returncode == 2
    assert "not an ima-ng measurement" in r.stderr


# ------------------------------------------------- anchoring to the log

def _server(tmp_path):
    import threading
    from http.server import ThreadingHTTPServer
    sys.path.insert(0, BASE)
    import log_server
    log_server.LOG = log_server.Log(
        str(tmp_path), os.path.join(BASE, "keys", "log_ed25519.key"),
        os.path.join(BASE, "keys", "log_ed25519.pub"))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), log_server.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, "http://127.0.0.1:%d" % httpd.server_address[1]


def _publish(url, doc, skip=()):
    from pkgintegrity.logclient import LogClient
    records = [{"name": p["name"], "version": p["version"],
                "arch": p["arch"], "image_line": doc["image_line"],
                "pkg_leaf_hash": p["leaf_hash"]}
               for p in doc["packages"] if p["name"] not in skip]
    LogClient(url).add_entries(records)


@pytest.fixture
def small(tmp_path):
    """A tiny published log, so anchoring is tested without image D's 2132."""
    from conftest import make_measurements_doc
    doc = make_measurements_doc(n_pkgs=6)
    for pkg in doc["packages"]:
        for f in pkg["files"]:
            f.setdefault("path", "/usr/bin/%s" % pkg["name"])
    return doc


def test_anchor_proves_every_leaf_is_in_the_log(tmp_path, small):
    httpd, url = _server(tmp_path / "log")
    try:
        _publish(url, small)
        p = tmp_path / "m.json"
        p.write_text(json.dumps(small))
        ima = tmp_path / "ima.log"
        pkg = small["packages"][0]
        ima.write_text(line(pkg["files"][0]["sha256"],
                            pkg["files"][0]["path"]) + "\n")
        r = run("verify-ima", "--measurements", str(p), "--anchor",
                "--log", url, "--json", str(ima))
        assert r.returncode == 0, r.stdout + r.stderr
        out = json.loads(r.stdout)
        assert out["anchor"]["missing"] == []
        assert out["anchor"]["packages"] == len(small["packages"])
        assert out["ok"] is True
    finally:
        httpd.shutdown()


def test_anchor_names_a_package_the_log_never_saw(tmp_path, small):
    # The whole point: a measurement document can be internally perfect and
    # still describe packages nobody ever published.
    httpd, url = _server(tmp_path / "log")
    try:
        held_back = small["packages"][1]["name"]
        _publish(url, small, skip=(held_back,))
        p = tmp_path / "m.json"
        p.write_text(json.dumps(small))
        ima = tmp_path / "ima.log"
        ima.write_text(line("00" * 32, "boot_aggregate") + "\n")
        r = run("verify-ima", "--measurements", str(p), "--anchor",
                "--log", url, "--json", str(ima))
        # No IMA finding at all, yet the run must still fail.
        out = json.loads(r.stdout)
        assert out["counts"]["modified"] == 0
        assert out["counts"]["unmeasured"] == 0
        assert out["anchor"]["missing"] == [held_back]
        assert out["ok"] is False
        assert r.returncode == 1
    finally:
        httpd.shutdown()
