"""pkgattest — command-line verification tools for package-aware integrity.

Subcommands:
  verify-image         signed phosphor update payloads (*.ext4.mmc.tar):
                       embedded pubkey pin, MANIFEST/publickey sigs, every
                       blob sig, image-full.sig (RSA/SHA256 PKCS#1 v1.5)
  verify-sth           transparency-log signed tree head (Ed25519)
  verify-package       per-package inclusion proof against the tree head
  verify-measurements  build measurement document: recompute every package
                       leaf and the merkle root
  verify-ima           a Linux IMA measurement log against those package
                       measurements: what ran, what was modified, and what
                       ran that no package installed
  attest               full device attestation chain (nonce -> ssh collect
                       -> root -> PCR14 -> TPM quote -> inclusion proofs)

Exit codes: 0 verified, 1 verification failure, 2 operational error.
"""

import argparse
import datetime
import hashlib
import json
import os
import sys

from . import canonical, imagesig, imalog, merkle
from .canonical import abbrev, display_version
from .logclient import LogClient

# Repo layout default (editable install / in-tree run): keys live in
# <repo>/keys next to this package. Every path is overridable by flag.
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _iso(ts):
    try:
        return datetime.datetime.fromtimestamp(
            int(ts), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OverflowError, OSError):
        return "?"


def _key_fingerprint(pub) -> str:
    """sha256 over the SPKI DER.

    This must stay the same definition the site bundle prints as `key_id`
    (pkgintegrity/site_export.py): the whole point of a fingerprint here is
    that a reader can compare what the CLI says against what the page says,
    and two different digests of the same key would read as a mismatch.
    """
    from cryptography.hazmat.primitives import serialization
    der = pub.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


# ---------------------------------------------------------------- verify-image
def cmd_verify_image(args):
    try:
        with open(args.pubkey, "rb") as f:
            pinned = f.read()
    except OSError as e:
        print("verify-image: cannot read pinned pubkey: %s" % e,
              file=sys.stderr)
        return 2

    results = []
    for spec in args.images:
        label, _, path = spec.rpartition("=")
        if not label:
            label, path = os.path.basename(path), spec
        try:
            v = imagesig.verify_mmc_tar(path, pinned)
        except OSError as e:
            print("verify-image: %s: %s" % (path, e), file=sys.stderr)
            return 2
        results.append((label, v))

    if args.json:
        print(json.dumps(
            [{"label": lab, "path": v.path, "sha384": v.sha384,
              "verified": v.ok, "checks": v.checks}
             for lab, v in results], indent=1))
        return 0 if all(v.ok for _, v in results) else 1

    width = max(len(lab) for lab, _ in results)
    for lab, v in results:
        digest = v.sha384 if args.full else abbrev(v.sha384)
        verdict = "OK" if v.ok else "FAIL"
        print("%-*s  sha384: %s   verified: %s"
              % (width, lab, digest, verdict))
        if not v.ok:
            for name, ok in v.checks.items():
                if not ok:
                    print("%-*s      failed: %s" % (width, "", name))
    return 0 if all(v.ok for _, v in results) else 1


# ------------------------------------------------------------------ verify-sth
def cmd_verify_sth(args):
    try:
        if args.sth_file:
            with open(args.sth_file) as f:
                sth = json.load(f)
        else:
            sth = LogClient(args.log).sth()
    except Exception as e:
        print("verify-sth: cannot obtain STH: %s" % e, file=sys.stderr)
        return 2
    try:
        pub = merkle.load_ed25519_public(args.log_pub)
    except Exception as e:
        print("verify-sth: cannot load log public key %s: %s"
              % (args.log_pub, e), file=sys.stderr)
        return 2

    ok = merkle.verify_sth(pub, sth)
    fp = _key_fingerprint(pub)

    if args.print_payload:
        payload = merkle.sth_payload(sth["tree_size"], sth["root_hash"],
                                     sth["timestamp"])
        print("payload:   %s" % payload.decode().rstrip("\n"))
    if args.json:
        print(json.dumps({"sth": sth, "signature_ok": ok,
                          "key": args.log_pub, "key_sha256": fp}, indent=1))
        return 0 if ok else 1

    root = sth["root_hash"] if args.full else abbrev(sth["root_hash"])
    print("tree head  %s" % (args.sth_file or args.log))
    print("  size:      %d" % sth["tree_size"])
    print("  root:      %s" % root)
    print("  timestamp: %s (%s)" % (sth["timestamp"], _iso(sth["timestamp"])))
    print("  key:       %s (sha256 %s)"
          % (args.log_pub, fp if args.full else abbrev(fp)))
    print("  signature: %s (ed25519, pkg-log-sth-v1)"
          % ("OK" if ok else "FAIL"))
    return 0 if ok else 1


# -------------------------------------------------------------- verify-package
def cmd_verify_package(args):
    client = LogClient(args.log)
    try:
        pub = merkle.load_ed25519_public(args.log_pub)
        sth = client.sth()
    except Exception as e:
        print("verify-package: %s" % e, file=sys.stderr)
        return 2
    sig_ok = merkle.verify_sth(pub, sth)
    tree_size = sth["tree_size"]
    root_bytes = bytes.fromhex(sth["root_hash"])
    head = sth["root_hash"] if args.full else abbrev(sth["root_hash"])

    results = []
    for name in args.names:
        try:
            published = client.lookup(name, args.image_line)
        except Exception as e:
            print("verify-package: lookup %s: %s" % (name, e),
                  file=sys.stderr)
            return 2
        if args.version:
            published = [e for e in published
                         if args.version in (e["version"],
                                             display_version(e["version"]))]
        recs = []
        if published:
            hashes = {}
            for e in published:
                data = canonical.log_leaf_data(
                    args.image_line, name, e["version"], e["arch"],
                    e["pkg_leaf_hash"])
                hashes[merkle.leaf_hash(data).hex()] = e
            proofs = client.proofs_batch(list(hashes),
                                         tree_size)["proofs"]
            for lh, e in hashes.items():
                proof = proofs.get(lh)
                ok = bool(proof) and merkle.verify_inclusion(
                    bytes.fromhex(lh), proof["index"], tree_size,
                    [bytes.fromhex(x) for x in proof["path"]], root_bytes)
                recs.append({"version": e["version"], "arch": e["arch"],
                             "leaf_index": e.get("leaf_index"),
                             "leaf_hash": lh, "inclusion_ok": ok})
            recs.sort(key=lambda r: (r["version"], r["leaf_index"] or 0))
        results.append((name, recs))

    ok_overall = sig_ok and results and all(
        recs and all(r["inclusion_ok"] for r in recs)
        for _, recs in results)

    if args.json:
        print(json.dumps({
            "tree_head": sth["root_hash"], "tree_size": tree_size,
            "sth_signature_ok": sig_ok, "image_line": args.image_line,
            "packages": {n: r for n, r in results}, "ok": ok_overall,
        }, indent=1))
        return 0 if ok_overall else 1

    print("tree head %s  size %d  STH signature %s"
          % (head, tree_size, "OK" if sig_ok else "FAIL"))
    for name, recs in results:
        if not recs:
            what = ("version %s" % args.version) if args.version else "ever"
            print("%s  ->  no published record (%s) for image line %s"
                  % (name, what, args.image_line))
            continue
        for r in recs:
            print("%s %s (%s)  leaf_index %s  inclusion proof: %s"
                  % (name, display_version(r["version"]), r["arch"],
                     r["leaf_index"], "OK" if r["inclusion_ok"] else "FAIL"))
    return 0 if ok_overall else 1


# --------------------------------------------------------- verify-measurements
def cmd_verify_measurements(args):
    rc = 0
    out = []
    for path in args.docs:
        try:
            doc = canonical.load_measurements_json(path)
        except (OSError, ValueError) as e:
            print("verify-measurements: %s: %s" % (path, e), file=sys.stderr)
            rc = max(rc, 2)
            continue
        problems = canonical.verify_measurements_doc(doc)
        n = len(doc["packages"])
        out.append({"path": path, "packages": n,
                    "merkle_root": doc["merkle_root"],
                    "ok": not problems, "problems": problems})
        if problems:
            rc = max(rc, 1)
        if not args.json:
            root = (doc["merkle_root"] if args.full
                    else abbrev(doc["merkle_root"]))
            if problems:
                print("%s: FAIL (%d packages, root %s)" % (path, n, root))
                for p in problems[:20]:
                    print("  ! %s" % p)
                if len(problems) > 20:
                    print("  ... and %d more" % (len(problems) - 20))
            else:
                print("%s: OK — %d package leaves + merkle root recomputed"
                      " (root %s)" % (path, n, root))
    if args.json:
        print(json.dumps(out, indent=1))
    return rc


# ------------------------------------------------------------------ verify-ima
def cmd_verify_ima(args):
    """Judge an IMA event stream against build-derived reference values.

    IMA has evidence and no reference values; this has reference values and
    no runtime evidence. Comparing them is the whole point, and it produces
    two findings neither side can reach alone: a measured path whose content
    changed, and a path that executed while belonging to no package.
    """
    try:
        doc = canonical.load_measurements_json(args.measurements)
    except (OSError, ValueError) as e:
        print("verify-ima: %s" % e, file=sys.stderr)
        return 2

    problems = canonical.verify_measurements_doc(doc)
    if problems:
        print("verify-ima: the measurement document does not recompute (%s); "
              "refusing to judge anything against it" % problems[0],
              file=sys.stderr)
        return 2

    try:
        with open(args.ima_log, encoding="utf-8", errors="replace") as f:
            events = imalog.parse_log(f.read())
    except OSError as e:
        print("verify-ima: %s" % e, file=sys.stderr)
        return 2
    except imalog.ImaParseError as e:
        print("verify-ima: %s" % e, file=sys.stderr)
        return 2

    index = imalog.file_index(doc)
    result = imalog.cross_reference(events, index)
    bad = imalog.findings(result)

    # Without this, the reference values are only self-consistent: a tampered
    # rootfs shipped with a matching measurement document passes clean, which
    # is the exact "trust the vendor's own claim" pattern this project exists
    # to break.
    #
    # Every package leaf is anchored, not just the ones a verdict touched.
    # The "unmeasured" verdict rests on *no* package owning the path, so a
    # forged extra package in the document would launder a real intruder into
    # a match. Only proving the whole set is in the log closes that.
    anchor = None
    if args.anchor:
        try:
            client = LogClient(args.log)
            pub = merkle.load_ed25519_public(args.log_pub)
            sth = client.sth()
        except Exception as e:
            print("verify-ima: --anchor: %s" % e, file=sys.stderr)
            return 2
        if not merkle.verify_sth(pub, sth):
            print("verify-ima: --anchor: the tree head is not validly signed "
                  "by %s" % args.log_pub, file=sys.stderr)
            return 2

        tree_size = sth["tree_size"]
        root_bytes = bytes.fromhex(sth["root_hash"])
        wanted = {}
        for pkg in doc["packages"]:
            data = canonical.log_leaf_data(doc["image_line"], pkg["name"],
                                           pkg["version"], pkg["arch"],
                                           pkg["leaf_hash"])
            wanted[merkle.leaf_hash(data).hex()] = pkg["name"]

        missing = []
        hashes = sorted(wanted)
        for i in range(0, len(hashes), 200):   # server caps a batch at 256
            chunk = hashes[i:i + 200]
            try:
                proofs = client.proofs_batch(chunk, tree_size)["proofs"]
            except Exception as e:
                print("verify-ima: --anchor: %s" % e, file=sys.stderr)
                return 2
            for lh in chunk:
                pr = proofs.get(lh)
                ok = bool(pr) and merkle.verify_inclusion(
                    bytes.fromhex(lh), pr["index"], tree_size,
                    [bytes.fromhex(x) for x in pr["path"]], root_bytes)
                if not ok:
                    missing.append(wanted[lh])
        anchor = {"tree_size": tree_size, "root": sth["root_hash"],
                  "packages": len(wanted), "missing": sorted(missing)}


    if args.json:
        print(json.dumps({
            "measurements": args.measurements,
            "ima_log": args.ima_log,
            "events": len(events),
            "counts": {k: v for k, v, _ in imalog.summarise(result)},
            "modified": [{"path": e["path"], "package": e["package"],
                          "expected": e["expected"], "loaded": e["digest"]}
                         for e in result["modified"]],
            "unmeasured": [e["path"] for e in result["unmeasured"]],
            "anchor": anchor,
            "ok": not bad and not (anchor and anchor["missing"]),
        }, indent=1))
        return 0 if not bad and not (anchor and anchor["missing"]) else 1

    print("IMA log: %d events, against %d measured files in %d packages"
          % (len(events), len(index), len(doc["packages"])))
    if anchor is None:
        print("  reference values: UNANCHORED - taken from %s on trust."
              % os.path.basename(args.measurements))
        print("                    re-run with --anchor to prove they are in "
              "the log.")
    elif anchor["missing"]:
        print("  reference values: %d of %d package leaves are NOT in the log "
              "at size %d" % (len(anchor["missing"]), anchor["packages"],
                              anchor["tree_size"]))
        for name in anchor["missing"][:10]:
            print("      unanchored: %s" % name)
        if len(anchor["missing"]) > 10:
            print("      ... and %d more" % (len(anchor["missing"]) - 10))
    else:
        print("  reference values: all %d package leaves proved present in "
              "the log" % anchor["packages"])
        print("                    at size %d, root %s"
              % (anchor["tree_size"],
                 anchor["root"] if args.full else abbrev(anchor["root"])))
    for name, count, note in imalog.summarise(result):
        if count or name in ("matched", "modified", "unmeasured"):
            print("  %-14s %6d   %s" % (name, count, note))

    if result["modified"]:
        print()
        print("MODIFIED — the build put different bytes at these paths:")
        for e in result["modified"]:
            print("  %s" % e["path"])
            print("      build  %s  (%s)" % (abbrev(e["expected"]),
                                              e["package"]))
            print("      loaded %s  <- what the kernel actually saw"
                  % abbrev(e["digest"]))

    if result["unmeasured"]:
        print()
        print("UNMEASURED — these ran, and no package installed them:")
        for e in result["unmeasured"][:20]:
            print("  %s" % e["path"])
        if len(result["unmeasured"]) > 20:
            print("  ... and %d more" % (len(result["unmeasured"]) - 20))

    print()
    unanchored = len(anchor["missing"]) if anchor else 0
    if bad or unanchored:
        if unanchored:
            print("FAIL: %d package %s the log has never seen -- the "
                  "reference values"
                  % (unanchored, "leaf" if unanchored == 1 else "leaves"))
            print("      themselves are unproven, so no verdict below is "
                  "worth much.")
        if bad:
            print("FAIL: %d event(s) the build does not account for"
                  % len(bad))
    else:
        print("OK: every event is accounted for by a measured package.")
        print("    This is load-time evidence. Code that never touches the "
              "filesystem, or")
        print("    that is gone before the next measurement, leaves nothing "
              "here either.")
    return 0 if not bad and not unanchored else 1


# ------------------------------------------------------------------------ main
def main(argv=None):
    argv = list(sys.argv[1:]) if argv is None else list(argv)

    # 'attest' owns a large argparse of its own — dispatch before parsing.
    if argv and argv[0] == "attest":
        from .attest import main as attest_main
        return attest_main(argv[1:])

    ap = argparse.ArgumentParser(
        prog="pkgattest", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True, metavar="COMMAND")

    def add_log_opts(p):
        p.add_argument("--log",
                       default=os.environ.get("PKGI_LOG",
                                              "http://127.0.0.1:8799"),
                       help="transparency log URL (env PKGI_LOG)")
        p.add_argument("--log-pub",
                       default=os.path.join(BASE, "keys", "log_ed25519.pub"),
                       help="log Ed25519 public key (PEM)")

    def add_common(p):
        p.add_argument("--json", action="store_true")
        p.add_argument("--full", action="store_true",
                       help="full hashes instead of abbreviated")

    p = sub.add_parser("verify-image",
                       help="verify signed phosphor update payloads")
    p.add_argument("images", nargs="+",
                   help="label=path pairs (e.g. image_A=/path/a.mmc.tar) "
                        "or bare paths")
    p.add_argument("--pubkey",
                   default=os.path.join(BASE, "keys",
                                        "build-rsa4096.pub.pem"),
                   help="pinned build signing public key (PEM)")
    add_common(p)
    p.set_defaults(func=cmd_verify_image)

    p = sub.add_parser("verify-sth",
                       help="verify the log's signed tree head")
    add_log_opts(p)
    p.add_argument("--sth-file", default=None,
                   help="verify a saved STH JSON instead of fetching")
    p.add_argument("--print-payload", action="store_true",
                   help="print the exact signed payload line")
    add_common(p)
    p.set_defaults(func=cmd_verify_sth)

    p = sub.add_parser("verify-package",
                       help="per-package inclusion proof against the "
                            "signed tree head")
    p.add_argument("names", nargs="+", metavar="package")
    p.add_argument("--image-line",
                   default=os.environ.get("PKGI_IMAGE_LINE", "rpi3-openbmc"))
    p.add_argument("--version", default=None,
                   help="only check records matching this version "
                        "(with or without -rN)")
    add_log_opts(p)
    add_common(p)
    p.set_defaults(func=cmd_verify_package)

    p = sub.add_parser("verify-ima",
                       help="cross-reference a Linux IMA measurement log "
                            "against package measurements")
    p.add_argument("ima_log", metavar="IMA_LOG",
                   help="ascii_runtime_measurements, or a copy of it")
    p.add_argument("--measurements", required=True,
                   metavar="pkg-measurements.json")
    p.add_argument("--anchor", action="store_true",
                   help="prove every package leaf in the document is in the "
                        "transparency log (needs --log)")
    add_log_opts(p)
    add_common(p)
    p.set_defaults(func=cmd_verify_ima)

    p = sub.add_parser("verify-measurements",
                       help="recompute leaves + root of build measurement "
                            "documents")
    p.add_argument("docs", nargs="+", metavar="pkg-measurements.json")
    add_common(p)
    p.set_defaults(func=cmd_verify_measurements)

    sub.add_parser("attest",
                   help="full device attestation chain "
                        "(run 'pkgattest attest --help')")

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
