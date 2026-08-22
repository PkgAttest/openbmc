#!/usr/bin/env python3
"""Generate a synthetic IMA measurement log for demonstrating verify-ima.

THIS IS NOT A REAL LOG. No device produced it. It is assembled from a build's
own measurement document so that the cross-reference can be shown working
before any hardware exists, and it is deliberately not committed to the
repository — generate it when you want it.

A real log comes from /sys/kernel/security/ima/ascii_runtime_measurements on
a machine booted with IMA enabled, and would need CONFIG_IMA plus an
`ima_policy=` boot argument, neither of which this image has yet.

The anomalies it can inject are the two findings the cross-reference exists
to produce:

  --modify PATH    a measured path whose content no longer matches the build
  --intruder PATH  a path that executed while belonging to no package
"""

import argparse
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pkgintegrity import canonical  # noqa: E402

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Roughly what a kernel actually measures under a default policy: things that
# get executed or mmapped, plus files read by root.
LIKELY = ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/libexec/")
LIKELY_SUFFIX = (".so", ".ko")


def looks_measurable(path):
    return path.startswith(LIKELY) or any(s in path for s in LIKELY_SUFFIX)


def line(pcr, algo, digest, path):
    # The template hash is a digest over the template fields. Nothing here
    # checks it -- replaying the log against PCR 10 needs a quote, which this
    # bundle does not have -- so a deterministic stand-in is honest enough
    # for a demonstration and is marked as such in the header.
    th = hashlib.sha1(("%s:%s %s" % (algo, digest, path)).encode()).hexdigest()
    return "%d %s ima-ng %s:%s %s" % (pcr, th, algo, digest, path)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--measurements", default=os.path.join(
        BASE, "artifacts", "D",
        "obmc-phosphor-image-raspberrypi3-64.pkg-measurements.json"))
    ap.add_argument("--limit", type=int, default=400,
                    help="how many measured files to pretend were used")
    ap.add_argument("--modify", action="append", default=[],
                    metavar="PATH",
                    help="measured path to log with different content")
    ap.add_argument("--intruder", action="append", default=[],
                    metavar="PATH",
                    help="path to log that no package installed")
    ap.add_argument("--out", default="-")
    args = ap.parse_args(argv)

    doc = canonical.load_measurements_json(args.measurements)
    files = [(f["path"], f["sha256"])
             for p in doc["packages"] for f in p["files"]]
    files.sort()

    chosen = [(p, h) for p, h in files if looks_measurable(p)][:args.limit]
    by_path = dict(files)

    out = [
        "# SYNTHETIC IMA measurement log -- no device produced this.",
        "# Assembled from %s" % os.path.basename(args.measurements),
        "# for demonstrating `pkgattest verify-ima`. Template hashes are",
        "# deterministic stand-ins; replaying against PCR 10 needs a quote.",
        line(10, "sha256", "00" * 32, "boot_aggregate"),
    ]
    for p, h in chosen:
        out.append(line(10, "sha256", h, p))

    for p in args.modify:
        if p not in by_path:
            sys.exit("--modify %s: not a measured path" % p)
        tampered = hashlib.sha256(("tampered:" + p).encode()).hexdigest()
        out.append(line(10, "sha256", tampered, p))
    for p in args.intruder:
        digest = hashlib.sha256(("intruder:" + p).encode()).hexdigest()
        out.append(line(10, "sha256", digest, p))

    text = "\n".join(out) + "\n"
    if args.out == "-":
        sys.stdout.write(text)
    else:
        with open(args.out, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        print("wrote %s: %d events (%d measured, %d modified, %d intruder)"
              % (args.out, len(chosen) + 1 + len(args.modify) +
                 len(args.intruder), len(chosen), len(args.modify),
                 len(args.intruder)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
