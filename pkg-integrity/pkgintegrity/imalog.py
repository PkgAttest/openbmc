"""Cross-reference a Linux IMA measurement log against package measurements.

Why the two belong together
---------------------------
IMA and this project solve opposite halves of the same problem, and neither
is much use alone.

IMA produces **evidence**: an event per file the kernel measured as it was
opened or executed. What it has never had is a trustworthy source of
**reference values** to judge those events against. Keylime, the main
consumer of IMA in the field, builds its runtime policy by recording the IMA
log of a machine you already believe is clean — which allowlists whatever you
happened to observe — and its own documentation calls the helper scripts
"reference points and not complete solutions".

This project produces exactly the missing input: a per-package,
per-file measurement set, derived from the build rather than from a running
machine, published to an append-only log and checkable against it. In RATS
terms (RFC 9334) IMA is the Attester's Evidence and the log is a Reference
Value Provider; a Verifier is supposed to compare them.

What the comparison catches that neither half catches alone
-----------------------------------------------------------
Every IMA event falls into one of these:

    matched       the path and the content digest are both in a measured
                  package -- this file is what the build put there
    modified      the path is measured but the content differs -- the file
                  on disk is not the file that was built
    unmeasured    the path is in no package at all -- something executed
                  that no package installed

The last two are runtime findings. Measuring at rest cannot produce them, and
IMA on its own cannot either, because on its own it has nothing to compare
against.

What it still does not do: this is load-time evidence. Malware that never
touches the filesystem, or that is gone before the next attestation, leaves
nothing here either. The TOCTOU problem is not solved by putting these two
together -- it is only narrowed.
"""

import re

# ascii_runtime_measurements, ima-ng template:
#   <pcr> <template-hash> <template> <algo>:<filedata-hash> <pathname>
# The pathname is last and may contain spaces, so the split is bounded.
_LINE = re.compile(r"^(\d+)\s+([0-9a-fA-F]+)\s+(\S+)\s+(\S+?):([0-9a-fA-F]+)\s+(.*)$")

BOOT_AGGREGATE = "boot_aggregate"


class ImaParseError(ValueError):
    pass


def parse_log(text):
    """Parse an IMA ASCII measurement log into event dicts."""
    events = []
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.rstrip("\n")
        if not line.strip():
            continue
        # A measurement line always begins with a PCR number, so a '#' line
        # can never be one. Allowing comments lets an archived or synthetic
        # log carry its own provenance; anything else unparseable is still a
        # hard error, because silently skipping lines in a verifier is how
        # you miss the event that mattered.
        if line.lstrip().startswith("#"):
            continue
        m = _LINE.match(line)
        if not m:
            raise ImaParseError("line %d is not an ima-ng measurement: %r"
                                % (lineno, line[:80]))
        events.append({
            "pcr": int(m.group(1)),
            "template_hash": m.group(2).lower(),
            "template": m.group(3),
            "algo": m.group(4).lower(),
            "digest": m.group(5).lower(),
            "path": m.group(6),
        })
    return events


def file_index(doc):
    """path -> (sha256, package name) from a pkg-measurements document.

    Paths are globally unique across packages in this image line, which is
    what makes a plain dict the right shape here.
    """
    index = {}
    for pkg in doc["packages"]:
        for f in pkg["files"]:
            index[f["path"]] = (f["sha256"], pkg["name"])
    return index


def cross_reference(events, index):
    """Sort IMA events against the measured file set."""
    out = {"matched": [], "modified": [], "unmeasured": [],
           "boot_aggregate": [], "incomparable": []}

    for e in events:
        if e["path"] == BOOT_AGGREGATE:
            out["boot_aggregate"].append(e)
            continue
        # The log records whatever digest the kernel was configured to use.
        # A sha1 log cannot be compared with sha256 measurements, and saying
        # "unmeasured" would be a false accusation rather than an answer.
        if e["algo"] != "sha256":
            out["incomparable"].append(e)
            continue

        known = index.get(e["path"])
        if known is None:
            out["unmeasured"].append(e)
        elif known[0] == e["digest"]:
            out["matched"].append(dict(e, package=known[1]))
        else:
            out["modified"].append(dict(e, package=known[1],
                                        expected=known[0]))
    return out


def summarise(result):
    """One line per category, in a fixed order, for a report."""
    return [
        ("matched", len(result["matched"]),
         "path and content are in a measured package"),
        ("modified", len(result["modified"]),
         "measured path, different content"),
        ("unmeasured", len(result["unmeasured"]),
         "executed, but installed by no package"),
        ("incomparable", len(result["incomparable"]),
         "logged with a digest algorithm the measurements do not use"),
        ("boot_aggregate", len(result["boot_aggregate"]),
         "the PCR0-7 aggregate, not a file"),
    ]


def findings(result):
    """Everything that is not simply accounted for."""
    return result["modified"] + result["unmeasured"]
