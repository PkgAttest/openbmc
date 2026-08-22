FILESEXTRAPATHS:prepend := "${THISDIR}/files:"

SRC_URI += "file://vtpm-proxy.cfg"

# IMA is opt-in per build (image E sets PKG_INTEGRITY_IMA = "1"). Turning it
# on changes the kernel, so it cannot be unconditional: images A-D must keep
# the measurements they were published with.
#
# Measured, not guessed: E differs from D by 28 changed leaves, 3 removed
# (kernel-module-tpm, -sha1, -libsha1, all promoted built-in by IMA's
# select TCG_TPM) and 1 added (ima-policy). 2,101 leaves are byte-identical
# and dedupe against the log. A kernel config change is a small diff here,
# not a whole-image one.
SRC_URI += "${@bb.utils.contains('PKG_INTEGRITY_IMA', '1', 'file://pkg-integrity-ima.cfg', '', d)}"
