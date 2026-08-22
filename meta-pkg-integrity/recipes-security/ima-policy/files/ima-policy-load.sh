#!/bin/sh
# Load the package-integrity IMA policy through securityfs.
#
# Ordering caveat, stated because it changes what the log means: anything
# executed before this runs was measured under whatever policy the kernel
# booted with (ima_policy= on the cmdline, or nothing at all). Loading a
# policy here does not retroactively measure early boot. The honest reading
# of a log produced this way is "from this point on".
set -u
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

POLICY=/etc/ima/pkg-integrity.policy
SECFS=/sys/kernel/security
IMA="$SECFS/ima"

[ -r "$POLICY" ] || { echo "ima-policy: $POLICY unreadable" >&2; exit 1; }

if [ ! -d "$IMA" ]; then
    mountpoint -q "$SECFS" 2>/dev/null || mount -t securityfs securityfs "$SECFS" 2>/dev/null
fi
[ -d "$IMA" ] || {
    echo "ima-policy: $IMA absent -- kernel built without CONFIG_IMA" >&2
    exit 1
}
[ -w "$IMA/policy" ] || {
    # Already loaded once and the kernel was built without
    # CONFIG_IMA_WRITE_POLICY, so the rules are sealed for this boot.
    echo "ima-policy: $IMA/policy not writable -- policy already sealed" >&2
    exit 0
}

# One write(2). The kernel parses the whole buffer; feeding it line by line
# is what makes multi-rule policies fail on some releases.
if ! dd if="$POLICY" of="$IMA/policy" bs=64k count=1 2>/dev/null; then
    echo "ima-policy: kernel rejected the policy" >&2
    exit 1
fi

echo "ima-policy: loaded $(grep -c '^[a-z]' "$POLICY") rules from $POLICY"
