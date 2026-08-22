SUMMARY = "Suggested IMA measurement policy for a package-measured image"
DESCRIPTION = "A measurement-only IMA policy scoped so that every event it \
produces can be adjudicated against the build's pkg-measurements document \
by `pkgattest verify-ima`: code is measured, data is not, and \
pseudo-filesystems are excluded. Appraisal is deliberately absent -- it \
answers a different question and needs signing keys this demo does not \
have. The policy file carries the argument for each rule."
LICENSE = "Apache-2.0"
LIC_FILES_CHKSUM = "file://${COREBASE}/meta/files/common-licenses/Apache-2.0;md5=89aea4e17d99a7cacdbeed46a0096b10"

SRC_URI = " \
    file://pkg-integrity.policy \
    file://ima-policy-load.sh \
    file://ima-policy.service \
    "

S = "${UNPACKDIR}"

inherit systemd

SYSTEMD_SERVICE:${PN} = "ima-policy.service"

do_install() {
    install -d ${D}${sysconfdir}/ima
    install -m 0644 ${S}/pkg-integrity.policy ${D}${sysconfdir}/ima/

    install -d ${D}${libexecdir}/pkg-integrity
    install -m 0755 ${S}/ima-policy-load.sh ${D}${libexecdir}/pkg-integrity/

    install -d ${D}${systemd_system_unitdir}
    install -m 0644 ${S}/ima-policy.service ${D}${systemd_system_unitdir}/
}
