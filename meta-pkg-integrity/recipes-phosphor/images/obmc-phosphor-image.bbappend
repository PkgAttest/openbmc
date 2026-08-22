inherit pkg-measurements

OBMC_IMAGE_EXTRA_INSTALL:append = " pkg-witness"
OBMC_IMAGE_EXTRA_INSTALL:append = "${@bb.utils.contains('PKG_INTEGRITY_IMA', '1', ' ima-policy', '', d)}"
