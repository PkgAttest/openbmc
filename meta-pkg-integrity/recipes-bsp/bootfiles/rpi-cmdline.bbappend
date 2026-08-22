# A hook for extra kernel arguments, empty by default. rpi-cmdline collapses
# runs of whitespace in do_compile, so an empty CMDLINE_PKG_INTEGRITY leaves
# cmdline.txt byte-identical to a build without this bbappend.
CMDLINE_PKG_INTEGRITY ?= ""
CMDLINE:append = " ${CMDLINE_PKG_INTEGRITY}"
