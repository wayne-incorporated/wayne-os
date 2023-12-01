# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# @ECLASS: cros-common.mk.eclass
# @MAINTAINER:
# Chromium OS Build Team
# @BUGREPORTS:
# Please report bugs via https://crbug.com/new (with label Build)
# @VCSURL: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/eclass/@ECLASS@
# @BLURB: helper eclass for building packages that use common.mk
# @DESCRIPTION:
# Some Chromium OS packages still build using common.mk rather than the newer
# platform.eclass.  If you're using that build framework, you want to inherit
# this eclass.

if [[ -z ${_ECLASS_CROS_COMMONMK} ]]; then
_ECLASS_CROS_COMMONMK="1"

# Check for EAPI 5+.
case "${EAPI:-0}" in
[01234]) die "unsupported EAPI (${EAPI}) in eclass (${ECLASS})" ;;
esac

# @ECLASS-VARIABLE: CROS_COMMON_MK_NATIVE_TEST
# @DESCRIPTION:
# If set to yes, run the test only for amd64 and x86.
: ${CROS_COMMON_MK_NATIVE_TEST:="yes"}

inherit toolchain-funcs

cros-common.mk_src_prepare() {
	# Run any portage-supplied defaults (e.g. eapply).
	default

	# Get the OUT dir from cros-workon if available.  We have some external
	# partners who are using this build system now.
	if [[ $(type -t cros-workon_get_build_dir) == "function" ]]; then
		export OUT="$(cros-workon_get_build_dir)"

		# Make sure the dir always exists.
		mkdir -p "${OUT}"
	fi
}

cros-common.mk_src_configure() {
	if [[ $(type -t cros-debug-add-NDEBUG) == "function" ]] ; then
		# Only run this if we've inherited cros-debug.eclass.
		cros-debug-add-NDEBUG
	fi

	# We somewhat overshoot here, but it isn't harmful,
	# and catches all the packages we care about.
	tc-export CC CXX AR RANLIB LD NM PKG_CONFIG

	# Portage takes care of this for us.
	export SPLITDEBUG=0

	export MODE=opt
}

cros-common.mk_src_compile() {
	emake ${CROS_WORKON_MAKE_COMPILE_ARGS} "$@"
}

cros-common.mk_src_test() {
	if [[ "${CROS_COMMON_MK_NATIVE_TEST}" == "yes" ]] && ! use amd64 && ! use x86; then
		ewarn "Skipping unittests for non-x86: ${PN}"
		return 0
	fi

	emake tests
}

EXPORT_FUNCTIONS src_prepare src_configure src_compile src_test

fi
