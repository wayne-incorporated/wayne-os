# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE.makefile file.

# @ECLASS: cros-ish.eclass
# @MAINTAINER:
# Chromium OS Firmware Team
# @BUGREPORTS:
# Please report bugs via http://crbug.com/new (with label Build)
# @VCSURL: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/eclass/@ECLASS@
# @BLURB: helper eclass for building ISH firmware based on Chromium OS EC
# @DESCRIPTION:
# Builds the ISH firmware and installs into /lib/firmware/intel/<board>.bin
#
# NOTE: When making changes to this class, make sure to modify all the -9999
# ebuilds that inherit it (e.g., chromeos-ish) to work around
# https://issuetracker.google.com/201299127.

# @ECLASS-VARIABLE: ISH_TARGETS
# @DESCRIPTION:
# An array of platform/ec boards that should be built based on build
# configuration (e.g. model.yaml or config.star)

# Check for EAPI 7+.
case "${EAPI:-0}" in
0|1|2|3|4|5|6) die "Unsupported EAPI=${EAPI:-0} (too old) for ${ECLASS}" ;;
*) ;;
esac

inherit toolchain-funcs cros-unibuild coreboot-sdk

IUSE="coreboot-sdk quiet test unibuild verbose"
REQUIRED_USE="unibuild"

# EC build requires libftdi, but not used for runtime (b:129129436).
DEPEND="
	dev-embedded/libftdi:1=
	chromeos-base/chromeos-config
	test? (
		dev-libs/libprotobuf-mutator:=
		dev-libs/openssl:=
		dev-libs/protobuf:=
	)
"

# @FUNCTION: cros-ish_src_unpack
# @DESCRIPTION:
# Get source files.
cros-ish_src_unpack() {
	cros-workon_src_unpack
	S+="/platform/ec"
}

# @FUNCTION: cros-ish_src_prepare
# @DESCRIPTION: Set compilation to EC source directory.
cros-ish_src_prepare() {
	default

	cros_use_gcc
}

# @FUNCTION: cros-ish_set_build_env
# @DESCRIPTION:
# Set toolchain and build options.
cros-ish_set_build_env() {
	# always use coreboot-sdk to build ISH
	export CROSS_COMPILE_i386=${COREBOOT_SDK_PREFIX_x86_32}
	export CROSS_COMPILE_coreboot_sdk_i386=${COREBOOT_SDK_PREFIX_x86_32}

	tc-export CC BUILD_CC
	export BUILDCC="${BUILD_CC}"

	# b/247791129: EC expects HOST_PKG_CONFIG to be the pkg-config targeting the
	# platform that the EC is running on top of (e.g., the Chromebook's AP).
	# That platform corresponds to the ChromeOS "$BOARD" and the pkg-config for
	# the "$BOARD" being built is specified by tc-getPKG_CONFIG.
	export HOST_PKG_CONFIG
	HOST_PKG_CONFIG=$(tc-getPKG_CONFIG)

	# EC expects BUILD_PKG_CONFIG to be the pkg-config targeting the build
	# machine (the machine doing the compilation).
	export BUILD_PKG_CONFIG
	BUILD_PKG_CONFIG=$(tc-getBUILD_PKG_CONFIG)

	ISH_TARGETS=($(cros_config_host get-firmware-build-targets ish))

	EC_OPTS=()
	use quiet && EC_OPTS+=( -s V=0 )
	use verbose && EC_OPTS+=( V=1 )

	# Disable the kconfig checker, as the platform/ec commit queue
	# does not use this code path.
	EC_OPTS+=( "ALLOW_CONFIG=1" )
}

# @FUNCTION: cros-ish_src_compile
# @DESCRIPTION:
# Compile all boards specified in ISH_TARGETS array variable.
cros-ish_src_compile() {
	cros-ish_set_build_env

	local target
	einfo "Building targets:" "${ISH_TARGETS[@]}"
	for target in "${ISH_TARGETS[@]}"; do
		BOARD="${target}" emake "${EC_OPTS[@]}" clean
		BOARD="${target}" emake "${EC_OPTS[@]}" all
	done
}

# @FUNCTION: cros-ish_src_test
# @DESCRIPTION:
# Runs host tests for all boards in platform/ec (even if not ISH target)
cros-ish_src_test() {
	cros-ish_set_build_env

	emake "${EC_OPTS[@]}" runhosttests
}

# @FUNCTION: cros-ec_src_install
# @DESCRIPTION:
# Install all ISH firmware targets into /lib/firmware/intel/<board>.bin
cros-ish_src_install() {
	cros-ish_set_build_env

	local target
	insinto "/lib/firmware/intel/"

	einfo "Installing targets:" "${ISH_TARGETS[@]}"
	for target in "${ISH_TARGETS[@]}"; do
		newins "build/${target}/ec.bin" "${target}.bin"
	done
}

EXPORT_FUNCTIONS src_unpack src_prepare src_compile src_test src_install
