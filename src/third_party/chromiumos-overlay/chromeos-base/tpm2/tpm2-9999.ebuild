# Copyright 2015 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_PROJECT="chromiumos/third_party/tpm2"
CROS_WORKON_LOCALNAME="third_party/tpm2"

inherit cros-workon toolchain-funcs

DESCRIPTION="TPM2.0 library"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/third_party/tpm2/"

LICENSE="BSD-Google"
KEYWORDS="~*"
IUSE="generic_tpm2 test tpm2_simulator tpm2_simulator_manufacturer"

DEPEND="dev-libs/openssl:0="

src_compile() {
	if use tpm2_simulator_manufacturer ; then
		export TPM2_SIMULATOR_MANUFACTURER=1
	fi
	if use generic_tpm2 ; then
		export TCG_EK_CERT_INDICES=1
	fi
	tc-export CC AR RANLIB
	emake
}

src_install() {
	dolib.a build/libtpm2.a

	"${S}"/thirdparty_preinstall.sh "${PV}" "$(cros-workon_get_build_dir)"
	insinto "/usr/$(get_libdir)/pkgconfig"
	doins "$(cros-workon_get_build_dir)/libtpm2.pc"

	insinto /usr/include/tpm2
	doins BaseTypes.h
	doins Capabilities.h
	doins ExecCommand_fp.h
	doins GetCommandCodeString_fp.h
	doins Implementation.h
	doins Manufacture_fp.h
	doins Platform.h
	doins TPMB.h
	doins TPM_Types.h
	doins Tpm.h
	doins TpmBuildSwitches.h
	doins TpmError.h
	doins _TPM_Init_fp.h
	doins bool.h
	doins swap.h
	doins tpm_generated.h
	doins tpm_types.h
	if use test || use tpm2_simulator; then
		doins tpm_manufacture.h
		doins tpm_simulator.hpp
	fi
}
