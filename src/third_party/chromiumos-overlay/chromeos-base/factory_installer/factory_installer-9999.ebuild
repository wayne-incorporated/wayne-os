# Copyright 2010 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7
CROS_WORKON_PROJECT="chromiumos/platform/factory_installer"
CROS_WORKON_LOCALNAME="platform/factory_installer"
CROS_RUST_CRATE_NAME="factory_installer"
CROS_RUST_SUBDIR="rust"
CROS_RUST_TEST_DIRECT_EXEC_ONLY="yes"

inherit cros-workon cros-rust cros-factory

DESCRIPTION="Chrome OS Factory Installer"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/factory_installer/"
SRC_URI=""
LICENSE="BSD-Google"
KEYWORDS="~*"

USE_PREFIX="tty_console_"
ALL_PORTS=(
	ttyAMA{0..5}
	ttyHSL{0..5}
	ttyMSM{0..5}
	ttymxc{0..5}
	ttyO{0..5}
	ttyS{0..5}
	ttySAC{0..5}
	ttyUSB{0..5}
	tty{0..5}
)
IUSE_PORTS="${ALL_PORTS[*]/#/${USE_PREFIX}}"
IUSE="${IUSE_PORTS} -asan test cr50_onboard ti50_onboard tpm"

# Factory install images operate by downloading content from a
# server.  In some cases, the downloaded content contains programs
# to be executed.  The downloaded programs may not be complete;
# they could have dependencies on shared libraries or commands
# that must be present in the factory install image.
#
# PROVIDED_DEPEND captures a minimal set of packages promised to be
# provided for use by any downloaded program.  The list must contain
# any package depended on by any downloaded program.
#
# Currently, the only downloaded program is the firmware installer;
# the dependencies below are gleaned from eclass/cros-firmware.eclass.
# Changes in that eclass must be reflected here.
PROVIDED_DEPEND="
	app-arch/gzip
	app-arch/sharutils
	app-arch/tar
	app-misc/figlet
	chromeos-base/chromeos-config-tools
	chromeos-base/vboot_reference
	sys-apps/mosys
	sys-apps/util-linux"

# Tests are run on the build host and execute the "secure-wipe.sh" from
# the build directory.  Unfortunately that script, in turn, includes
# "/usr/share/misc/chromeos-common.sh" via an absolute path which requires
# the script to be present on the build host itself.  Let's make sure it's
# there.
BDEPEND="
	test? ( chromeos-base/chromeos-common-script )"

# COMMON_DEPEND tracks dependencies common to both DEPEND and
# RDEPEND.
#
# For chromeos-init there's a runtime dependency because the factory
# jobs depend on upstart jobs in that package.  There's a build-time
# dependency because pkg_postinst in this ebuild edits specifc jobs
# in that package.
COMMON_DEPEND="
	chromeos-base/chromeos-init:=
	!chromeos-base/chromeos-factoryinstall
	!chromeos-base/chromeos-factory"

DEPEND="${COMMON_DEPEND}
	chromeos-base/factory:=
	dev-rust/third-party-crates-src:=
	test? ( chromeos-base/secure-wipe:= )
	x86? ( sys-boot/syslinux:= )"

RDEPEND="${COMMON_DEPEND}
	${PROVIDED_DEPEND}
	app-arch/lbzip2
	app-arch/pigz
	app-misc/jq
	chromeos-base/chromeos-installer
	chromeos-base/chromeos-storage-info
	chromeos-base/dlcservice
	chromeos-base/ec-utils
	chromeos-base/secure-wipe
	chromeos-base/vpd
	dev-util/stressapptest
	net-misc/htpdate
	net-wireless/iw
	sys-apps/flashrom
	sys-apps/net-tools
	sys-apps/upstart
	sys-apps/util-linux
	sys-block/parted
	sys-fs/e2fsprogs
	sys-kernel/linux-firmware"


src_unpack() {
	cros-workon_src_unpack
	cros-rust_src_unpack
}

src_configure() {
	sanitizers-setup-env
	cd "${CROS_RUST_SUBDIR}" || die
	cros-rust_src_configure
	cd "${S}" || die
}

src_compile() {
	tc-export AR CC CXX RANLIB
	cd "${CROS_RUST_SUBDIR}" || die
	cros-rust_src_compile --no-default-features --features="factory-fai" \
		--bin="factory_fai"
	cd "${S}" || die
	emake
}

src_test() {
	tests/secure-wipe.sh || die "integration test failed"
	cd "${CROS_RUST_SUBDIR}" || die
	cros-rust_src_test --all-features
	cd "${S}" || die
}

src_install() {
	local service_file="factory_tty.sh"
	local tmp_service_file="${T}/${service_file}"
	local scripts=(*.sh)
	scripts=( "${scripts[@]# ${service_file}}" )

	if [[ -n "${TTY_CONSOLE}" ]]; then
		local item ports=()
		for item in ${IUSE_PORTS}; do
			if use "${item}"; then
				ports+=("${item#${USE_PREFIX}}")
			fi
		done
		sed -e "s/^TTY_CONSOLE=.*$/TTY_CONSOLE=\"${ports[*]}\"/" \
			"${service_file}" >"${tmp_service_file}" || \
			die "Failed to change TTY_CONSOLE"
		service_file="${tmp_service_file}"
		einfo "Changed TTY_CONSOLE to ${ports[*]}."
	fi
	dosbin "${scripts[@]}" "${service_file}"

	# install factory_fai
	cd "${CROS_RUST_SUBDIR}" || die
	cros-rust_publish "${CROS_RUST_CRATE_NAME}" \
		"$(cros-rust_get_crate_version "${S}/${CROS_RUST_SUBDIR}")"
	dosbin "$(cros-rust_get_build_dir)/factory_fai"
	cd "${S}" || die

	local tpm_dir="/usr/share/factory_installer/tpm"
	local tpm_utils="stub.sh"
	insinto "${tpm_dir}"

	if use cr50_onboard || use ti50_onboard; then
		tpm_utils=cros.sh
	elif use tpm; then
		tpm_utils=infineon.sh
	fi

	einfo "Installing ${tpm_dir}/${tpm_utils}"
	newins tpm/"${tpm_utils}" "tpm_utils.sh"

	insinto /usr/share/factory_installer/init
	doins init/*.conf

	insinto /root
	newins "${FILESDIR}/dot.factory_installer" .factory_installer
	# install PMBR code
	case "$(tc-arch)" in
		"x86")
		einfo "using x86 PMBR code from syslinux"
		PMBR_SOURCE="${ROOT}/usr/share/syslinux/gptmbr.bin"
		;;
		*)
		einfo "using default PMBR code"
		PMBR_SOURCE="${FILESDIR}/dot.pmbr_code"
		;;
	esac
	newins "${PMBR_SOURCE}" .pmbr_code

	einfo "Install resources from chromeos-base/factory."
	factory_unpack_resource installer "${ED}/usr"

	if [[ -f "$(factory_get_resource_archive_path installer-board)" ]]; then
		einfo "Install resources from chromeos-base/factory-board."
		factory_unpack_resource installer-board "${ED}"
	fi
}

pkg_postinst() {
	[[ "$(cros_target)" != "target_image" ]] && return 0

	STATEFUL="${ROOT}/usr/local"
	STATEFUL_LSB="${STATEFUL}/etc/lsb-factory"

	: "${FACTORY_SERVER:=$(hostname -f)}"

	mkdir -p "${STATEFUL}/etc"
	sudo dd of="${STATEFUL_LSB}" <<EOF
CHROMEOS_AUSERVER=http://${FACTORY_SERVER}:8080/update
CHROMEOS_DEVSERVER=http://${FACTORY_SERVER}:8080/update
FACTORY_INSTALL=1
HTTP_SERVER_OVERRIDE=true
EOF
}
