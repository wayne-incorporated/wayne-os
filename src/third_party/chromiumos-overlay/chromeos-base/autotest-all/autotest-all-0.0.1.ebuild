# Copyright 2010 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

PYTHON_COMPAT=( python3_{6..9} )

inherit cros-constants python-any-r1

DESCRIPTION="Meta ebuild for all packages providing tests"
HOMEPAGE="http://www.chromium.org"

LICENSE="GPL-2"
SLOT=0
KEYWORDS="*"
IUSE="cheets -chromeless_tests +bluetooth +cras +debugd -chromeless_tty kvm_host +power_management +shill +tpm tpm2"

RDEPEND="
	chromeos-base/autotest-client
	chromeos-base/autotest-private-all
	chromeos-base/autotest-server-tests
	chromeos-base/autotest-server-tests-tast
	chromeos-base/autotest-tests
	chromeos-base/autotest-tests-security
	chromeos-base/autotest-tests-toolchain
	bluetooth? (
		chromeos-base/autotest-server-tests-bluetooth
		chromeos-base/autotest-tests-bluetooth
	)
	cheets? ( chromeos-base/autotest-tests-arc-public )
	!chromeless_tty? (
		chromeos-base/autotest-tests-cryptohome
		!chromeless_tests? (
			chromeos-base/autotest-chrome
			chromeos-base/autotest-server-tests-telemetry
			chromeos-base/autotest-tests-graphics
			chromeos-base/autotest-tests-ownershipapi
			chromeos-base/autotest-tests-touchpad
		)
	)
	cras? ( chromeos-base/autotest-tests-audio )
	debugd? ( chromeos-base/autotest-tests-debugd )
	kvm_host? ( chromeos-base/autotest-tests-vm-host )
	power_management? ( chromeos-base/autotest-tests-power )
	shill? (
		chromeos-base/autotest-server-tests-shill
		chromeos-base/autotest-tests-shill
	)
	tpm2? ( chromeos-base/autotest-tests-tpm )
	tpm? ( chromeos-base/autotest-tests-tpm )
"

DEPEND="${RDEPEND}"

SUITE_DEPENDENCIES_FILE="dependency_info"
SUITE_TO_CONTROL_MAP="suite_to_control_file_map"

src_unpack() {
	mkdir -p "${S}"
	touch "${S}/${SUITE_DEPENDENCIES_FILE}"
	touch "${S}/${SUITE_TO_CONTROL_MAP}"
}

src_install() {
	# So that this package properly owns the file
	insinto "${AUTOTEST_BASE}"/test_suites
	doins "${SUITE_DEPENDENCIES_FILE}"
	doins "${SUITE_TO_CONTROL_MAP}"
}

# Pre-processes control files and installs DEPENDENCIES info.
pkg_postinst() {
	local root_autotest_dir="${ROOT}${AUTOTEST_BASE}"
	export PYTHONDONTWRITEBYTECODE=1
	"${EPYTHON}" "${root_autotest_dir}/site_utils/suite_preprocessor.py" \
		-a "${root_autotest_dir}" \
		-o "${root_autotest_dir}/test_suites/${SUITE_DEPENDENCIES_FILE}" || die
	"${EPYTHON}" "${root_autotest_dir}/site_utils/control_file_preprocessor.py" \
		-a "${root_autotest_dir}" \
		-o "${root_autotest_dir}/test_suites/${SUITE_TO_CONTROL_MAP}" || die
	"${EPYTHON}" "${root_autotest_dir}/utils/generate_metadata.py" \
		-autotest_path "${root_autotest_dir}" \
		-output_file="${root_autotest_dir}"/autotest_metadata.pb || die
}
