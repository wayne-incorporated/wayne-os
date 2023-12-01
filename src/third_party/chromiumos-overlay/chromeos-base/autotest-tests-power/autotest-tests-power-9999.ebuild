# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

PYTHON_COMPAT=( python3_{6..9} )

CROS_WORKON_PROJECT="chromiumos/third_party/autotest"
CROS_WORKON_LOCALNAME="third_party/autotest/files"

inherit cros-workon autotest python-any-r1

DESCRIPTION="power autotests"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/third_party/autotest/"
SRC_URI=""

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="~*"
# Enable autotest by default.
IUSE="+autotest +shill"

RDEPEND="
	shill? ( chromeos-base/shill-test-scripts )
	!<chromeos-base/autotest-tests-0.0.3
"
DEPEND="${RDEPEND}"

# cros/power_suspend depends on shill-test-scripts.
IUSE_TESTS="
	+tests_power_ARMSettings
	+tests_power_Backlight
	+tests_power_BacklightSuspend
	+tests_power_BatteryCharge
	+tests_power_CheckAC
	+tests_power_CheckAfterSuspend
	+tests_power_CPUFreq
	+tests_power_CPUIdle
	+tests_power_Draw
	+tests_power_Dummy
	+tests_power_HotCPUSuspend
	+tests_power_KernelSuspend
	+tests_power_KeyboardBacklight
	+tests_power_ProbeDriver
	shill? ( +tests_power_Resume )
	+tests_power_Standby
	+tests_power_StatsCPUFreq
	+tests_power_StatsCPUIdle
	+tests_power_Status
	shill? (
		+tests_power_SuspendStress
		+tests_power_SuspendToIdle
	)
	+tests_power_WaitForCoolDown
"

IUSE="${IUSE} ${IUSE_TESTS}"

AUTOTEST_FILE_MASK="*.a *.tar.bz2 *.tbz2 *.tgz *.tar.gz"
