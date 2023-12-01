# Copyright 2013 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_PROJECT="chromiumos/third_party/autotest"

inherit cros-workon autotest

DESCRIPTION="Autotest tests that require chrome_binary_test, or telemetry deps"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/third_party/autotest/"
SRC_URI=""
LICENSE="GPL-2"
SLOT="0"
KEYWORDS="~*"

# Enable autotest by default.
IUSE="
	${IUSE}
	+autotest
	+cellular
	drm_atomic
	+shill
	vaapi
"

RDEPEND="
	!chromeos-base/autotest-telemetry
	!<chromeos-base/autotest-tests-0.0.4
	!<chromeos-base/autotest-tests-cellular-0.0.1-r3203
	chromeos-base/autotest-deps-graphics
	chromeos-base/autotest-deps-policy
	chromeos-base/autotest-deps-webgl-mpd
	chromeos-base/chromeos-chrome
	dev-python/grpcio
	dev-python/mkvparse
	shill? ( chromeos-base/shill-test-scripts )
	chromeos-base/telemetry
	sys-apps/ethtool
	vaapi? ( x11-libs/libva )
	virtual/autotest-private-libs
"

DEPEND="${RDEPEND}"

IUSE_TESTS=(
	# Tests that depend on telemetry.
	+tests_accessibility_Check
	+tests_accessibility_ChromeVoxSound
	+tests_audio_CrasCheck
	+tests_autoupdate_EOL
	+tests_autoupdate_LoginStartUpdateLogout
	+tests_autoupdate_StartOOBEUpdate
	+tests_autoupdate_UpdateFromUI
	+tests_autoupdate_UserData
	+tests_bluetooth_AdapterReboot
	+tests_bluetooth_AdapterHealth
	+tests_bluetooth_IDCheck
	+tests_bluetooth_RegressionClient
	+tests_bluetooth_TurnOnOffUI
	+tests_desktopui_AudioFeedback
	+tests_desktopui_CheckRlzPingSent
	+tests_desktopui_RootfsLacros
	+tests_desktopui_SimpleLogin
	+tests_logging_CrashServices
	+tests_login_CryptohomeIncognito
	+tests_login_LoginPin
	+tests_login_LoginSuccess
	+tests_login_OobeLocalization
	+tests_login_SavePassword
	+tests_network_CastTDLS
	+tests_network_ChromeWifiConfigure
	+tests_platform_InitLoginPerf
	+tests_platform_LogoutPerf
	+tests_policy_WilcoUSBPowershare
	+tests_power_AudioDetector
	+tests_power_BasicBrowsing
	+tests_power_BatteryDrain
	+tests_power_CellularIdle
	+tests_power_Display
	+tests_power_Idle
	+tests_power_IdleSuspend
	+tests_power_LoadTest
	+tests_power_LowMemorySuspend
	+tests_power_Speedometer2
	+tests_power_SuspendType
	+tests_power_ThermalLoad
	+tests_power_UiResume
	+tests_power_VideoCall
	+tests_power_VideoDetector
	+tests_power_VideoEncode
	+tests_power_VideoPlayback
	+tests_power_VideoSuspend
	+tests_power_WebGL
	+tests_power_WifiIdle
	+tests_security_BundledExtensions
	+tests_stub_IdleSuspend
	+tests_telemetry_AFDOGenerateClient
	+tests_touch_GestureNav
	+tests_touch_MouseScroll
	+tests_touch_ScrollDirection
	+tests_touch_TapSettings
	+tests_touch_TabSwitch
	+tests_touch_TouchscreenScroll
	+tests_touch_TouchscreenTaps
	+tests_touch_TouchscreenZoom
	+tests_touch_StylusTaps
	+tests_video_AVAnalysis
)

IUSE_TESTS_CELLULAR="
	cellular? (
		+tests_cellular_ModemControl
		+tests_network_ChromeCellularEndToEnd
		+tests_network_ChromeCellularNetworkPresent
		+tests_network_ChromeCellularNetworkProperties
		+tests_network_ChromeCellularSmokeTest
	)
"

IUSE_TESTS_SHILL="
	shill? (
		+tests_network_ChromeWifiEndToEnd
		+tests_network_RoamSuspendEndToEnd
		+tests_network_RoamWifiEndToEnd
	)
"

IUSE_TESTS_ARC="
"


IUSE_TESTS_CHROMIUM="
	+tests_chromium
	+tests_chromium_Telemetry
	+tests_chromium_Graphics
"

IUSE_TESTS="
	${IUSE_TESTS[*]}
	${IUSE_TESTS_CELLULAR}
	${IUSE_TESTS_SHILL}
	${IUSE_TESTS_ARC}
	${IUSE_TESTS_CHROMIUM}
"

IUSE="
	${IUSE}
	${IUSE_TESTS}
"

CROS_WORKON_LOCALNAME="third_party/autotest/files"

AUTOTEST_DEPS_LIST=""
AUTOTEST_CONFIG_LIST=""
AUTOTEST_PROFILERS_LIST=""

AUTOTEST_FILE_MASK="*.a *.tar.bz2 *.tbz2 *.tgz *.tar.gz"

src_prepare() {
	# Telemetry tests require the path to telemetry source to exist in order to
	# build. Copy the telemetry source to a temporary directory that is writable,
	# so that file removals in Telemetry source can be performed properly.
	export TMP_DIR="$(mktemp -d)"
	rsync -a --exclude=third_party/trace-viewer/test_data/ \
		"${SYSROOT}"/usr/local/telemetry/src/ "${TMP_DIR}"
	export PYTHONPATH="${TMP_DIR}/third_party/catapult/telemetry"
	autotest_src_prepare
}
