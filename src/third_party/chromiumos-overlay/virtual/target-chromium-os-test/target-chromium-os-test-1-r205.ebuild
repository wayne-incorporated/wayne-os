# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

# This ebuild only cares about its own FILESDIR and ebuild file, so it tracks
# the canonical empty project.
CROS_WORKON_COMMIT="d2d95e8af89939f893b1443135497c1f5572aebc"
CROS_WORKON_TREE="776139a53bc86333de8672a51ed7879e75909ac9"
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="../platform/empty-project"

inherit cros-workon

DESCRIPTION="List of packages that are needed inside the Chromium OS test image;
Note: test images are a superset of dev images."
HOMEPAGE="https://dev.chromium.org/"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"
# Note: Do not utilize USE=internal here.  Update virtual/target-chrome-os-test.
IUSE="
	arc-camera3
	biod
	camera_feature_auto_framing
	camera_feature_frame_annotator
	camera_feature_hdrnet
	-chromeless_tests
	cheets
	chromeless_tty
	clvk
	cr50_onboard
	+cras
	cros_embedded
	dlc
	hammerd
	iioservice
	ml_service
	hps
	nnapi
	no_factory_flow
	ondevice_document_scanner
	opengl
	opengles
	p2p
	+perfetto
	pvs
	python_targets_python3_6 python_targets_python3_8
	racc
	scanner
	+shill
	ti50_onboard
	+tpm
	tpm2
	unibuild
	vaapi
	vulkan
	wifi_hostap_test
	wifi_testbed_ap
"

# Packages required to support autotest images.  Dependencies here
# are for packages that must be present on a local device and that
# are not downloaded by the autotest server.  This includes both
# packages relied on by the server, as well as packages relied on by
# specific tests.
#
# This package is not meant to capture tools useful for test debug;
# use the chromeos-dev package for that purpose.
#
# Note that some packages used by autotest are actually built by the
# autotest package and downloaded by the server, regardless of
# whether the package is present on the target device; those
# packages aren't listed here.
#
# Developers should be aware that packages installed by this ebuild
# are rooted in /usr/local.  This means that libraries are installed
# in /usr/local/lib, executables in /usr/local/bin, etc.
#
# TODO(jrbarnette):  It's not known definitively that the list
# below contains no unneeded dependencies.  More work is needed to
# determine for sure that every package listed is actually used.


################################################################################
#
# CROS_COMMON_* : Dependencies common to all CrOS flavors (embedded, regular)
#
################################################################################

CROS_COMMON_RDEPEND="
	tpm? (
		app-crypt/tpm-tools
		chromeos-base/hwsec-test-utils
		chromeos-base/tpm_softclear_utils
	)
	tpm2? (
		chromeos-base/hwsec-test-utils
		chromeos-base/tpm_softclear_utils
	)
	chromeos-base/chromeos-test-root
	chromeos-base/ec-utils
	chromeos-base/ec-utils-test
	!no_factory_flow? ( chromeos-base/factory-deps )
	biod? (
		virtual/chromeos-fpmcu-test
		chromeos-base/chromeos-fpmcu-unittests
	)
	chromeos-base/mock-biod-test-deps
	hammerd? ( chromeos-base/hammerd-test-utils )
	iioservice? ( chromeos-base/iioservice_simpleclient )
	scanner? (
		chromeos-base/lorgnette_cli
		chromeos-base/lorgnette-wwcb-tests
		chromeos-base/sane-backends-test
	)
	ml_service? ( chromeos-base/ml-cmdline )
	hps? ( chromeos-base/hps-tool )
	nnapi? (
		chromeos-base/aosp-frameworks-ml-nn-vts
		chromeos-base/ml-test-assets
	)
	ondevice_document_scanner? (
		media-libs/cros-camera-document-scanning-test
	)
	camera_feature_auto_framing? (
		media-libs/cros-camera-auto-framing-tests
	)
	camera_feature_frame_annotator? (
		media-libs/cros-camera-frame-annotator
	)
	camera_feature_hdrnet? (
		media-libs/cros-camera-hdrnet-tests
	)
	racc? (
		chromeos-base/factory_runtime_probe
	)
	chromeos-base/recover-duts
	chromeos-base/libsegmentation-test
	chromeos-base/tast-local-test-runner
	chromeos-base/tast-local-tests
	chromeos-base/tast-use-flags
	chromeos-base/vboot_reference-tests
	chromeos-base/verity
	chromeos-base/vpd
	chromeos-base/ec-devutils
	!chromeless_tty? (
		!chromeless_tests? (
			>=dev-cpp/gflags-2.0
		)
	)
	wifi_testbed_ap? (
		dev-python/btsocket
	)
	x86?   ( dev-go/delve )
	amd64? ( dev-go/delve )
	arm64? ( dev-go/delve )
	python_targets_python3_6? ( dev-lang/python:3.6 )
	python_targets_python3_8? ( dev-lang/python:3.8 )
	dev-libs/opensc
	p2p? ( dev-python/dpkt )
	perfetto? (
		chromeos-base/perfetto
		chromeos-base/perfetto_simple_producer
	)
	pvs? ( dev-util/pvs-host )
	cr50_onboard? ( dev-util/u2f-ref-code )
	net-misc/rsync
	sys-apps/memtester
	ti50_onboard? ( dev-util/u2f-ref-code )
	virtual/autotest-capability
	virtual/chromeos-bsp-test
"

# Packages needed by FAFT.
CROS_COMMON_RDEPEND+="
	sys-apps/hdparm
	sys-apps/mmc-utils
"

################################################################################
#
# CROS_* : Dependencies for "regular" CrOS devices (coreutils, etc.)
#
################################################################################
CROS_X86_RDEPEND="
	app-benchmarks/sysbench
	sys-apps/pciutils
	sys-power/iasl
	vaapi? ( media-gfx/vadumpcaps media-video/libva-utils )
	x11-misc/read-edid
"

CROS_RDEPEND="
	x86? ( ${CROS_X86_RDEPEND} )
	amd64? ( ${CROS_X86_RDEPEND} )
"

CROS_RDEPEND="${CROS_RDEPEND}
	app-admin/sudo
	app-arch/gzip
	app-arch/tar
	app-benchmarks/blktests
	app-benchmarks/blogbench
	app-benchmarks/lmbench
	app-benchmarks/microbenchmarks
	app-benchmarks/pjdfstest
	app-benchmarks/xfstests
	app-metrics/node_exporter
	opengles? ( app-misc/eglinfo )
	app-misc/tmux
	app-misc/utouch-evemu
	app-mobilephone/dfu-util
	chromeos-base/autotest-client
	cras? (
		chromeos-base/audiotest
		dev-util/rt-tests
		media-sound/audio_streams_conformance_test
	)
	chromeos-base/avtest_label_detect
	chromeos-base/chrome-binary-tests
	chromeos-base/cros-camera-tool
	!chromeless_tty? ( !chromeless_tests? ( chromeos-base/drm-tests ) )
	!no_factory_flow? ( chromeos-base/factory-mini )
	chromeos-base/glbench
	chromeos-base/graphics-expectations
	chromeos-base/graphics-utils-python
	chromeos-base/libvda-gpu-tests
	chromeos-base/modem-diagnostics
	!chromeless_tty? ( !chromeless_tests? (
		chromeos-base/mojo_service_manager-test
	) )
	chromeos-base/policy_utils
	chromeos-base/protofiles
	chromeos-base/pywalt
	!chromeless_tty? ( chromeos-base/screen-capture-utils www-apps/novnc )
	chromeos-base/secure-wipe
	shill? (
		chromeos-base/shill-test-scripts
		net-wireless/hostapd
	)
	!chromeless_tests? ( chromeos-base/telemetry )
	chromeos-base/toolchain-tests
	vulkan? (
		chromeos-base/vkbench
		!clvk? ( media-libs/clvk )
		media-libs/clvk-test
		media-libs/opencl-cts
	)
	dev-embedded/dfu-programmer
	dev-go/syzkaller
	dev-libs/re2
	dev-python/protobuf-python
	dev-python/btsocket
	dev-python/contextlib2
	dev-python/dbus-python
	dev-python/dpkt
	dev-python/grpcio
	dev-python/httplib2
	dev-python/jsonrpclib
	dev-python/mkvparse
	dev-python/netifaces
	dev-python/pydbus
	dev-python/pygobject
	dev-python/pyserial
	dev-python/pytest
	dev-python/python-evdev
	dev-python/python-uinput
	dev-python/pyudev
	dev-python/pyxattr
	dev-python/pyyaml
	dev-python/requests
	dev-python/selenium
	dev-python/setproctitle
	dev-python/setuptools
	dev-python/ws4py
	!chromeless_tty? ( !chromeless_tests? ( dev-util/apitrace ) )
	dev-util/stressapptest
	dev-util/trace-cmd
	dlc? ( sys-fs/squashfs-tools )
	games-util/joystick
	media-gfx/imagemagick[jpeg,png,svg,tiff]
	media-gfx/perceptualdiff
	media-gfx/zbar
	arc-camera3? ( media-libs/cros-camera-libcamera_connector_test )
	arc-camera3? ( media-libs/cros-camera-libjea_test )
	arc-camera3? ( media-libs/cros-camera-test )
	media-libs/cros-camera-app
	media-libs/cros-camera-sw-privacy-switch-test
	media-libs/cros-camera-usb-tests
	media-libs/libaom
	media-libs/libexif
	media-libs/libvmaf
	media-libs/libvpx
	media-libs/opencv
	media-libs/openh264
	!chromeless_tty? ( !chromeless_tests? (
		media-gfx/deqp
		media-gfx/deqp-runner
	) )
	media-libs/tiff
	opengles? ( media-libs/waffle )
	opengl? ( media-libs/waffle )
	media-sound/sox
	net-analyzer/netperf
	net-analyzer/netdata
	net-dialup/minicom
	net-dns/dnsmasq
	net-misc/dhcp
	net-misc/iperf:2
	net-misc/iputils
	net-misc/openssh
	net-misc/radvd
	net-proxy/tinyproxy
	wifi_hostap_test? ( net-wireless/hostap-test )
	sys-apps/ap_wpsr
	sys-apps/coreutils
	sys-apps/dtc
	sys-apps/ethtool
	sys-apps/file
	sys-apps/findutils
	sys-apps/mosys
	sys-apps/shadow
	sys-devel/binutils
	sys-process/iotop
	sys-process/procps
	sys-process/psmisc
	sys-process/time
	x11-libs/libdrm
	"

################################################################################
# Assemble the final RDEPEND and DEPEND variables for portage
################################################################################
RDEPEND="${CROS_COMMON_RDEPEND}
	!cros_embedded? ( ${CROS_RDEPEND} )
"
