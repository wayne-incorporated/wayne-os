# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

# This ebuild only cares about its own FILESDIR and ebuild file, so it tracks
# the canonical empty project.
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="../platform/empty-project"

inherit cros-workon

DESCRIPTION="List of packages that are needed inside the Chromium OS dev image"
HOMEPAGE="https://dev.chromium.org/"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="~*"
# Note: Do not utilize USE=internal here.  Update virtual/target-chrome-os-dev.
IUSE="
	asan
	cellular
	chromeless_tty
	cras
	diag
	hps
	lldbserver
	nvme
	opengl
	pam
	+power_management
	+profile
	python_targets_python3_6 python_targets_python3_8
	+shill
	tpm
	tpm2
	ubsan
	ufs
	usb
	vaapi
	video_cards_amdgpu
	video_cards_intel
	video_cards_mediatek
	video_cards_msm
	vulkan
"

# The dependencies here are meant to capture "all the packages
# developers want to use for development, test, or debug".  This
# category is meant to include all developer use cases, including
# software test and debug, performance tuning, hardware validation,
# and debugging failures running autotest.
#
# To protect developer images from changes in other ebuilds you
# should include any package with a user constituency, regardless of
# whether that package is included in the base Chromium OS image or
# any other ebuild.
#
# Don't include packages that are indirect dependencies: only
# include a package if a file *in that package* is expected to be
# useful.

################################################################################
#
# CROS_* : Dependencies for CrOS devices (coreutils, etc.)
#
################################################################################
CROS_X86_RDEPEND="
	app-benchmarks/i7z
	power_management? ( dev-util/turbostat )
	sys-apps/dmidecode
	sys-apps/pciutils
	sys-boot/syslinux
	vaapi? ( media-gfx/vadumpcaps media-video/libva-utils )
"

RDEPEND="
	x86? ( ${CROS_X86_RDEPEND} )
	amd64? ( ${CROS_X86_RDEPEND} )
"

RDEPEND="${RDEPEND}
	pam? ( app-admin/sudo )
	app-admin/sysstat
	app-arch/bzip2
	app-arch/gzip
	app-arch/tar
	app-arch/unzip
	app-arch/xz-utils
	app-arch/zip
	profile? (
		chromeos-base/quipper
		app-benchmarks/libc-bench
		net-analyzer/netperf
		dev-util/perf
	)
	app-benchmarks/stress-ng
	app-crypt/nss
	tpm? ( app-crypt/tpm-tools )
	app-editors/nano
	app-editors/qemacs
	app-editors/vim
	app-misc/edid-decode
	app-misc/evtest
	app-misc/pax-utils
	app-misc/screen
	app-portage/portage-utils
	app-shells/bash
	app-text/tree
	cras? (
		chromeos-base/audiotest
		media-sound/sox
	)
	chromeos-base/avtest_label_detect
	chromeos-base/chromeos-dev-root
	chromeos-base/cryptohome-dev-utils
	tpm2? ( chromeos-base/g2f_tools )
	!chromeless_tty? ( chromeos-base/graphics-utils-go )
	hps? (
		!asan? (
			!ubsan? (
				chromeos-base/hps-firmware-tools
			)
		)
		chromeos-base/hps-tool
	)
	chromeos-base/policy_utils
	chromeos-base/protofiles
	!chromeless_tty? ( chromeos-base/screen-capture-utils www-apps/novnc )
	shill? ( chromeos-base/shill-test-scripts )
	chromeos-base/touch_firmware_test
	chromeos-base/usi-test
	dev-vcs/git
	net-analyzer/tcpdump
	net-analyzer/speedtest-cli
	net-analyzer/traceroute
	net-dialup/minicom
	net-dns/bind-tools
	net-misc/dhcp
	diag? ( net-misc/diag )
	net-misc/iperf:2
	net-misc/iputils
	cellular? ( net-misc/modem-logger-fibocom )
	net-misc/openssh
	net-misc/rsync
	net-wireless/iw
	net-wireless/wireless-tools
	python_targets_python3_6? ( dev-lang/python:3.6 )
	python_targets_python3_8? ( dev-lang/python:3.8 )
	dev-libs/libgpiod
	dev-python/protobuf-python
	dev-python/cherrypy
	dev-python/dbus-python
	dev-python/pydbus
	dev-python/hid-tools
	dev-util/hdctools
	lldbserver? ( dev-util/lldb-server )
	dev-util/mem
	dev-util/strace
	media-libs/libyuv-test
	media-libs/openh264
	vulkan? (
		dev-util/vulkan-tools
		media-libs/vulkan-layers
	)
	media-tv/v4l-utils
	media-video/yavta
	net-dialup/lrzsz
	net-fs/sshfs
	net-misc/curl
	net-misc/wget
	sys-apps/coreboot-utils
	sys-apps/coreutils
	sys-apps/diffutils
	sys-apps/file
	sys-apps/findutils
	sys-apps/flashrom-tester
	sys-apps/gawk
	sys-apps/i2c-tools
	sys-apps/iotools
	sys-apps/kexec-lite
	sys-apps/less
	sys-apps/mmc-utils
	nvme? ( sys-apps/nvme-cli )
	sys-apps/portage
	sys-apps/smartmontools
	ufs? (
		sys-apps/sg3_utils
		sys-apps/ufs-utils
	)
	usb? ( sys-apps/usbutils )
	sys-apps/which
	sys-block/fio
	sys-devel/gdb
	sys-fs/cryptsetup
	sys-fs/fuse
	sys-fs/lvm2
	sys-fs/mtd-utils
	power_management? ( sys-power/powertop )
	sys-process/procps
	sys-process/psmisc
	sys-process/time
	virtual/autotest-capability
	virtual/chromeos-bsp-dev
	video_cards_amdgpu? ( x11-apps/igt-gpu-tools )
	video_cards_intel? ( x11-apps/igt-gpu-tools )
	video_cards_mediatek? ( x11-apps/igt-gpu-tools )
	video_cards_msm? ( x11-apps/igt-gpu-tools )
"
