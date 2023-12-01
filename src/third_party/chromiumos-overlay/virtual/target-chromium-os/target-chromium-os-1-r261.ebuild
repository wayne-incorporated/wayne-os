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

DESCRIPTION="List of packages that are needed inside the Chromium OS base (release)"
HOMEPAGE="https://dev.chromium.org/"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"
# Note: Do not utilize USE=internal here.  Update virtual/target-chrome-os instead.
# Note: You almost never want to use + here to enable settings by default.
# Please see https://crrev.com/c/2776455 as an example instead.
IUSE="
	asan
	arc-camera3
	biod
	bluetooth
	bootchart
	cecservice
	cellular
	chargesplash
	chrome_internal
	clvk
	compupdates
	containers
	cr50_onboard
	+cras
	+crash_reporting
	+cros_disks
	cros_embedded
	cups
	+debugd
	diagnostics
	diagnostics-minidiag
	dlc
	dlc_test
	dlp
	dns-proxy
	dptf
	eclog
	factory_branch
	featured
	floss
	+fonts
	fpstudy
	fusebox
	fuzzer
	fwupd
	gl3590
	hammerd
	iioservice
	ime
	input_devices_evdev
	intel_lpe
	iwlwifi_rescan
	kerberos_daemon
	kvm_host
	lacros_rootfs
	lvm_stateful_partition
	manatee
	media_perception
	memd
	missive
	mist
	minios
	mmc
	secanomalyd
	modemfwd
	ml_service
	hps
	mtd
	+network_time
	ondevice_handwriting
	os_install_service
	pam
	pciguard
	perfetto
	postscript
	+power_management
	+profile
	private_computing
	racc
	+readahead
	resourced
	rgbkbd
	rmad
	scanner
	secagent
	selinux
	+shill
	sirenia
	smbprovider
	spaced
	swap_management
	+syslog
	+system_locales
	system_proxy
	system_wide_scudo
	systemd
	ti50_onboard
	+tpm
	-tpm2
	+trim_supported
	typecd
	ubsan
	ufs
	usb_bouncer
	usbguard
	+vpn
	watchdog
"

REQUIRED_USE="
	cellular? ( shill )
	modemfwd? ( cellular )
"

################################################################################
#
# READ THIS BEFORE ADDING PACKAGES TO THIS EBUILD!
#
################################################################################
#
# Every chromeos dependency (along with its dependencies) is included in the
# release image -- more packages contribute to longer build times, a larger
# image, slower and bigger auto-updates, increased security risks, etc. Consider
# the following before adding a new package:
#
# 1. Does the package really need to be part of the release image?
#
# Some packages can be included only in the developer or test images, i.e., the
# target-os-dev or chromeos-test ebuilds. If the package will eventually be used
# in the release but it's still under development, consider adding it to
# target-os-dev initially until it's ready for production.
#
# 2. Why is the package a direct dependency of the chromeos ebuild?
#
# It makes sense for some packages to be included as a direct dependency of the
# chromeos ebuild but for most it doesn't. The package should be added as a
# direct dependency of the ebuilds for all packages that actually use it -- in
# time, this ensures correct builds and allows easier cleanup of obsolete
# packages. For example, if a utility will be invoked by the session manager,
# its package should be added as a dependency in the chromeos-login ebuild. If
# the package really needs to be a direct dependency of the chromeos ebuild,
# consider adding a comment why the package is needed and how it's used.
#
# 3. Are all default package features and dependent packages needed?
#
# The release image should include only packages and features that are needed in
# the production system. Often packages pull in features and additional packages
# that are never used. Review these and consider pruning them (e.g., through USE
# flags).
#
# 4. What is the impact on the image size?
#
# Before adding a package, evaluate the impact on the image size. If the package
# and its dependencies increase the image size significantly, consider
# alternative packages or approaches.
#
# 5. Is the package needed on all targets?
#
# If the package is needed only on some target boards, consider making it
# conditional through USE flags in the board overlays.
#
# Variable Naming Convention:
# ---------------------------
# CROS_COMMON_* : Dependencies common to all CrOS flavors
# CROS_* : Dependencies for "regular" CrOS devices (coreutils, etc.)
################################################################################

################################################################################
#
# Per Package Comments:
# --------------------
# Please add any comments specific to why certain packages are
# pulled into the dependency here. This is optional and required only when
# the dependency isn't obvious.
#
################################################################################

################################################################################
#
# Dependencies common to all CrOS flavors (embedded, regular).
# Everything in here should be behind a USE flag.
#
################################################################################
RDEPEND="
	input_devices_evdev? ( app-misc/evtest )
	syslog? (
		app-admin/rsyslog
		chromeos-base/croslog
		chromeos-base/bootid-logger
	)
	biod? ( chromeos-base/biod )
	chargesplash? ( chromeos-base/chargesplash )
	fpstudy? ( chromeos-base/fingerprint_study )
	compupdates? ( chromeos-base/imageloader )
	dlc? (
		app-accessibility/pumpkin
		app-accessibility/screen-ai
		chromeos-base/dlcservice
		chromeos-base/sample-dlc
		chromeos-base/scaled-dlc
		chromeos-languagepacks/tts-bn-bd
		chromeos-languagepacks/tts-cs-cz
		chromeos-languagepacks/tts-da-dk
		chromeos-languagepacks/tts-de-de
		chromeos-languagepacks/tts-el-gr
		chromeos-languagepacks/tts-en-au
		chromeos-languagepacks/tts-en-gb
		chromeos-languagepacks/tts-en-us
		chromeos-languagepacks/tts-es-es
		chromeos-languagepacks/tts-es-us
		chromeos-languagepacks/tts-fi-fi
		chromeos-languagepacks/tts-fil-ph
		chromeos-languagepacks/tts-fr-fr
		chromeos-languagepacks/tts-hi-in
		chromeos-languagepacks/tts-hu-hu
		chromeos-languagepacks/tts-id-id
		chromeos-languagepacks/tts-it-it
		chromeos-languagepacks/tts-ja-jp
		chromeos-languagepacks/tts-km-kh
		chromeos-languagepacks/tts-ko-kr
		chromeos-languagepacks/tts-nb-no
		chromeos-languagepacks/tts-ne-np
		chromeos-languagepacks/tts-nl-nl
		chromeos-languagepacks/tts-pl-pl
		chromeos-languagepacks/tts-pt-br
		chromeos-languagepacks/tts-si-lk
		chromeos-languagepacks/tts-sk-sk
		chromeos-languagepacks/tts-sv-se
		chromeos-languagepacks/tts-th-th
		chromeos-languagepacks/tts-tr-tr
		chromeos-languagepacks/tts-uk-ua
		chromeos-languagepacks/tts-vi-vn
		chromeos-languagepacks/tts-yue-hk
		chrome_internal? (
			chromeos-base/assistant-dlc
		)
	)
	bluetooth? ( net-wireless/bluez )
	floss? (
		!asan? (
			!ubsan? ( net-wireless/floss )
		)
	)
	bootchart? ( app-benchmarks/bootchart )
	tpm? (
		app-crypt/trousers
		chromeos-base/chaps
	)
	tpm2? (
		chromeos-base/trunks
		chromeos-base/vtpm
	)
	pam? ( virtual/chromeos-auth-config )
	fonts? ( chromeos-base/chromeos-fonts )
	chromeos-base/chromeos-installer
	chromeos-base/dev-install
	os_install_service? ( chromeos-base/os_install_service )
	perfetto? ( chromeos-base/perfetto )
	crash_reporting? ( chromeos-base/crash-reporter )
	missive? ( chromeos-base/missive )
	mist? ( chromeos-base/mist )
	modemfwd? ( chromeos-base/modemfwd )
	containers? ( chromeos-base/run_oci )
	cros_disks? ( chromeos-base/cros-disks )
	debugd? ( chromeos-base/debugd )
	diagnostics? ( chromeos-base/diagnostics )
	diagnostics-minidiag? ( chromeos-base/diagnostics-minidiag )
	dlp? ( chromeos-base/dlp )
	kerberos_daemon? ( chromeos-base/kerberos )
	scanner? ( chromeos-base/lorgnette )
	ml_service? ( chromeos-base/ml )
	ondevice_handwriting? (
		chromeos-languagepacks/handwriting-base
		chromeos-languagepacks/handwriting-am
		chromeos-languagepacks/handwriting-ar
		chromeos-languagepacks/handwriting-be
		chromeos-languagepacks/handwriting-bg
		chromeos-languagepacks/handwriting-bn
		chromeos-languagepacks/handwriting-ca
		chromeos-languagepacks/handwriting-cs
		chromeos-languagepacks/handwriting-da
		chromeos-languagepacks/handwriting-de
		chromeos-languagepacks/handwriting-el
		chromeos-languagepacks/handwriting-es
		chromeos-languagepacks/handwriting-et
		chromeos-languagepacks/handwriting-fa
		chromeos-languagepacks/handwriting-fi
		chromeos-languagepacks/handwriting-fil
		chromeos-languagepacks/handwriting-fr
		chromeos-languagepacks/handwriting-ga
		chromeos-languagepacks/handwriting-gu
		chromeos-languagepacks/handwriting-hi
		chromeos-languagepacks/handwriting-hr
		chromeos-languagepacks/handwriting-hu
		chromeos-languagepacks/handwriting-hy
		chromeos-languagepacks/handwriting-id
		chromeos-languagepacks/handwriting-is
		chromeos-languagepacks/handwriting-it
		chromeos-languagepacks/handwriting-iw
		chromeos-languagepacks/handwriting-ja
		chromeos-languagepacks/handwriting-ka
		chromeos-languagepacks/handwriting-kk
		chromeos-languagepacks/handwriting-km
		chromeos-languagepacks/handwriting-kn
		chromeos-languagepacks/handwriting-ko
		chromeos-languagepacks/handwriting-lo
		chromeos-languagepacks/handwriting-lt
		chromeos-languagepacks/handwriting-lv
		chromeos-languagepacks/handwriting-ml
		chromeos-languagepacks/handwriting-mn
		chromeos-languagepacks/handwriting-mr
		chromeos-languagepacks/handwriting-ms
		chromeos-languagepacks/handwriting-mt
		chromeos-languagepacks/handwriting-my
		chromeos-languagepacks/handwriting-ne
		chromeos-languagepacks/handwriting-nl
		chromeos-languagepacks/handwriting-no
		chromeos-languagepacks/handwriting-or
		chromeos-languagepacks/handwriting-pa
		chromeos-languagepacks/handwriting-pl
		chromeos-languagepacks/handwriting-pt
		chromeos-languagepacks/handwriting-ro
		chromeos-languagepacks/handwriting-ru
		chromeos-languagepacks/handwriting-si
		chromeos-languagepacks/handwriting-sk
		chromeos-languagepacks/handwriting-sl
		chromeos-languagepacks/handwriting-sr
		chromeos-languagepacks/handwriting-sv
		chromeos-languagepacks/handwriting-ta
		chromeos-languagepacks/handwriting-te
		chromeos-languagepacks/handwriting-th
		chromeos-languagepacks/handwriting-ti
		chromeos-languagepacks/handwriting-tr
		chromeos-languagepacks/handwriting-uk
		chromeos-languagepacks/handwriting-ur
		chromeos-languagepacks/handwriting-vi
		chromeos-languagepacks/handwriting-zh
		chromeos-languagepacks/handwriting-zh-HK
	)
	hps? (
		chromeos-base/hpsd
		chromeos-base/hps-firmware-images
		!asan? (
			!ubsan? ( chromeos-base/hps-firmware )
		)
	)
	hammerd? ( chromeos-base/hammerd )
	racc? (
		chromeos-base/hardware_verifier
		chromeos-base/runtime_probe
	)
	rgbkbd? ( chromeos-base/rgbkbd )
	rmad? ( chromeos-base/rmad )
	iioservice? ( chromeos-base/iioservice )
	memd? ( chromeos-base/memd )
	power_management? ( chromeos-base/power_manager )
	private_computing? ( chromeos-base/private_computing )
	!chromeos-base/platform2
	profile? ( chromeos-base/quipper )
	resourced? ( chromeos-base/resourced )
	secagent? ( virtual/secagentd )
	selinux? ( chromeos-base/selinux-policy )
	shill? ( >=chromeos-base/shill-0.0.1-r2205 )
	manatee? ( chromeos-base/sirenia )
	sirenia? ( chromeos-base/sirenia )
	spaced? ( chromeos-base/spaced )
	usb_bouncer? ( chromeos-base/usb_bouncer )
	chromeos-base/update_engine
	clvk? ( media-libs/clvk )
	cras? (
		media-sound/adhd
		media-sound/cras-client
	)
	trim_supported? ( chromeos-base/chromeos-trim )
	network_time? ( net-misc/tlsdate )
	iwlwifi_rescan? ( net-wireless/iwlwifi_rescan )
	readahead? ( sys-apps/ureadahead )
	pam? ( sys-auth/pam_pwdfile )
	watchdog? ( sys-apps/daisydog )
	mtd? ( sys-fs/mtd-utils )
	cups? ( virtual/chromium-os-printing )
	swap_management? ( chromeos-base/swap_management )
	system_locales? ( chromeos-base/system-locales )
	system_proxy? ( chromeos-base/system-proxy )
	eclog? ( chromeos-base/timberslide )
	chromeos-base/chromeos-machine-id-regen
	systemd? ( sys-apps/systemd )
	!systemd? ( sys-apps/systemd-utils )
	usbguard? ( sys-apps/usbguard )
	kvm_host? (
		chromeos-base/crosdns
		chromeos-base/crostini_client
		chromeos-base/vm_host_tools
		chromeos-base/termina-dlc
		chromeos-base/termina-tools-dlc
		amd64? (
			chromeos-base/edk2-ovmf-dlc
		)
	)
	sys-kernel/linux-firmware
	virtual/chromeos-bsp
	virtual/chromeos-firewall
	!factory_branch? ( virtual/chromeos-firmware )
	virtual/chromeos-interface
	virtual/chromeos-regions
	virtual/implicit-system
	virtual/linux-sources
	sys-apps/kmod[tools]
	virtual/service-manager
	cr50_onboard? ( chromeos-base/chromeos-cr50 )
	ti50_onboard? ( chromeos-base/chromeos-ti50 )
	chromeos-base/u2fd
	chromeos-base/bootlockbox
	ime? (
		app-i18n/chinese-input
		app-i18n/keyboard-input
		app-i18n/japanese-input
		app-i18n/hangul-input
	)
	fuzzer? ( virtual/target-fuzzers )
	!dev-python/socksipy
	arc-camera3? ( chromeos-base/cros-camera )
	fwupd? (
		sys-apps/fwupd
		sys-firmware/fwupd-peripherals
		sys-firmware/fwupd-storage
		mmc? ( sys-firmware/mmc-firmware )
		gl3590? ( sys-firmware/gl3590-firmware )
	)
	smbprovider? (
		chromeos-base/smbfs
		chromeos-base/smbprovider
	)
	typecd? ( chromeos-base/typecd )
	pciguard? ( chromeos-base/pciguard )
	minios? ( chromeos-base/minios )
	secanomalyd? ( chromeos-base/secanomalyd )
	lacros_rootfs? ( chromeos-base/chromeos-lacros )
	dns-proxy? ( chromeos-base/dns-proxy )
	featured? ( chromeos-base/featured )
	fusebox? ( chromeos-base/fusebox )
	lvm_stateful_partition? ( chromeos-base/lvmd )
	ufs? (
		chromeos-base/discod
		chromeos-base/factory_ufs
	)
	system_wide_scudo? ( sys-libs/scudo )
	cecservice? ( sys-apps/cecservice )
"

################################################################################
#
# CROS_* : Dependencies for "regular" CrOS devices (coreutils, X etc)
#
# Comments on individual packages:
# --------------------------------
# app-editors/neatvi:
# Specifically include the editor we want to appear in chromeos images, so that
# it is deterministic which editor is chosen by 'virtual/editor' dependencies
# (such as in the 'sudo' package).  See crosbug.com/5777.
#
# app-shells/bash:
# We depend on dash for the /bin/sh shell for runtime speeds, but we also
# depend on bash to make the dev mode experience better.  We do not enable
# things like line editing in dash, so its interactive mode is very bare.
################################################################################

CROS_X86_RDEPEND="
	dptf? ( virtual/dptf )
	intel_lpe? ( virtual/lpe-support )
"

CROS_RDEPEND="
	x86? ( ${CROS_X86_RDEPEND} )
	amd64? ( ${CROS_X86_RDEPEND} )
"

# Anything behind a USE flag belongs in the main RDEPEND list above.
# New packages usually should be behind a USE flag.
CROS_RDEPEND="${CROS_RDEPEND}
	app-arch/tar
	app-editors/neatvi
	app-shells/bash
	chromeos-base/common-assets
	chromeos-base/chromeos-imageburner
	chromeos-base/crosh
	chromeos-base/crosh-extension
	chromeos-base/inputcontrol
	chromeos-base/mtpd
	chromeos-base/permission_broker
	chromeos-base/userfeedback
	chromeos-base/vboot_reference
	chromeos-base/vpd
	net-wireless/crda
	sys-apps/dbus
	sys-apps/flashrom
	sys-apps/iproute2
	sys-apps/rootdev
	!systemd? ( sys-apps/upstart )
	sys-fs/e2fsprogs
	virtual/assets
	virtual/cheets
	virtual/udev
"

# TODO(toolchain): Remove this libxcrypt dep after all packages directly depend
# on it and it is not installed as a system library anymore
CROS_RDEPEND="${CROS_RDEPEND}
	sys-libs/libxcrypt
"

RDEPEND+="!cros_embedded? ( ${CROS_RDEPEND} )"
