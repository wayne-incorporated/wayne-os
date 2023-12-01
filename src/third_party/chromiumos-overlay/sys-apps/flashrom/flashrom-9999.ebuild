# Copyright 1999-2011 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: /var/cvsroot/gentoo-x86/sys-apps/flashrom/flashrom-0.9.4.ebuild,v 1.5 2011/09/20 16:03:21 nativemad Exp $

EAPI=7
CROS_WORKON_PROJECT="chromiumos/third_party/flashrom"
CROS_WORKON_EGIT_BRANCH="master"

inherit cros-workon toolchain-funcs meson cros-sanitizers

DESCRIPTION="Utility for reading, writing, erasing and verifying flash ROM chips"
HOMEPAGE="https://flashrom.org/"
#SRC_URI="http://download.flashrom.org/releases/${P}.tar.bz2"
SRC_URI=""

LICENSE="GPL-2"
SLOT="0/0"
KEYWORDS="~*"
IUSE="
	atahpt
	atapromise
	atavia
	buspirate_spi
	ch341a_spi
	+cli
	dediprog
	developerbox_spi
	digilent_spi
	drkaiser
	+dummy
	+ft2232_spi
	gfxnvidia
	ich_descriptors
	+internal
	+it8212
	jlink_spi
	+linux_mtd
	+linux_spi
	+mediatek_i2c_spi
	mstarddc_spi
	nic3com
	nicintel
	nicintel_eeprom
	nicintel_spi
	nicnatsemi
	nicrealtek
	ogp_spi
	+parade_lspcon
	pickit2_spi
	pony_spi
	+raiden_debug_spi
	rayer_spi
	+realtek_mst_i2c_spi
	satasii
	satamv
	+serprog static
	+stlinkv3_spi
	test
	+usbblaster_spi
	wiki
	manpages
	docs
"

LIB_DEPEND="
	atahpt? ( sys-apps/pciutils[static-libs(+)] )
	atapromise? ( sys-apps/pciutils[static-libs(+)] )
	atavia? ( sys-apps/pciutils[static-libs(+)] )
	ch341a_spi? ( virtual/libusb:1[static-libs(+)] )
	dediprog? ( virtual/libusb:1[static-libs(+)] )
	developerbox_spi? ( virtual/libusb:1[static-libs(+)] )
	digilent_spi? ( virtual/libusb:1[static-libs(+)] )
	drkaiser? ( sys-apps/pciutils[static-libs(+)] )
	ft2232_spi? ( dev-embedded/libftdi:=[static-libs(+)] )
	gfxnvidia? ( sys-apps/pciutils[static-libs(+)] )
	internal? ( sys-apps/pciutils[static-libs(+)] )
	it8212? ( sys-apps/pciutils[static-libs(+)] )
	jlink_spi? ( dev-embedded/libjaylink[static-libs(+)] )
	nic3com? ( sys-apps/pciutils[static-libs(+)] )
	nicintel_eeprom? ( sys-apps/pciutils[static-libs(+)] )
	nicintel_spi? ( sys-apps/pciutils[static-libs(+)] )
	nicintel? ( sys-apps/pciutils[static-libs(+)] )
	nicnatsemi? ( sys-apps/pciutils[static-libs(+)] )
	nicrealtek? ( sys-apps/pciutils[static-libs(+)] )
	raiden_debug_spi? ( virtual/libusb:1[static-libs(+)] )
	ogp_spi? ( sys-apps/pciutils[static-libs(+)] )
	pickit2_spi? ( virtual/libusb:0[static-libs(+)] )
	rayer_spi? ( sys-apps/pciutils[static-libs(+)] )
	satamv? ( sys-apps/pciutils[static-libs(+)] )
	satasii? ( sys-apps/pciutils[static-libs(+)] )
	stlinkv3_spi? ( virtual/libusb:1[static-libs(+)] )
	usbblaster_spi? ( dev-embedded/libftdi:1=[static-libs(+)] )
"
RDEPEND="!static? ( ${LIB_DEPEND//\[static-libs(+)]} )"
DEPEND="${RDEPEND}
	static? ( ${LIB_DEPEND} )
	test? ( dev-util/cmocka )"
RDEPEND+=" internal? ( sys-apps/dmidecode )"

BDEPEND="sys-apps/diffutils"

DOCS=( README.chromiumos Documentation/ )

src_configure() {
	# Constructing programmers array from enabled IUSE flags
	local flag programmer_flags=(
		atahpt atapromise atavia buspirate_spi ch341a_spi dediprog developerbox_spi
		digilent_spi drkaiser dummy ft2232_spi gfxnvidia internal it8212 jlink_spi
		linux_mtd linux_spi mediatek_i2c_spi mstarddc_spi nic3com nicintel_eeprom
		nicintel_spi nicintel nicnatsemi nicrealtek ogp_spi parade_lspcon pickit2_spi
		pony_spi raiden_debug_spi rayer_spi realtek_mst_i2c_spi satamv satasii
		serprog stlinkv3_spi usbblaster_spi
	)
	local programmers=$(
		# shellcheck disable=SC2046
		printf '%s,' $(for flag in "${programmer_flags[@]}"; do usev "${flag}"; done)
	)

	# Remove trailing comma.
	programmers=${programmers%,}

	local emesonargs=(
		-Ddefault_programmer_name=internal
		-Dprogrammer="${programmers}"
		$(meson_feature cli classic_cli)
		$(meson_feature ich_descriptors ich_descriptors_tool)
		$(meson_feature wiki classic_cli_print_wiki)
		$(meson_feature manpages man-pages)
		$(meson_feature docs documentation)
	)
	sanitizers-setup-env
	meson_src_configure
}

src_install() {
	meson_src_install
}

src_test() {
	meson_src_test
}
