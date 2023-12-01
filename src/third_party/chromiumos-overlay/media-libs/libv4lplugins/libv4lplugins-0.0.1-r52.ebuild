# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="5"

CROS_WORKON_COMMIT="17e182085b6871f8ab84c3e064ce6e37e3dcbfd4"
CROS_WORKON_TREE="785dc2a0149c113045f6b8ecbbb42cccb050ee17"
CROS_WORKON_PROJECT="chromiumos/third_party/libv4lplugins"
inherit autotools cros-workon eutils

MY_P=v4l-utils-1.18.1

DESCRIPTION="Separate plugin library from upstream v4l-utils package"
HOMEPAGE="http://git.linuxtv.org/v4l-utils.git"
SRC_URI="http://linuxtv.org/downloads/v4l-utils/${MY_P}.tar.bz2"

LICENSE="LGPL-2.1"
SLOT="0"
KEYWORDS="*"
PLUGIN_IUSE="rockchip rockchip_v2"
IUSE="${PLUGIN_IUSE}"
REQUIRED_USE="^^ ( ${PLUGIN_IUSE} )"

RDEPEND="media-libs/libv4l"
DEPEND="${RDEPEND}"

S=${WORKDIR}/${MY_P}

src_unpack() {
	cros-workon_src_unpack
	default
}

src_prepare() {
	if use rockchip; then
		PLUGIN_DIR="libv4l-rockchip"
	elif use rockchip_v2; then
		PLUGIN_DIR="libv4l-rockchip_v2"
	fi
	mv ${PLUGIN_DIR} lib || die
	# Append "SUBDIRS += ${PLUGIN_DIR}" at the end of lib/Makefile.am
	sed -i -e "\$aSUBDIRS += ${PLUGIN_DIR}" lib/Makefile.am || die
	# Add "lib/${PLUGIN_DIR}/Makefile" after lib/libv4l2rds/Makefile
	sed -i -e "s:libv4l2rds/Makefile:&\n\tlib/${PLUGIN_DIR}/Makefile:" \
		configure.ac || die
	rm -rf include
	eautoreconf
}

src_configure() {
	econf \
		--disable-static \
		--disable-qv4l2 \
		--disable-v4l-utils \
		--without-jpeg
}

src_compile() {
	emake -C lib/${PLUGIN_DIR}
}

src_install() {
	emake -C lib/${PLUGIN_DIR} DESTDIR="${D}" install
}
