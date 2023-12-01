# Copyright 1999-2018 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit autotools cros-fuzzer cros-sanitizers flag-o-matic multilib toolchain-funcs

MY_PN=${PN/-gpl}
MY_P="${MY_PN}-${PV/_}"
PVM=$(ver_cut 1-2)
PVM_S=$(ver_rs 1-2 "")

# Use https://gitweb.gentoo.org/proj/codec/ghostscript-gpl-patches.git/ for patches
# See 'index' branch for README
MY_PATCHSET="ghostscript-gpl-10.0-patches.tar.xz"

DESCRIPTION="Interpreter for the PostScript language and PDF"
HOMEPAGE="https://ghostscript.com/"
SRC_URI="https://github.com/ArtifexSoftware/ghostpdl-downloads/releases/download/gs${PVM_S}/${MY_P}.tar.xz"
if [[ -n "${MY_PATCHSET}" ]] ; then
	SRC_URI+=" https://dev.gentoo.org/~sam/distfiles/${CATEGORY}/${PN}/${MY_PATCHSET}"
fi

# Google has a commercial license for ghostscript when distributed with
# Chrome OS (not Chromium OS). So toggle the license to the required
# copyright when building for Chrome OS, and use the open source licensing
# text otherwise.
LICENSE="
	internal? ( LICENSE.artifex_commercial )
	!internal? ( AGPL-3 CPL-1.0 )
"
SLOT="0"
KEYWORDS="*"
IUSE="asan cups dbus fuzzer gtk idn internal l10n_de crosfonts static-libs tiff unicode X msan"

LANGS="ja ko zh-CN zh-TW"
for X in ${LANGS} ; do
	IUSE="${IUSE} l10n_${X}"
done

DEPEND="app-text/libpaper:=
	media-libs/fontconfig
	>=media-libs/freetype-2.4.9:2=
	!!media-libs/jbig2dec
	>=media-libs/lcms-2.6:2
	>=media-libs/libpng-1.6.2:=
	media-libs/libjpeg-turbo:=
	>=media-libs/openjpeg-2.1.0:2=
	tiff? ( >=media-libs/tiff-4.0.1:= )
	>=sys-libs/zlib-1.2.7
	cups? ( >=net-print/cups-1.3.8 )
	dbus? ( sys-apps/dbus )
	gtk? ( x11-libs/gtk+:3 )
	idn? ( net-dns/libidn )
	X? ( x11-libs/libXt x11-libs/libXext )"
BDEPEND="virtual/pkgconfig"
# We need urw-fonts for the 35 base postscript level 2 fonts,
# eg CenturySchL-Roma is not included in the Noto fonts.
RDEPEND="${DEPEND}
	!crosfonts? ( >=media-fonts/urw-fonts-2.4.9 )
	l10n_ja? ( media-fonts/kochi-substitute )
	l10n_ko? ( media-fonts/baekmuk-fonts )
	l10n_zh-CN? ( media-fonts/arphicfonts )
	l10n_zh-TW? ( media-fonts/arphicfonts )"

S="${WORKDIR}/${MY_P}"

PATCHES=(
	"${FILESDIR}/"
)

# Lowers the optimization level if the package is being built
# for fuzzing. Ghostscript appears to default to `-O2`.
cros_gs_set_optimization() {
	use fuzzer || return 0
	replace-flags "-O*" "-Og"
}

src_prepare() {
	if [[ -n ${MY_PATCHSET} ]] ; then
		# apply various patches, many borrowed from Fedora
		# https://src.fedoraproject.org/rpms/ghostscript
		# and Debian
		# https://salsa.debian.org/printing-team/ghostscript/-/tree/debian/latest/debian/patches
		eapply "${WORKDIR}"/${MY_PATCHSET%%.tar*}
	fi

	default

	# Remove internal copies of various libraries
	rm -r cups/libs || die
	rm -r freetype || die
	rm -r lcms2mt || die
	rm -r libpng || die
	rm -r tiff || die
	rm -r zlib || die

	# Enable compilation of select contributed drivers,
	# but prune ones with incompatible or unclear licenses
	# (c.f. commit 0334118d6279640cb860f2f4a9af64b0fd008b49).
	rm -r contrib/epson740/ || die
	rm -r contrib/md2k_md5k/ || die
	rm -r contrib/pscolor || die
	rm -r contrib/uniprint || die
	rm contrib/gdevgdi.c || die
	rm contrib/gdevln03.c || die
	rm contrib/gdevlx7.c || die
	rm contrib/gdevmd2k.c || die
	rm contrib/gdevop4w.c || die
	rm contrib/gdevxes.c || die

	if ! use gtk ; then
		sed -e "s:\$(GSSOX)::" \
			-e "s:.*\$(GSSOX_XENAME)$::" \
			-i base/unix-dll.mak || die "sed failed"
	fi

	if use crosfonts; then
		rm -rf "${S}/Resource/Font" || die
		cat "${FILESDIR}/Fontmap.cros" >> "${S}/Resource/Init/Fontmap.GS" || die
	fi

	# Force the include dirs to a neutral location.
	sed -e "/^ZLIBDIR=/s:=.*:=${T}:" \
		-i configure.ac || die
	# Some files depend on zlib.h directly.  Redirect them. #573248
	# Also make sure to not define OPJ_STATIC to avoid linker errors due to
	# hidden symbols (https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=203327#c1)
	sed -e '/^zlib_h/s:=.*:=:' \
		-e 's|-DOPJ_STATIC ||' \
		-i base/lib.mak || die

	# Search path fix
	# put LDFLAGS after BINDIR, bug #383447
	sed -e "s:\$\(gsdatadir\)/lib:@datarootdir@/ghostscript/${PV}/$(get_libdir):" \
		-e "s:exdir=.*:exdir=@datarootdir@/doc/${PF}/examples:" \
		-e "s:docdir=.*:docdir=@datarootdir@/doc/${PF}/html:" \
		-e "s:GS_DOCDIR=.*:GS_DOCDIR=@datarootdir@/doc/${PF}/html:" \
		-e "s:-L\$(BINDIR):& \$(LDFLAGS):g" \
		-i Makefile.in base/*.mak || die "sed failed"

	# Remove incorrect symlink, bug 590384
	rm ijs/ltmain.sh || die
	eautoreconf

	cd ijs || die
	eautoreconf
}

src_configure() {
	sanitizers-setup-env
	cros_gs_set_optimization
	use msan && append-cppflags "-DPACIFY_VALGRIND"

	# See https://bugs.gentoo.org/899952
	append-lfs-flags

	local FONTPATH
	for path in \
		"${EPREFIX}"/usr/share/fonts/urw-fonts \
		"${EPREFIX}"/usr/share/fonts/Type1 \
		"${EPREFIX}"/usr/share/fonts
	do
		FONTPATH="${FONTPATH}${FONTPATH:+:}${EPREFIX}${path}"
	done

	tc-export_build_env BUILD_CC

	# This list contains all ghostscript devices used by CUPS/PPD files.
	# It was built basing on an output from platform_PrinterPpds autotest.
	# See the readme.txt file in the autotest directory to learn how the list
	# was created.
	local devices=(
		ap3250 bit bj10e bj200 bjc600 bjc800 bjc880j bjccolor cdj500
		cdj550 cdnj500 cljet5c declj250 djet500 dnj650c epl2050 eplcolor
		eps9high eps9mid epson epsonc hl1250 ibmpro imagen jetp3852 laserjet
		lbp8 lips2p lips3 lips4 ljet2p ljet3 ljet4 ljetplus lp1800 lp1900
		lp2200 lp2400 lp2500 lp2563 lp3000c lp7500 lp7700 lp7900 lp8000
		lp8000c lp8100 lp8200c lp8300c lp8300f lp8400f lp8500c lp8600 lp8600f
		lp8700 lp8800c lp8900 lp9000b lp9000c lp9100 lp9200b lp9200c lp9300
		lp9400 lp9500c lp9600 lp9600s lp9800c lps4500 lps6500 lq850 lxm5700m
		m8510 necp6 npdl oce9050 oki182 okiibm pdfwrite pcl3 picty180 pjxl300
		ps2write pxlcolor pxlmono r4081 sj48 stcolor t4693d4 tek4696 uniprint
		# The "cups" driver is added if and only if we are building with CUPS.
		$(usev cups)
	)

	# Do not add --enable-dynamic here, it's not supported fully upstream
	# https://bugs.ghostscript.com/show_bug.cgi?id=705895
	# bug #884707
	PKGCONFIG=$(type -P "$(tc-getPKG_CONFIG)") \
	econf \
		CUPSCONFIG="${EROOT}/usr/bin/${CHOST}-cups-config" \
		CCAUX="${BUILD_CC}" \
		CFLAGSAUX="${BUILD_CFLAGS}" \
		LDFLAGSAUX="${BUILD_LDFLAGS}" \
		--enable-freetype \
		--enable-fontconfig \
		--enable-openjpeg \
		$(use_enable crosfonts compile-inits) \
		--with-drivers="$(printf %s, "${devices[@]}")" \
		--with-fontpath="${FONTPATH}" \
		--with-ijs \
		--with-jbig2dec \
		--with-libpaper \
		--without-luratech \
		--without-tesseract \
		$(use_enable cups) \
		$(use_enable dbus) \
		$(use_enable gtk) \
		$(use_with cups pdftoraster) \
		$(use_with idn libidn) \
		$(use_with tiff libtiff) \
		$(use_with tiff system-libtiff) \
		$(use_with X x)

	cd "${S}/ijs" || die
	econf \
		--enable-shared \
		$(use_enable static-libs static)
}

src_compile() {
	emake -j8 so all

	cd "${S}"/ijs || die
	emake
}

src_install() {
	emake DESTDIR="${D}" install-so install

	# move gsc to gs, bug #343447
	# gsc collides with gambit, bug #253064
	mv -f "${ED}"/usr/bin/{gsc,gs} || die

	cd "${S}/ijs" || die
	emake DESTDIR="${D}" install

	# Sometimes the upstream versioning deviates from the tarball(!)
	# bug #844115#c32
	local my_gs_version=$(find "${ED}"/usr/share/ghostscript/ -maxdepth 1 -mindepth 1 -type d || die)
	my_gs_version=${my_gs_version##*/}

	insinto "/usr/share/ghostscript/${PVM}/Resource/Init"

	if ! use static-libs; then
		find "${ED}" -name '*.la' -delete || die
	fi

	# set environment variables
	doenvd "${FILESDIR}"/02ghostscript
}
