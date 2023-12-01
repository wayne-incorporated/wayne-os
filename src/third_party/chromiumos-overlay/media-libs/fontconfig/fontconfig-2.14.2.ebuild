# Copyright 1999-2023 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

PYTHON_COMPAT=( python3_{6..11} )
inherit multilib meson-multilib python-any-r1 readme.gentoo-r1

DESCRIPTION="A library for configuring and customizing font access"
HOMEPAGE="https://fontconfig.org/"
SRC_URI="https://fontconfig.org/release/${P}.tar.xz"

LICENSE="MIT"
SLOT="1.0"
KEYWORDS="*"

IUSE="cros_host doc nls +subpixel_rendering touchview test"
RESTRICT="!test? ( test )"

# - Check minimum freetype & other deps on bumps. See
#   https://gitlab.freedesktop.org/fontconfig/fontconfig/-/blob/main/configure.ac#L314.
#   Note that FT versioning is confusing, need to map it using
#   https://git.savannah.gnu.org/cgit/freetype/freetype2.git/tree/docs/VERSIONS.TXT
#   But sometimes it's actually greater than that, e.g. see Fedora's spec file
#   https://src.fedoraproject.org/rpms/fontconfig/blob/rawhide/f/fontconfig.spec#_1
#
# - Purposefully dropped the xml USE flag and libxml2 support. Expat is the
#   default and used by every distro. See bug #283191.
#
# - There's a test-only dep on json-c.
#   It might become an optional(?) runtime dep in future though. Who knows.
#   Keep an eye on it.
#
RDEPEND="
	>=dev-libs/expat-2.1.0-r3[${MULTILIB_USEDEP}]
	>=media-libs/freetype-2.9.1[${MULTILIB_USEDEP}]
	virtual/libintl[${MULTILIB_USEDEP}]
	!elibc_Darwin? ( !elibc_SunOS? ( sys-apps/util-linux[${MULTILIB_USEDEP}] ) )
	elibc_Darwin? ( sys-libs/native-uuid )
	elibc_SunOS? ( sys-libs/libuuid )
"
DEPEND="
	${RDEPEND}
	test? ( dev-libs/json-c )
"
BDEPEND="
	${PYTHON_DEPS}
	virtual/pkgconfig
	doc? (
		=app-text/docbook-sgml-dtd-3.1*
		app-text/docbook-sgml-utils[jadetex]
	)
	nls? ( >=sys-devel/gettext-0.19.8 )
"
PDEPEND="virtual/ttf-fonts"

PATCHES=(
	"${FILESDIR}"/${P}-fonts-config.patch
	"${FILESDIR}"/${P}-mtime.patch

	# Avoid test failure (bubblewrap doesn't work within sandbox)
	"${FILESDIR}"/${PN}-2.14.0-skip-bubblewrap-tests.patch

	# Patches from upstream (can usually be removed with next version bump)
	"${FILESDIR}"/${P}-sysroot.patch
)

# Checks that a passed-in fontconfig default symlink (e.g. "10-autohint.conf")
# is present and dies if it isn't.
check_fontconfig_default() {
	local path="${D}"/etc/fonts/conf.d/"$1"
	if [[ ! -L ${path} ]]; then
		die "Didn't find $1 among default fontconfig settings (at ${path})."
	fi
}

MULTILIB_CHOST_TOOLS=("/usr/bin/fc-cache$(get_exeext)")

DOC_CONTENTS="Please make fontconfig configuration changes using
\`eselect fontconfig\`. Any changes made to /etc/fonts/fonts.conf will be
overwritten. If you need to reset your configuration to upstream defaults,
delete the directory ${EROOT%/}/etc/fonts/conf.d/ and re-emerge fontconfig."

src_prepare() {
	default

	# Test needs network access
	# https://gitlab.freedesktop.org/fontconfig/fontconfig/-/issues/319
	# On bumps, please check to see if this has been fixed
	# to allow local access!
	sed -i -e '/test-crbug1004254/d' test/meson.build || die
}

multilib_src_configure() {
	cros_optimize_package_for_speed

	local addfonts=(
		"${EPREFIX}"/usr/local/share/fonts
	)

	# Harvest some font locations, such that users can benefit from the
	# host OS's installed fonts
	case ${CHOST} in
		*-darwin*)
			addfonts+=(
				/Library/Fonts
				/System/Library/Fonts
			)
		;;

		*-solaris*)
			[[ -d /usr/X/lib/X11/fonts/TrueType ]] && \
				addfonts+=( /usr/X/lib/X11/fonts/TrueType )
			[[ -d /usr/X/lib/X11/fonts/Type1 ]] &&
				addfonts+=( /usr/X/lib/X11/fonts/Type1 )
		;;

		*-linux-gnu)
			use prefix && [[ -d /usr/share/fonts ]] && \
				addfonts+=( /usr/share/fonts )
		;;
	esac

	local emesonargs=(
		# USE=doc only controls the additional bits like html/pdf
		# and regeneration of man pages from source. We always install
		# the prebuilt man pages.
		"$(meson_native_use_feature doc)"
		"$(meson_native_use_feature doc doc-txt)"
		"$(meson_native_use_feature doc doc-html)"
		"$(meson_native_use_feature doc doc-man)"
		"$(meson_native_use_feature doc doc-pdf)"

		"$(meson_native_use_feature nls)"
		"$(meson_feature test tests)"

		-Dcache-build=disabled
		-Dbaseconfig-dir="${EPREFIX}"/etc/fonts
		# Font cache should be in /usr/share/cache instead of /var/cache
		# because the latter is not in the read-only partition.
		-Dcache-dir="${EPREFIX}"/usr/share/cache/fontconfig
		-Ddefault-fonts-dirs="${EPREFIX}"/usr/share/fonts
		-Dadditional-fonts-dirs="${EPREFIX}/usr/local/share/fonts${addfonts[@]}"
		-Dconfig-dir="${EPREFIX}"/etc/fonts/conf.d
		-Dtemplate-dir="${EPREFIX}"/etc/fonts/conf.avail
	)

	meson_src_configure
}

multilib_src_install() {
	MULTILIB_CHOST_TOOLS=( "/usr/bin/fc-cache$(get_exeext)" )

	meson_src_install

	# Avoid calling this multiple times, bug #459210
	if multilib_is_native_abi; then
		insinto /etc/fonts
		doins fonts.conf
	fi
}

multilib_src_install_all() {
	einstalldocs
	find "${ED}" -name "*.la" -delete || die

	insinto /etc/fonts
	doins "${FILESDIR}"/local.conf
	# Enable autohint by default
	# match what we want to use.
	dosym ../conf.avail/10-autohint.conf /etc/fonts/conf.d/10-autohint.conf
	check_fontconfig_default 10-autohint.conf

	# Make sure that hinting-slight is on.
	check_fontconfig_default 10-hinting-slight.conf

	# Set sub-pixel mode to RGB
	dosym ../conf.avail/10-sub-pixel-rgb.conf \
		/etc/fonts/conf.d/10-sub-pixel-rgb.conf
	check_fontconfig_default 10-sub-pixel-rgb.conf

	# Use the default LCD filter
	dosym ../conf.avail/11-lcdfilter-default.conf \
		/etc/fonts/conf.d/11-lcdfilter-default.conf
	check_fontconfig_default 11-lcdfilter-default.conf

	# CrOS: Delete unnecessary configurtaion files
	local confs_to_delete=(
		"20-unhint-small-vera"
		"40-nonlatin"
		"45-latin"
		"50-user"
		"60-latin"
		"65-fonts-persian"
		"65-nonlatin"
		"69-unifont"
		"80-delicious"
	)

	local conf
	for conf in "${confs_to_delete[@]}"; do
		rm -f "${D}"/etc/fonts/conf.d/"${conf}".conf
	done

	# There's a lot of variability across different displays with subpixel
	# rendering. Until we have a better solution, turn it off and use grayscale
	# instead on boards that don't have internal displays.
	#
	# Additionally, disable it for convertible devices with rotatable displays
	# (http://crbug.com/222208) and when installing to the host sysroot so the
	# images in the initramfs package won't use subpixel rendering
	# (http://crosbug.com/27872).
	if ! use subpixel_rendering || use touchview || use cros_host; then
		rm "${D}"/etc/fonts/conf.d/10-sub-pixel-rgb.conf
		rm "${D}"/etc/fonts/conf.d/11-lcdfilter-default.conf
		dosym ../conf.avail/10-no-sub-pixel.conf \
			/etc/fonts/conf.d/10-no-sub-pixel.conf
		check_fontconfig_default 10-no-sub-pixel.conf
	fi

	if ! use doc ; then
		find "${S}" -name "*.[[:digit:]]" -type f -exec doman '{}' + || die
	fi

	if [[ -e ${ED}/usr/share/doc/fontconfig/ ]] ;  then
		mv "${ED}"/usr/share/doc/fontconfig/* "${ED}"/usr/share/doc/${PF} || die
		rm -rf "${ED}"/usr/share/doc/fontconfig || die
	fi

	# Changes should be made to /etc/fonts/local.conf, and as we had
	# too much problems with broken fonts.conf we force update it ...
	echo 'CONFIG_PROTECT_MASK="/etc/fonts/fonts.conf"' > "${T}"/37fontconfig || die
	doenvd "${T}"/37fontconfig

	# As of fontconfig 2.7, everything sticks their noses in here.
	dodir /etc/sandbox.d
	echo 'SANDBOX_PREDICT="/usr/share/cache/fontconfig"' > "${ED}"/etc/sandbox.d/37fontconfig || die

	readme.gentoo_create_doc
}

pkg_postinst() {
	einfo "Cleaning broken symlinks in ${EROOT}/etc/fonts/conf.d/"
	find -L "${EROOT}"/etc/fonts/conf.d/ -type l -delete

	readme.gentoo_print_elog

	if [[ -z ${ROOT} ]] ; then
		multilib_pkg_postinst() {
			ebegin "Creating global font cache for ${ABI}"
			"${EPREFIX}"/usr/bin/"${CHOST}"-fc-cache -srf
			eend $?
		}

		multilib_parallel_foreach_abi multilib_pkg_postinst
	fi
}
