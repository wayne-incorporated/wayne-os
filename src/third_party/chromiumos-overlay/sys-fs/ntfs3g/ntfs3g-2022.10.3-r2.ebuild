# Copyright 2006-2022 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit autotools toolchain-funcs

MY_P="ntfs-3g_ntfsprogs-${PV}"

DESCRIPTION="Open source read-write NTFS driver that runs under FUSE"
HOMEPAGE="https://github.com/tuxera/ntfs-3g"
SRC_URI="https://download.tuxera.com/opensource/${MY_P}.tgz"

LICENSE="GPL-2"
# The subslot matches the SONAME major #.
SLOT="0/89"
KEYWORDS="*"
IUSE=""

RDEPEND="
	sys-fs/fuse
"
DEPEND="${RDEPEND}
	sys-apps/attr
"
BDEPEND="
	virtual/pkgconfig
"

S="${WORKDIR}/${MY_P}"

PATCHES=(
	"${FILESDIR}"/${PN}-2022.5.17-configure-bashism.patch
	"${FILESDIR}"/${PN}-2022.10.3-unaligned-types.patch
	"${FILESDIR}"/${PN}-2022.10.3-allow-unpriv-fuseblk.patch
	"${FILESDIR}"/${PN}-2022.10.3-dont-log-volume-label.patch
	"${FILESDIR}"/${PN}-2022.10.3-use-open-fd.patch
)

src_prepare() {
	default

	# Only needed for bashism patch
	eautoreconf
}

src_configure() {
	tc-ld-disable-gold

	local myconf=(
		# passing --exec-prefix is needed as the build system is trying to be clever
		# and install itself into / instead of /usr in order to be compatible with
		# separate-/usr setups (which we don't support without an initrd).
		--exec-prefix="${EPREFIX}"/usr

		--disable-ldconfig
		--enable-extras
		--disable-debug
		--enable-ntfs-3g
		--disable-posix-acls
		--enable-xattr-mappings
		--disable-crypto
		--enable-ntfsprogs
		--disable-static

		--with-uuid

		# disable hd library until we have the right library in the tree and
		# don't links to hwinfo one causing issues like bug #602360
		--without-hd

		# ChromeOS uses the external FUSE library
		--with-fuse=external
	)

	econf "${myconf[@]}"
}

src_install() {
	default
	# Plugins directory
	keepdir "/usr/$(get_libdir)/ntfs-3g"
	find "${ED}" -name '*.la' -type f -delete || die

	# Add the mount.ntfs symlink (http://b/259007877)
	dosym mount.ntfs-3g /sbin/mount.ntfs

	# Remove lowntfs-3g as it's not used on ChromeOS.
	rm -f "${D}/usr/bin/lowntfs-3g" "${D}/usr/sbin/mount.lowntfs-3g" "${D}/sbin/mount.lowntfs-3g"
}
