# Copyright 2020 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="03cf6f3cead34ccb282536c4d176364f1bcded10"
CROS_WORKON_TREE="a73af9489b36ce504a956f2df3a4c6b73dae128b"
CROS_WORKON_PROJECT="chromiumos/third_party/systemd"
CROS_WORKON_LOCALNAME="../third_party/systemd"

MINKV="3.11"
PYTHON_COMPAT=( python3_{6..9} )
inherit meson python-any-r1 cros-workon

DESCRIPTION="Creates, deletes and cleans up volatile and temporary files and directories"
HOMEPAGE="https://www.freedesktop.org/wiki/Software/systemd"
SRC_URI="elibc_musl? ( https://dev.gentoo.org/~gyakovlev/distfiles/${P}-musl.tar.xz )"

LICENSE="BSD-2 GPL-2 LGPL-2.1 MIT public-domain"
SLOT="0"
KEYWORDS="*"
IUSE="selinux test"
RESTRICT="!test? ( test )"

DEPEND="
	sys-apps/acl:0=
	>=sys-apps/util-linux-2.30:0=
	>=sys-kernel/linux-headers-${MINKV}
	sys-libs/libcap:0=
	selinux? ( sys-libs/libselinux:0= )
"
RDEPEND="${DEPEND}
	!sys-apps/opentmpfiles
	!sys-apps/systemd
"

BDEPEND="
	app-text/docbook-xml-dtd:4.2
	app-text/docbook-xml-dtd:4.5
	app-text/docbook-xsl-stylesheets
	dev-libs/libxslt:0
	dev-util/gperf
	>=dev-util/meson-0.46
	>=dev-util/intltool-0.50
	>=sys-apps/coreutils-8.16
	sys-devel/m4
	virtual/pkgconfig
	test? ( ${PYTHON_DEPS} )
"

pkg_setup() {
	use test && python-any-r1_pkg_setup
}

src_prepare() {
	# musl patchset from:
	# http://cgit.openembedded.org/openembedded-core/tree/meta/recipes-core/systemd/systemd
	use elibc_musl && eapply "${WORKDIR}/${P}-musl"
	default
}

src_configure() {
	# disable everything until configure says "enabled features: ACL, tmpfiles"
	local systemd_disable_options=(
		adm-group
		analyze
		apparmor
		audit
		backlight
		binfmt
		blkid
		bzip2
		coredump
		dbus
		efi
		elfutils
		environment-d
		fdisk
		gcrypt
		glib
		gshadow
		gnutls
		hibernate
		hostnamed
		hwdb
		idn
		ima
		initrd
		firstboot
		kernel-install
		kmod
		ldconfig
		libcryptsetup
		libcurl
		libfido2
		libidn
		libidn2
		libiptc
		link-networkd-shared
		link-systemctl-shared
		link-timesyncd-shared
		link-udev-shared
		localed
		logind
		lz4
		machined
		microhttpd
		networkd
		nss-myhostname
		nss-resolve
		nss-systemd
		openssl
		p11kit
		pam
		pcre2
		polkit
		portabled
		pstore
		pwquality
		randomseed
		resolve
		rfkill
		seccomp
		$(usex selinux '' selinux)
		smack
		sysusers
		timedated
		timesyncd
		tpm
		qrencode
		quotacheck
		userdb
		utmp
		vconsole
		wheel-group
		xdg-autostart
		xkbcommon
		xz
		zlib
		zstd
	)

	# prepend -D and append =false, e.g. zstd becomes -Dzstd=false
	systemd_disable_options=( ${systemd_disable_options[@]/#/-D} )
	systemd_disable_options=( ${systemd_disable_options[@]/%/=false} )

	local emesonargs=(
		-Dacl=true
		-Dtmpfiles=true
		-Dstandalone-binaries=true # this and below option does the magic
		-Dstatic-libsystemd=true
		-Dsysvinit-path=''
		${systemd_disable_options[@]}
	)
	meson_src_configure
}

src_compile() {
	# tmpfiles and sysusers can be built as standalone, link systemd-shared in statically.
	# https://github.com/systemd/systemd/pull/16061 original implementation
	# we just need to pass -Dstandalone-binaries=true and
	# use <name>.standalone target below.
	# check meson.build for if have_standalone_binaries condition per target.
	local mytargets=(
		systemd-tmpfiles.standalone
		man/tmpfiles.d.5
		man/systemd-tmpfiles.8
	)
	meson_src_compile "${mytargets[@]}"
}

src_install() {
	# lean and mean installation, single binary and man-pages
	pushd "${BUILD_DIR}" > /dev/null || die
	into /
	newbin systemd-tmpfiles.standalone systemd-tmpfiles

	doman man/{systemd-tmpfiles.8,tmpfiles.d.5}

	popd > /dev/null || die

	# The init file installation was intentally removed.
}

src_test() {
	# 'meson test' will compile full systemd, but we can still outsmart it
	python_fix_shebang src/test/test-systemd-tmpfiles.py
	ASAN_OPTIONS=log_path=stderr \
	UBSAN_OPTIONS=print_stacktrace=1:log_path=stderr \
	/mnt/host/source/src/platform2/common-mk/platform2_test.py \
	--sysroot="${SYSROOT}" -- "${EPYTHON}" src/test/test-systemd-tmpfiles.py \
	"/${BUILD_DIR#${SYSROOT}/}"/systemd-tmpfiles.standalone || die "${FUNCNAME} failed"
}

# adapted from opentmpfiles ebuild
add_service() {
	local initd=$1
	local runlevel=$2

	elog "Auto-adding '${initd}' service to your ${runlevel} runlevel"
	mkdir -p "${EROOT}/etc/runlevels/${runlevel}"
	ln -snf "${EROOT}/etc/init.d/${initd}" "${EROOT}/etc/runlevels/${runlevel}/${initd}"
}

pkg_postinst() {
	: # This is intentionally removed from the upstream ebuild.
}
