# Copyright 1999-2022 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit flag-o-matic multilib toolchain-funcs multilib-minimal

NSPR_VER="4.32"
RTM_NAME="NSS_${PV//./_}_RTM"

DESCRIPTION="Mozilla's Network Security Services library that implements PKI support"
HOMEPAGE="https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS"
SRC_URI="https://archive.mozilla.org/pub/security/nss/releases/${RTM_NAME}/src/${P}.tar.gz
	cacert? ( https://dev.gentoo.org/~whissi/dist/ca-certificates/nss-cacert-class1-class3-r2.patch )"

LICENSE="|| ( MPL-2.0 GPL-2 LGPL-2.1 )"
SLOT="0"
KEYWORDS="*"
IUSE="cacert utils cpu_flags_ppc_altivec cpu_flags_ppc_vsx"
# pkg-config called by nss-config -> virtual/pkgconfig in RDEPEND
RDEPEND="
	>=dev-libs/nspr-${NSPR_VER}[${MULTILIB_USEDEP}]
	>=dev-db/sqlite-3.8.2[${MULTILIB_USEDEP}]
	>=sys-libs/zlib-1.2.8-r1[${MULTILIB_USEDEP}]
	virtual/pkgconfig
	>=dev-libs/nss-${PV}[${MULTILIB_USEDEP}]
"
DEPEND="${RDEPEND}"
BDEPEND="dev-lang/perl"

RESTRICT="test"

S="${WORKDIR}/${P}/${PN}"

PATCHES=(
	# Custom changes for gentoo
	"${FILESDIR}/${PN}-3.53-gentoo-fixups.patch"
	"${FILESDIR}/${PN}-3.21-gentoo-fixup-warnings.patch"
	"${FILESDIR}/${PN}-3.23-hppa-byte_order.patch"
	# CrOS specific fix crbug.com/1132030
	"${FILESDIR}/${PN}-3.44-prefer-writable-tokens-for-trust.patch"
	# local fix for https://bugs.gentoo.org/834846
	"${FILESDIR}/${PN}-3.68.2-nss-ld-fixup.patch"
)

src_prepare() {
	# use host shlibsign if need be crbug.com/884946
	if tc-is-cross-compiler ; then
		PATCHES+=(
			"${FILESDIR}/${PN}-3.38-shlibsign-path-pollution.patch"
		)
	fi

	default

	if use cacert ; then
		eapply -p2 "${DISTDIR}"/nss-cacert-class1-class3-r2.patch
	fi

	pushd coreconf >/dev/null || die
	# hack nspr paths
	echo 'INCLUDES += -I$(DIST)/include/dbm' \
		>> headers.mk || die "failed to append include"

	# modify install path
	sed -e '/CORE_DEPTH/s:SOURCE_PREFIX.*$:SOURCE_PREFIX = $(CORE_DEPTH)/dist:' \
		-i source.mk || die

	# Respect LDFLAGS
	sed -i -e 's/\$(MKSHLIB) -o/\$(MKSHLIB) \$(LDFLAGS) -o/g' rules.mk
	popd >/dev/null || die

	# Fix pkgconfig file for Prefix
	sed -i -e "/^PREFIX =/s:= /usr:= ${EPREFIX}/usr:" \
		config/Makefile || die

	# use host shlibsign if need be #436216
	if tc-is-cross-compiler ; then
		sed -i \
			-e 's:"${2}"/shlibsign:shlibsign:' \
			cmd/shlibsign/sign.sh || die
	fi

	# dirty hack
	sed -i -e "/CRYPTOLIB/s:\$(SOFTOKEN_LIB_DIR):../freebl/\$(OBJDIR):" \
		lib/ssl/config.mk || die
	sed -i -e "/CRYPTOLIB/s:\$(SOFTOKEN_LIB_DIR):../../lib/freebl/\$(OBJDIR):" \
		cmd/platlibs.mk || die

	multilib_copy_sources

	strip-flags
}

multilib_src_configure() {
	# Ensure we stay multilib aware
	sed -i -e "/@libdir@/ s:lib64:$(get_libdir):" config/Makefile || die
}

nssarch() {
	# Most of the arches are the same as $ARCH
	local t=${1:-${CHOST}}
	case ${t} in
		*86*-pc-solaris2*) echo "i86pc"   ;;
		aarch64*)          echo "aarch64" ;;
		hppa*)             echo "parisc"  ;;
		i?86*)             echo "i686"    ;;
		x86_64*)           echo "x86_64"  ;;
		*)                 tc-arch ${t}   ;;
	esac
}

nssbits() {
	local cc cppflags="${1}CPPFLAGS" cflags="${1}CFLAGS"
	if [[ ${1} == BUILD_ ]]; then
		cc=$(tc-getBUILD_CC)
	else
		cc=$(tc-getCC)
	fi
	echo > "${T}"/test.c || die
	${cc} ${!cppflags} ${!cflags} -c "${T}"/test.c -o "${T}/${1}test.o" || die
	case $(file "${T}/${1}test.o") in
		*32-bit*x86-64*) echo USE_X32=1;;
		*64-bit*|*ppc64*|*x86_64*) echo USE_64=1;;
		*32-bit*|*ppc*|*i386*) ;;
		*) die "Failed to detect whether ${cc} builds 64bits or 32bits, disable distcc if you're using it, please";;
	esac
}

multilib_src_compile() {
	# use ABI to determine bit'ness, or fallback if unset
	local buildbits mybits
	case "${ABI}" in
		n32) mybits="USE_N32=1";;
		x32) mybits="USE_X32=1";;
		s390x|*64) mybits="USE_64=1";;
		${DEFAULT_ABI})
			einfo "Running compilation test to determine bit'ness"
			mybits=$(nssbits)
			;;
	esac
	# bitness of host may differ from target
	if tc-is-cross-compiler; then
		buildbits=$(nssbits BUILD_)
	fi

	local makeargs=(
		CC="$(tc-getCC)"
		CCC="$(tc-getCXX)"
		AR="$(tc-getAR) rc \$@"
		RANLIB="$(tc-getRANLIB)"
		OPTIMIZER=
		${mybits}
	)

	# Take care of nspr settings #436216
	local myCPPFLAGS="${CPPFLAGS} $($(tc-getPKG_CONFIG) nspr --cflags)"
	unset NSPR_INCLUDE_DIR

	export NSS_ALLOW_SSLKEYLOGFILE=1
	export NSS_ENABLE_WERROR=0 #567158
	export BUILD_OPT=1
	export NSS_USE_SYSTEM_SQLITE=1
	export NSDISTMODE=copy
	export FREEBL_NO_DEPEND=1
	export FREEBL_LOWHASH=1
	export NSS_SEED_ONLY_DEV_URANDOM=1
	export USE_SYSTEM_ZLIB=1
	export ZLIB_LIBS=-lz
	export ASFLAGS=""
	# Fix build failure on arm64
	export NS_USE_GCC=1
	# Detect compiler type and set proper environment value
	if tc-is-gcc; then
		export CC_IS_GCC=1
	elif tc-is-clang; then
		export CC_IS_CLANG=1
	fi

	# explicitly disable altivec/vsx if not requested
	# https://bugs.gentoo.org/789114
	case ${ARCH} in
		ppc*)
			use cpu_flags_ppc_altivec || export NSS_DISABLE_ALTIVEC=1
			use cpu_flags_ppc_vsx || export NSS_DISABLE_CRYPTO_VSX=1
			;;
	esac

	local d

	# Build the host tools first.
	LDFLAGS="${BUILD_LDFLAGS}" \
	XCFLAGS="${BUILD_CFLAGS}" \
	NSPR_LIB_DIR="${T}/fakedir" \
	emake -j1 -C coreconf \
		CC="$(tc-getBUILD_CC)" \
		${buildbits-${mybits}}
	makeargs+=( NSINSTALL="${PWD}/$(find -type f -name nsinstall)" )

	# Then build the target tools.
	for d in . lib/dbm ; do
		CPPFLAGS="${myCPPFLAGS}" \
		XCFLAGS="${CFLAGS} ${CPPFLAGS}" \
		NSPR_LIB_DIR="${T}/fakedir" \
		emake -j1 "${makeargs[@]}" -C ${d} OS_TEST="$(nssarch)"
	done
}

multilib_src_install() {
	local f nssutils

	# The tests we do not need to install.
	#nssutils_test="bltest crmftest dbtest dertimetest
	#fipstest remtest sdrtest"
	# checkcert utils has been removed in nss-3.22:
	# https://bugzilla.mozilla.org/show_bug.cgi?id=1187545
	# https://hg.mozilla.org/projects/nss/rev/df1729d37870
	# certcgi has been removed in nss-3.36:
	# https://bugzilla.mozilla.org/show_bug.cgi?id=1426602
	nssutils=(
		addbuiltin
		atob
		baddbdir
		btoa
		certutil
		cmsutil
		conflict
		crlutil
		derdump
		digest
		makepqg
		mangle
		modutil
		multinit
		nonspr10
		ocspclnt
		oidcalc
		p7content
		p7env
		p7sign
		p7verify
		pk11mode
		pk12util
		pp
		rsaperf
		selfserv
		signtool
		signver
		ssltap
		strsclnt
		symkeyutil
		tstclnt
		vfychain
		vfyserv
	)
	pushd dist/*/bin >/dev/null || die
	into /usr/local
	for f in "${nssutils[@]}"; do
		dobin "${f}"
	done
	popd >/dev/null || die
}
