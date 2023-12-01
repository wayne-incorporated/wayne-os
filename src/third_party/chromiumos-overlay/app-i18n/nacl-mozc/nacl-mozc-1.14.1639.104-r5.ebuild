# Copyright 2013 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="4"
inherit eutils

INTERNAL_NACL_MOZC_P="nacl-mozc-1.15.1800.4"

DESCRIPTION="The Mozc engine for IME extension API"
HOMEPAGE="http://code.google.com/p/mozc"
S="${WORKDIR}"
SRC_URI="!internal? ( http://commondatastorage.googleapis.com/chromeos-localmirror/distfiles/nacl-mozc-${PV}.tgz )
internal? ( gs://chromeos-localmirror-private/distfiles/${INTERNAL_NACL_MOZC_P}.tgz )"

LICENSE="BSD-Google"
IUSE="internal"
SLOT="0"
KEYWORDS="*"
RESTRICT="mirror"

src_prepare() {
	cd ${PN}-*/ || die

	# Removes unused NaCl binaries.
	if ! use arm && ! use arm64; then
		rm nacl_session_handler_arm.nexe || die
	fi
	if ! use x86 ; then
		rm nacl_session_handler_x86_32.nexe || die
	fi
	if ! use amd64 ; then
		rm nacl_session_handler_x86_64.nexe || die
	fi

	# Inserts the public key to manifest.json.
	# The key is used to execute NaCl Mozc as a component extension.
	if use internal; then
		# NaCl Mozc is handled as id:fpfbhcjppmaeaijcidgiibchfbnhbelj.
		epatch "${FILESDIR}"/${INTERNAL_NACL_MOZC_P}-insert-internal-public-key.patch
		epatch "${FILESDIR}"/${INTERNAL_NACL_MOZC_P}-call-startIme.patch
                epatch "${FILESDIR}"/${INTERNAL_NACL_MOZC_P}-fix-software-keyboard-bug.patch
	else
		# NaCl Mozc is handled as id:bbaiamgfapehflhememkfglaehiobjnk.
		epatch "${FILESDIR}"/${P}-insert-oss-public-key.patch
	fi
}

src_install() {
	cd ${PN}-*/ || die

	insinto /usr/share/chromeos-assets/input_methods/nacl_mozc
	doins -r *
}
