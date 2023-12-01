# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the Apache License v2.

EAPI="4"
inherit eutils

DESCRIPTION="The wrapping IME extension for xkb-based input methods"
HOMEPAGE="https://code.google.com/p/google-input-tools"
# TODO: Change the $PF to $P.
SRC_URI="http://commondatastorage.googleapis.com/chromeos-localmirror/distfiles/${P}.tar.gz"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"

S="${WORKDIR}/${PN}"

src_prepare() {
	epatch "${FILESDIR}"/${P}-insert-pub-key.patch
}

src_install() {
	insinto /usr/share/chromeos-assets/input_methods/xkb
	doins -r *
}
