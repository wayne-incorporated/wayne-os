# Copyright 2013 The ChromiumOS Authors
# Distributed under the terms of the Apache License v2.

EAPI="4"
inherit eutils

DESCRIPTION="The Google Input Tools (keyboard part) based on IME Extension API"
HOMEPAGE="https://code.google.com/p/google-input-tools"
# TODO: Change the $PF to $P.
SRC_URI="http://commondatastorage.googleapis.com/chromeos-localmirror/distfiles/${PF}.tar.gz"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"

S="${WORKDIR}/${PN}"

src_prepare() {
	epatch "${FILESDIR}"/${P}-insert-pub-key-private-api.patch
}

src_install() {
	insinto /usr/share/chromeos-assets/input_methods/keyboard_layouts
	doins -r *
}
