# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="A broad, well-tested, modular, and cross-browser JavaScript library"
HOMEPAGE="https://developers.google.com/closure/library/"
GIT_REV="26b34f2241fece8df8d7424a275b0e0ce571303b"
SRC_URI="https://github.com/google/${PN}/archive/${GIT_REV}.tar.gz -> ${P}.tar.gz"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"

S="${WORKDIR}"

src_install() {
	insinto /opt/closure-library
	doins -r closure-library-${GIT_REV}/*
}
