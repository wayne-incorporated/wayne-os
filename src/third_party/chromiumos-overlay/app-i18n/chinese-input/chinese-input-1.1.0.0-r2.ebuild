# Copyright 2013 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="4"

DESCRIPTION="This is a meta package for installing Chinese IME packages"
HOMEPAGE="http://www.google.com/inputtools/"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE="internal"

RDEPEND="
	!internal? (
		app-i18n/chromeos-cangjie
		app-i18n/chromeos-pinyin
		app-i18n/chromeos-zhuyin
	)"
DEPEND="${RDEPEND}"
