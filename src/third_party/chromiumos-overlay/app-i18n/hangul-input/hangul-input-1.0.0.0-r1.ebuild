# Copyright 2016 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="4"

DESCRIPTION="This is a meta package for installing hangul IME packages"
HOMEPAGE="https://code.google.com/p/google-input-tools/"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE="internal"

RDEPEND="
        !internal? (
                app-i18n/chromeos-hangul
        )"
DEPEND="${RDEPEND}"
