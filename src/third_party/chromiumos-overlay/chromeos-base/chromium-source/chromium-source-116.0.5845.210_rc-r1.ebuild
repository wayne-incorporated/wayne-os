# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# Downloads Chrome sources to ${CHROMIUM_SOURCE_DIR} which is typically
# set to /var/cache/chromeos-cache/distfiles/target/chrome-src.

EAPI="6"
inherit chromium-source

DESCRIPTION="Source code for the open-source version of Google Chrome web browser"
HOMEPAGE="http://www.chromium.org/"
SRC_URI=""

LICENSE="BSD-Google
	chrome_internal? ( Google-TOS )"
SLOT="0"
KEYWORDS="*"
IUSE=""
