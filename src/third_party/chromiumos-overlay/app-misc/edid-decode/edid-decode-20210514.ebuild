# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="5"

inherit toolchain-funcs eutils

DESCRIPTION="Extended Display Identification Data (EDID) decoder"
HOMEPAGE="https://git.linuxtv.org/edid-decode.git/about"

## To Uprev ##
# git clone git://linuxtv.org/edid-decode.git
# cd edid-decode
# git archive --format=tar.gz --prefix=edid-decode-20190614/ 15df4ae -o edid-decode-20190614.tar.gz
# gsutil cp -n -a public-read edid-decode-20190614.tar.gz gs://chromeos-localmirror/distfiles/edid-decode-20190614.tar.gz
SRC_URI="http://commondatastorage.googleapis.com/chromeos-localmirror/distfiles/${P}.tar.gz"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""

src_configure() {
	tc-export CC
}
