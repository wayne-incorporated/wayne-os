# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="5"

inherit toolchain-funcs eutils

DESCRIPTION="U2F reference code and test tools"
HOMEPAGE="https://github.com/google/u2f-ref-code"

GIT_SHA1="8f37b6e2265717cbc2acd0a9c4144c7fcd09af6c"
MY_P=${PN}-8f37b6e
SRC_URI="http://github.com/google/u2f-ref-code/archive/${GIT_SHA1}.tar.gz -> ${MY_P}.tar.gz
		https://android.googlesource.com/platform/system/core/+archive/lollipop-release.tar.gz -> android-system-core-lollipop-release.tar.gz"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""

RDEPEND="dev-libs/hidapi
	virtual/libudev"
DEPEND="${RDEPENDS}"

S="${WORKDIR}/${PN}-${GIT_SHA1}"

TESTDIR="${S}/u2f-tests/HID"

src_prepare() {
	ln -s "${WORKDIR}" "${TESTDIR}/core"
}

src_configure() {
	tc-export CC CXX PKG_CONFIG
}

src_compile() {
	emake -C "${TESTDIR}"
}

src_install() {
	dobin "${TESTDIR}/U2FTest"
	dobin "${TESTDIR}/HIDTest"
}
