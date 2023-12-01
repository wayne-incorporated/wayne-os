# Copyright 2010 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2
# $Header$

EAPI="7"
CROS_WORKON_COMMIT="421593a8cea1083288d5d047b0c43f85c92fe069"
CROS_WORKON_TREE="0d347f2d000b90963fc38d64ae9259ecf19535cf"
CROS_WORKON_PROJECT="chromiumos/platform/tpm"
CROS_WORKON_LOCALNAME="../third_party/tpm"

inherit cros-sanitizers cros-workon toolchain-funcs

DESCRIPTION="Various TPM tools"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/tpm/"

LICENSE="BSD"
SLOT="0/0"
KEYWORDS="*"
IUSE="-asan"

RDEPEND="app-crypt/trousers:="
DEPEND="${RDEPEND}"

src_configure() {
	sanitizers-setup-env
	default
}

src_compile() {
	emake -C nvtool CC="$(tc-getCC)"
}

src_install() {
	dobin nvtool/tpm-nvtool
}
