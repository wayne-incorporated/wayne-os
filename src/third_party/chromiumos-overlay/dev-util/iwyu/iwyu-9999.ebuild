# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

PYTHON_COMPAT=( python3_{6..9} )

CROS_WORKON_PROJECT="external/github.com/include-what-you-use/include-what-you-use"
CROS_WORKON_LOCALNAME="include-what-you-use"
CROS_WORKON_DESTDIR="${S}"

inherit cmake git-r3 cros-workon python-single-r1

DESCRIPTION="Include What You Use"
HOMEPAGE="https://include-what-you-use.org/"
SRC_URI=""

LICENSE="UoI-NCSA"
SLOT="0"
KEYWORDS="~*"
IUSE=""

RDEPEND="${PYTHON_DEPS}"

DEPEND="
	sys-devel/llvm
	${RDEPEND}
"

REQUIRED_USE="${PYTHON_REQUIRED_USE}"

pkg_setup() {
	cros-workon_pkg_setup
	python-single-r1_pkg_setup
}

src_prepare() {
	if has_version "sys-devel/llvm[llvm-next]" || has_version ">sys-devel/llvm-16.0_pre484197_p20230405-r1000"; then
		true
	else
		eapply "${FILESDIR}/${PN}-Revert-clang-compat-Use-new-include-path-for-Host.patch"
		eapply "${FILESDIR}/${PN}-Revert-clang-compat-Use-new-include-path-for-Triple.patch"
	fi
	eapply_user
	cmake_src_prepare
	python_fix_shebang .
}
