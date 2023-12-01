# Copyright 1999-2022 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit meson-multilib

DESCRIPTION="C libary for Netflix's Perceptual video quality assessment"
HOMEPAGE="https://github.com/Netflix/vmaf"

if [[ ${PV} == "9999" ]]; then
	inherit git-r3
	EGIT_REPO_URI="https://github.com/Netflix/vmaf.git"
else
	SRC_URI="
		https://github.com/Netflix/vmaf/archive/v${PV}.tar.gz -> ${P}.tar.gz
	"
	KEYWORDS="*"
fi

LICENSE="BSD-2-with-patent"
SLOT="0"
IUSE="embed-models test"

RESTRICT="!test? ( test )"

BDEPEND="
	dev-lang/nasm
	embed-models? ( app-editors/vim-core )
"

RDEPEND="${BDEPEND}"

S="${WORKDIR}/vmaf-${PV}"

src_prepare() {
	default

	# Workaround for https://bugs.gentoo.org/837221
	# The paths in the tests are hard coded to look for the model folder as "../../model"
	sed -i "s|\"../../model|\"../vmaf-${PV}/model|g" "${S}"/libvmaf/test/* || die
}

multilib_src_configure() {

	# Enable exceptions for this package. This goes against Style Guide, but since
	# vmaf is a standalone binary and only used for testing, it's OK.
	# https://chromium.googlesource.com/website/+/HEAD/site/chromium-os/build/c-exception-support/index.md
	cros_enable_cxx_exceptions

	local emesonargs=(
		$(meson_use embed-models built_in_models)
		$(meson_use test enable_tests)
		-Dbuilt_in_models=true
	)

	EMESON_SOURCE="${S}/libvmaf"
	meson_src_configure
}

multilib_src_install() {
	meson_src_install
	find "${D}" -name '*.la' -delete -o -name '*.a' -delete || die
}

multilib_src_install_all() {
	einstalldocs

	insinto "/usr/share/vmaf"
	doins -r "${S}/model"
}
