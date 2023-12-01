# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="MARISA: Matching Algorithm with Recursively Implemented StorAge (AOSP fork)"
HOMEPAGE="https://android.googlesource.com/platform/external/marisa-trie/"

inherit cros-constants

CROS_WORKON_REPO=(
	"${CROS_GIT_HOST_URL}"
	"${CROS_GIT_AOSP_URL}"
)
CROS_WORKON_LOCALNAME=(
	"../platform2"
	"../aosp/external/marisa-trie"
)
CROS_WORKON_PROJECT=(
	"chromiumos/platform2"
	"platform/external/marisa-trie"
)
CROS_WORKON_DESTDIR=(
	"${S}/platform2"
	"${S}/platform2/marisa-trie"
)
CROS_WORKON_SUBTREE=(
	"common-mk .gn"
	""
)
CROS_WORKON_EGIT_BRANCH=(
	"main"
	"master"
)
# To uprev manually, run:
#    cros_mark_as_stable --force --overlay-type public --packages \
#      dev-libs/marisa-aosp commit
CROS_WORKON_MANUAL_UPREV="1"

PLATFORM_SUBDIR="marisa-trie"

inherit cros-workon platform

LICENSE="BSD-2 LGPL-2.1 BSD-Google"
SLOT="0"
KEYWORDS="~*"

IUSE=""
REQUIRED_USE=""

# To warn future developers that this is the AOSP fork of marisa.
POSTFIX="-aosp"

src_prepare() {
	default
	cp "${FILESDIR}/BUILD.gn" "${S}"
}

src_install() {
	platform_src_install

	mv "${OUT}/libmarisa.a" "${OUT}/libmarisa${POSTFIX}.a"
	dolib.a "${OUT}/libmarisa${POSTFIX}.a"

	# Install the header files to /usr/include/marisa-trie/.
	insinto "/usr/include/marisa${POSTFIX}"
	doins "${S}/include/marisa.h"
	insinto "/usr/include/marisa${POSTFIX}/marisa"
	local f
	for f in \
		"include/marisa/agent.h" \
		"include/marisa/base.h" \
		"include/marisa/exception.h" \
		"include/marisa/iostream.h" \
		"include/marisa/key.h" \
		"include/marisa/keyset.h" \
		"include/marisa/query.h" \
		"include/marisa/scoped-array.h" \
		"include/marisa/scoped-ptr.h" \
		"include/marisa/stdio.h" \
		"include/marisa/trie.h"; do
		doins "${S}/${f}"
	done
}
