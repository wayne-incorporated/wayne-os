# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

inherit toolchain-funcs

DESCRIPTION="QEMU wrappers to preserve argv[0] when testing"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/docs/+/HEAD/testing/qemu_unit_tests_design.md"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""

S=${WORKDIR}

src_compile() {
	# We normally want FLAGS variables quoted, but when running the compiler
	# directly here, we want to let them expand.
	# shellcheck disable=SC2086
	$(tc-getCC) \
		-Wall -Wextra -Werror \
		${CFLAGS} \
		${CPPFLAGS} \
		${LDFLAGS} \
		"${FILESDIR}"/${PN}.c \
		-o ${PN} \
		-static || die
}

src_install() {
	dobin ${PN}
}
