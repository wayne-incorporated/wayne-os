# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

inherit toolchain-funcs flag-o-matic

DESCRIPTION="A small vi/ex editor for editing bidirectional UTF-8 text"
HOMEPAGE="https://github.com/aligrudi/neatvi"
SRC_URI="${HOMEPAGE}/archive/refs/tags/${PV}.tar.gz -> ${PN}-${PV}.tar.gz"

LICENSE="MIT"
KEYWORDS="*"
SLOT="0"

src_configure() {
	tc-export CC
	append-lfs-flags
}

src_compile() {
	emake CC="${CC}" CFLAGS="${CFLAGS} ${CPPFLAGS}" LDFLAGS="${LDFLAGS}"
}

src_install() {
	dobin vi
	dosym vi /usr/bin/ex
	dosym vi /usr/bin/view
	dosym vi /usr/bin/rvi
}
