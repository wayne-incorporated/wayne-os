# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI="7"

DESCRIPTION="Make vmcore smaller by filtering and compressing pages"
HOMEPAGE="https://github.com/makedumpfile/makedumpfile"
SRC_URI="https://github.com/${PN}/${PN}/releases/download/${PV}/makedumpfile-${PV}.tar.gz"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="*"
IUSE=""

PATCHES=(
	"${FILESDIR}/0001-makedumpfile-replace-hardcode-CFLAGS.patch"
)

RDEPEND="dev-libs/elfutils:=
	app-arch/bzip2:=
	app-arch/xz-utils:="
DEPEND="${RDEPEND}"
