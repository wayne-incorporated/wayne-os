# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


EAPI=7

CROS_GO_SOURCE="github.com/go-ini/ini:gopkg.in/ini.v1 b2f570e5b5b844226bbefe6fb521d891f529a951"

CROS_GO_PACKAGES=(
	"gopkg.in/ini.v1"
)

inherit cros-go

DESCRIPTION="INI file read and write functionality in Go"
HOMEPAGE="https://github.com/go-ini/ini"
SRC_URI="$(cros-go_src_uri)"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND=""
RDEPEND=""
