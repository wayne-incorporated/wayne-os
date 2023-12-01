# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

CROS_GO_SOURCE="github.com/dustin/go-humanize v${PV}"
CROS_GO_PACKAGES=(
	"github.com/dustin/go-humanize"
)

inherit cros-go

DESCRIPTION="Formatters for units to human friendly sizes"
HOMEPAGE="https://github.com/dustin/go-humanize"
SRC_URI="$(cros-go_src_uri)"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""
