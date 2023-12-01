# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

CROS_GO_SOURCE="github.com/go-tomb/tomb:gopkg.in/tomb.v1 dd632973f1e7218eb1089048e0798ec9ae7dceb8"

CROS_GO_PACKAGES=(
	"gopkg.in/tomb.v1"
)

inherit cros-go

DESCRIPTION="The package handles clean goroutine tracking and termination."
HOMEPAGE="https://github.com/go-tomb/tomb"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND=""
RDEPEND=""
