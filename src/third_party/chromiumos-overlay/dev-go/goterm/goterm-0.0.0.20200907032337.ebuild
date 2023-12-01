# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

CROS_GO_SOURCE="github.com/google/goterm 555d40f16ae2fad8b4429d18d5cb777e75e5a9dc"
CROS_GO_PACKAGES=(
	"github.com/google/goterm/term"
)

inherit cros-go

DESCRIPTION="Go Terminal library with PTY support and colors"
HOMEPAGE="https://github.com/google/goterm"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""
