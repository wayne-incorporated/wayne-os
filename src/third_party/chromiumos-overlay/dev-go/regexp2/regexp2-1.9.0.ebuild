# Copyright 2023 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/dlclark/regexp2 v${PV}"

CROS_GO_PACKAGES=(
	"github.com/dlclark/regexp2"
	"github.com/dlclark/regexp2/syntax"
)

CROS_GO_TEST=(
	"${CROS_GO_PACKAGES[@]}"
)

inherit cros-go

DESCRIPTION="A full-featured regex engine in pure Go based on the .NET engine"
HOMEPAGE="https://github.com/dlclark/regexp2"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""

DEPEND=""
RDEPEND=""
