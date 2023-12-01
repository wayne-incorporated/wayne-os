# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/opencontainers/go-digest v${PV}"

CROS_GO_PACKAGES=(
	"github.com/opencontainers/go-digest"
)

inherit cros-go

DESCRIPTION="Common digest package used across the container ecosystem"
HOMEPAGE="https://github.com/opencontainers/go-digest"
SRC_URI="$(cros-go_src_uri)"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE="test"
RESTRICT="binchecks strip"
DEPEND=""
RDEPEND="!<=dev-go/docker-20.10.8-r1"
