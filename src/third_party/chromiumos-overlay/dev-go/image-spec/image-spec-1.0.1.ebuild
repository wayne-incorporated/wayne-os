# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/opencontainers/image-spec v${PV}"

CROS_GO_PACKAGES=(
	"github.com/opencontainers/image-spec/specs-go"
	"github.com/opencontainers/image-spec/specs-go/v1"
)

inherit cros-go

DESCRIPTION="OCI Image Format"
HOMEPAGE="https://github.com/opencontainers/image-spec"
SRC_URI="$(cros-go_src_uri)"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE="test"
RESTRICT="binchecks strip"
DEPEND="
	dev-go/blackfriday
	dev-go/errors
	dev-go/go-digest
	dev-go/go-spew
	dev-go/testify
	dev-go/yaml:3
"
RDEPEND="!<=dev-go/docker-20.10.8-r1"
