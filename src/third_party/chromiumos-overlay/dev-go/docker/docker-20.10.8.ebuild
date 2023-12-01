# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7
CROS_GO_SOURCE=(
	"github.com/moby/moby:github.com/docker/docker 5f0703c549935d2cfec42b468b858d822b58a27e"
)

PATCHES=(
	"${FILESDIR}"/docker-20.10.8-add-distribution-major-ver.patch
)

CROS_GO_PACKAGES=(
	"github.com/docker/docker/api"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/blkiodev"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/api/types/strslice"
	"github.com/docker/docker/api/types/swarm"
	"github.com/docker/docker/api/types/swarm/runtime"
	"github.com/docker/docker/api/types/time"
	"github.com/docker/docker/api/types/versions"
	"github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/client"
	"github.com/docker/docker/errdefs"
	"github.com/docker/docker/pkg/stdcopy"
)

inherit cros-go

CROS_GO_TEST=(
	"${CROS_GO_PACKAGES[@]}"
)

DESCRIPTION="Docker SDK in Go"
HOMEPAGE="mobyproject.org"
SRC_URI="$(cros-go_src_uri)"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="
	dev-go/containerd
	dev-go/crypto
	dev-go/distribution
	dev-go/errors
	dev-go/go-connections
	dev-go/go-digest
	dev-go/go-sys
	dev-go/go-units
	dev-go/gogo-protobuf
	dev-go/grpc
	dev-go/image-spec
	dev-go/logrus
	dev-go/net
	dev-go/protobuf
	dev-go/protobuf-legacy-api
	dev-go/text
"
RDEPEND="${DEPEND}"
