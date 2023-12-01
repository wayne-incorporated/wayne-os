# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/containerd/containerd v${PV}"

CROS_GO_PACKAGES=(
	"github.com/containerd/containerd/errdefs"
)

inherit cros-go

DESCRIPTION="An open and reliable container runtime"
HOMEPAGE="https://github.com/containerd/containerd"
SRC_URI="$(cros-go_src_uri)"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE="test"
RESTRICT="binchecks strip"
DEPEND="
	dev-go/errcheck
	dev-go/grpc
"
RDEPEND="!<=dev-go/docker-20.10.8-r1"
