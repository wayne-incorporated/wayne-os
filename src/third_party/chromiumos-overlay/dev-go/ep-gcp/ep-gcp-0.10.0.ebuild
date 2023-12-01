# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

# The dev-go/gcp* packages are all built from this repo.  They should
# be updated together.
CROS_GO_SOURCE="github.com/envoyproxy/go-control-plane:github.com/envoyproxy/go-control-plane v${PV}"

CROS_GO_PACKAGES=(
	"github.com/envoyproxy/go-control-plane/envoy/annotations"
	"github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	"github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/envoyproxy/go-control-plane/envoy/type/metadata/v3"
	"github.com/envoyproxy/go-control-plane/envoy/type/tracing/v3"
	"github.com/envoyproxy/go-control-plane/envoy/type/v3"
)

CROS_GO_TEST=(
	"${CROS_GO_PACKAGES[@]}"
)

inherit cros-go

DESCRIPTION="Discovery service APIs for Go"
HOMEPAGE="https://github.com/envoyproxy/go-control-plane"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks"

DEPEND="
	dev-go/cncf-xds
	dev-go/ep-pvg
	dev-go/genproto
	dev-go/go-sys
	dev-go/net
	dev-go/protobuf
	dev-go/protobuf-legacy-api
	dev-go/testify
"
RDEPEND="${DEPEND}"
