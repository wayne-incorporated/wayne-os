# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

# The dev-go/grpc* packages are all built from this repo.  They should
# be updated together.
CROS_GO_SOURCE="github.com/grpc/grpc-go:google.golang.org/grpc v${PV}"

CROS_GO_PACKAGES=(
	"google.golang.org/grpc"
	"google.golang.org/grpc/attributes"
	"google.golang.org/grpc/benchmark/stats"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/balancer"
	"google.golang.org/grpc/balancer/base"
	"google.golang.org/grpc/balancer/grpclb/..."
	"google.golang.org/grpc/balancer/roundrobin"
	"google.golang.org/grpc/binarylog/grpc_binarylog_v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/alts/..."
	"google.golang.org/grpc/credentials/google"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/credentials/local"
	"google.golang.org/grpc/credentials/oauth"
	"google.golang.org/grpc/credentials/tls/certprovider/..."
	"google.golang.org/grpc/credentials/xds"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/encoding/proto"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/grpc/internal/..."
	"google.golang.org/grpc/interop/grpc_testing"
	"google.golang.org/grpc/interop/grpc_testing/core"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/reflection/..."
	"google.golang.org/grpc/resolver/..."
	"google.golang.org/grpc/serviceconfig"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/tap"
	"google.golang.org/grpc/test/codec_perf"
	"google.golang.org/grpc/test/grpc_testing"
	"google.golang.org/grpc/testdata"
)

CROS_GO_TEST=(
	"${CROS_GO_PACKAGES[@]}"
)

inherit cros-go

DESCRIPTION="Go implementation of gRPC"
HOMEPAGE="https://grpc.io/"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="
	dev-go/cmp
	dev-go/cncf-xds
	dev-go/glog
	dev-go/ep-gcp
	dev-go/genproto
	dev-go/go-sys
	dev-go/net
	dev-go/oauth2
	dev-go/protobuf-legacy-api
	dev-go/uuid
	dev-go/xxhash
	dev-go/yaml:3
"
RDEPEND="
	${DEPEND}
	!dev-go/grpc-credentials-oauth
"
