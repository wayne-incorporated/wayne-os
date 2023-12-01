# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/google/google-api-go-client:google.golang.org/api v${PV}"

# temporary cyclic dep workaround until we switch to modules mode
# which can correctly handle for eg gapi -> opencensus -> gapi
CROS_GO_SKIP_DEP_CHECK="1"

CROS_GO_PACKAGES=(
	"google.golang.org/api/bigquery/v2"
	"google.golang.org/api/support/bundler"
	"google.golang.org/api/discovery/v1"
	"google.golang.org/api/drive/v3"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/googleapi/transport"
	"google.golang.org/api/iamcredentials/v1"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/internal"
	"google.golang.org/api/internal/gensupport"
	"google.golang.org/api/internal/impersonate"
	"google.golang.org/api/internal/third_party/uritemplates"
	"google.golang.org/api/iterator"
	"google.golang.org/api/iterator/testing"
	"google.golang.org/api/option"
	"google.golang.org/api/option/internaloption"
	"google.golang.org/api/storage/v1"
	"google.golang.org/api/transport"
	"google.golang.org/api/transport/cert"
	"google.golang.org/api/transport/grpc"
	"google.golang.org/api/transport/http"
	"google.golang.org/api/transport/http/internal/propagation"
	"google.golang.org/api/transport/internal/dca"
)

CROS_GO_TEST=(
	"${CROS_GO_PACKAGES[@]}"
)

inherit cros-go

DESCRIPTION="Auto-generated Google APIs for Go"
HOMEPAGE="https://github.com/google/google-api-go-client"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks"

DEPEND="
	dev-go/appengine
	dev-go/genproto
	dev-go/golang-groupcache
	dev-go/cmp
	dev-go/net
	dev-go/enterprise-certificate-proxy
"
RDEPEND="
	!dev-go/gapi-bigquery
	!dev-go/gapi-bundler
	!dev-go/gapi-discovery
	!dev-go/gapi-drive
	!dev-go/gapi-gensupport
	!dev-go/gapi-googleapi
	!dev-go/gapi-iamcredentials
	!dev-go/gapi-internal
	!dev-go/gapi-internal-thirdparty
	!dev-go/gapi-iterator
	!dev-go/gapi-option
	!dev-go/gapi-storage
	!dev-go/gapi-transport
"
