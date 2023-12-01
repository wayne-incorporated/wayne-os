# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/google/go-genproto:google.golang.org/genproto dcfb400f0633028bb925288e6cd93e22e4946303"

CROS_GO_PACKAGES=(
	"google.golang.org/genproto/googleapis/api"
	"google.golang.org/genproto/googleapis/api/annotations"
	"google.golang.org/genproto/googleapis/api/distribution"
	"google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/genproto/googleapis/api/label"
	"google.golang.org/genproto/googleapis/api/metric"
	"google.golang.org/genproto/googleapis/api/monitoredres"
	"google.golang.org/genproto/googleapis/api/serviceconfig"
	"google.golang.org/genproto/googleapis/cloud/bigquery/connection/v1"
	"google.golang.org/genproto/googleapis/chromeos/uidetection/v1/..."
	"google.golang.org/genproto/googleapis/devtools/cloudtrace/v2"
	"google.golang.org/genproto/googleapis/iam/v1"
	"google.golang.org/genproto/googleapis/longrunning"
	"google.golang.org/genproto/googleapis/monitoring/v3"
	"google.golang.org/genproto/googleapis/pubsub/v1"
	"google.golang.org/genproto/googleapis/rpc/code"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/genproto/googleapis/storage/v2"
	"google.golang.org/genproto/googleapis/type/calendarperiod"
	"google.golang.org/genproto/googleapis/type/date"
	"google.golang.org/genproto/googleapis/type/expr"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/genproto/googleapis/chromeos/moblab/v1beta1"
)

CROS_GO_TEST=(
	"${CROS_GO_PACKAGES[@]}"
)

inherit cros-go

DESCRIPTION="Go generated proto packages"
HOMEPAGE="https://github.com/googleapis/googleapis/"
SRC_URI="$(cros-go_src_uri)"

CROS_GO_SKIP_DEP_CHECK="1"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="
	dev-go/protobuf-legacy-api
	!dev-go/genproto-rpc
	!dev-go/genproto-api-expr
	!dev-go/genproto-chromeosuidetection
"
RDEPEND="${DEPEND}"
