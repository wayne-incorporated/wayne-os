# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

# The dev-go/gcp* packages are versioned separately but all come from the same
# repo to simplify updates we set them all to be the same ebuild version but
# all should point to same git hash corresponding to a release and be update
# together
CROS_GO_SOURCE="github.com/GoogleCloudPlatform/google-cloud-go:cloud.google.com/go 06a54a16a5866cce966547c51e203b9e09a25bc0"

CROS_GO_PACKAGES=(
	"cloud.google.com/go/civil"
	"cloud.google.com/go/internal"
	"cloud.google.com/go/internal/detect"
	"cloud.google.com/go/internal/fields"
	"cloud.google.com/go/internal/optional"
	"cloud.google.com/go/internal/trace"
	"cloud.google.com/go/internal/testutil"
	"cloud.google.com/go/internal/uid"
	"cloud.google.com/go/internal/version"
	"cloud.google.com/go/httpreplay/..."
	"cloud.google.com/go/longrunning/..."
)

CROS_GO_TEST=(
	"${CROS_GO_PACKAGES[@]}"
)

# temporary cyclic dep workaround until we switch to modules mode
CROS_GO_SKIP_DEP_CHECK="1"

inherit cros-go

DESCRIPTION="Google Cloud Client Libraries for Go"
HOMEPAGE="https://code.googlesource.com/gocloud"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="
	dev-go/cmp
	dev-go/gapi
	dev-go/genproto
	dev-go/net
	dev-go/protoc-gen-go-grpc
	dev-go/martian
	dev-go/gax
"
RDEPEND="
	${DEPEND}
	!dev-go/gcp-internal
	!dev-go/gcp-civil
"
