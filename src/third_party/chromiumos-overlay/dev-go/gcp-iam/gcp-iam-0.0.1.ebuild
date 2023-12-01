# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

# The dev-go/gcp* packages are versioned separately but all come from the same
# repo to simplify updates we set them all to be the same ebuild version but
# all should point to same git hash corresponding to a release and be update
# together
CROS_GO_SOURCE="github.com/GoogleCloudPlatform/google-cloud-go:cloud.google.com/go 06a54a16a5866cce966547c51e203b9e09a25bc0"

CROS_GO_PACKAGES=(
	"cloud.google.com/go/iam"
	"cloud.google.com/go/iam/apiv1"
	"cloud.google.com/go/iam/apiv1/iampb"
	"cloud.google.com/go/iam/internal"
)

CROS_GO_TEST=(
	"${CROS_GO_PACKAGES[@]}"
)

inherit cros-go

DESCRIPTION="Google Cloud Client Libraries of IAM APIs for Go"
HOMEPAGE="https://code.googlesource.com/gocloud"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="
	dev-go/gapi
	dev-go/gax:1
	dev-go/genproto
	dev-go/grpc
	dev-go/net
	dev-go/protobuf-legacy-api
"
RDEPEND="${DEPEND}"
