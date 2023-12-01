# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

# The dev-go/gcp* packages are all built from this repo. They should be updated
# together.
CROS_GO_SOURCE="github.com/GoogleCloudPlatform/google-cloud-go:cloud.google.com/go 06a54a16a5866cce966547c51e203b9e09a25bc0"

CROS_GO_PACKAGES=(
	"cloud.google.com/go/storage"
	"cloud.google.com/go/storage/internal"
	"cloud.google.com/go/storage/internal/apiv2"
	"cloud.google.com/go/storage/internal/apiv2/stubs"
	"cloud.google.com/go/storage/internal/test/conformance"
)

CROS_GO_TEST=(
	"${CROS_GO_PACKAGES[@]}"
)

inherit cros-go

DESCRIPTION="Google Cloud Client Libraries for Go"
HOMEPAGE="https://code.googlesource.com/gocloud"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks"

DEPEND="
	dev-go/gapi
	dev-go/gcp
	dev-go/gcp-iam
	dev-go/genproto
	dev-go/gax
"
RDEPEND="${DEPEND}"
