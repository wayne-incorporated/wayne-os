# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

# The dev-go/gcp* packages are versioned separately but all come from the same
# repo to simplify updates we set them all to be the same ebuild version but
# all should point to same git hash corresponding to a release and be update
# together
CROS_GO_SOURCE="github.com/GoogleCloudPlatform/google-cloud-go:cloud.google.com/go 06a54a16a5866cce966547c51e203b9e09a25bc0"

CROS_GO_PACKAGES=(
	"cloud.google.com/go/compute/metadata"
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
RESTRICT="binchecks strip"

DEPEND="
	dev-go/net
"
RDEPEND="${DEPEND}"
