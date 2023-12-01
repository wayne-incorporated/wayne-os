# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_COMMIT="2084ab01763918df87c0ff514006dd8982ed174e"
CROS_WORKON_TREE="4a2b57aa7ac50122bb67ebfb2c780a0ca2b37420"
CROS_WORKON_PROJECT="chromiumos/platform/dev-util"
CROS_WORKON_LOCALNAME=("../platform/dev")
CROS_WORKON_SUBTREE="src/chromiumos/lroold"

inherit cros-go cros-workon

DESCRIPTION="Common golang library to support google.longrunning.operations server impls"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/dev-util/+/HEAD/src/chromiumos/lroold"

LICENSE="BSD-Google"
KEYWORDS="*"
IUSE=""

CROS_GO_WORKSPACE=(
	"${S}"
)

CROS_GO_PACKAGES=(
	"chromiumos/lroold/..."
)

CROS_GO_TEST=(
	"${CROS_GO_PACKAGES[@]}"
)

CROS_GO_VET=(
	"${CROS_GO_TEST[@]}"
)

DEPEND="
	dev-go/go-tools
	dev-go/grpc
	dev-go/mock
	dev-go/protobuf
	dev-go/protobuf-legacy-api
	chromeos-base/cros-config-api
"

RDEPEND="!<chromeos-base/test-server-0.0.1-r49"
