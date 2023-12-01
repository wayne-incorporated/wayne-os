# Copyright 2023 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_GO_SOURCE=(
	"github.com/jtolio/gls:github.com/jtolds/gls v4.20.0"
	"github.com/smartystreets/assertions v1.13.0"
	"github.com/smartystreets/goconvey v1.7.2"
)

CROS_GO_PACKAGES=(
	"github.com/jtolds/gls"
	"github.com/smartystreets/assertions"
	"github.com/smartystreets/assertions/internal/go-diff/diffmatchpatch"
	"github.com/smartystreets/assertions/internal/go-render/render"
	"github.com/smartystreets/assertions/internal/oglematchers"
	"github.com/smartystreets/goconvey/convey"
	"github.com/smartystreets/goconvey/convey/gotest"
	"github.com/smartystreets/goconvey/convey/reporting"
)

CROS_GO_WORKSPACE=(
	"${S}"
)

CROS_GO_BINARIES=(
	"chromiumos/test/provision/v2/android-provision"
)

CROS_GO_TEST=(
	"chromiumos/test/provision/v2/android-provision/..."
)

CROS_GO_VET=(
	"${CROS_GO_TEST[@]}"
)

CROS_WORKON_PROJECT="chromiumos/platform/dev-util"
CROS_WORKON_LOCALNAME=("../platform/dev")
CROS_WORKON_SUBTREE="src/chromiumos/test/provision src/chromiumos/test/util"

inherit cros-go cros-workon

DESCRIPTION="Android provision server implementation for installing packages on a test device"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/dev-util/+/HEAD/src/chromiumos/test/provision/v2/android-provision"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-Google"
KEYWORDS="~*"
IUSE=""

DEPEND="
	dev-util/cros-test
	dev-util/lro-server
	dev-util/lroold-server
	dev-go/gcp-storage
	dev-go/genproto
	dev-go/luci-go-cipd
	dev-go/mock
	dev-go/opencensus
	dev-go/protobuf
	dev-go/protobuf-legacy-api
	chromeos-base/cros-config-api
"
RDEPEND="${DEPEND}"

src_prepare() {
	# CGO_ENABLED=0 will make the executable statically linked.
	export CGO_ENABLED=0
	# Unpack the Go source tarballs.
	cros-go_src_unpack

	default
}
