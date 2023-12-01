# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_PROJECT="chromiumos/platform/graphics"
CROS_WORKON_LOCALNAME="platform/graphics"

INSTALL_DIR="/usr/local/graphics"

CROS_GO_BINARIES=(
	# Add more apps here.
	"go.chromium.org/chromiumos/graphics-utils-go/hardware_probe/cmd/hardware_probe:${INSTALL_DIR}/hardware_probe"
	"go.chromium.org/chromiumos/graphics-utils-go/platform_decoding/cmd/ffmpeg_md5sum:${INSTALL_DIR}/ffmpeg_md5sum"
	"go.chromium.org/chromiumos/graphics-utils-go/platform_decoding/cmd/validate:${INSTALL_DIR}/validate"
	"go.chromium.org/chromiumos/graphics-utils-go/sanity/cmd/pass:${INSTALL_DIR}/pass"
	"go.chromium.org/chromiumos/graphics-utils-go/trace_profiling/cmd/analyze:${INSTALL_DIR}/analyze"
	"go.chromium.org/chromiumos/graphics-utils-go/trace_profiling/cmd/gen_db_result:${INSTALL_DIR}/get_device_info"
	"go.chromium.org/chromiumos/graphics-utils-go/trace_profiling/cmd/harvest:${INSTALL_DIR}/harvest"
	"go.chromium.org/chromiumos/graphics-utils-go/trace_profiling/cmd/merge:${INSTALL_DIR}/merge"
	"go.chromium.org/chromiumos/graphics-utils-go/trace_profiling/cmd/profile:${INSTALL_DIR}/profile"
	"go.chromium.org/chromiumos/graphics-utils-go/trace_replay/cmd/trace_replay:${INSTALL_DIR}/trace_replay"
)

CROS_GO_TEST=(
	"go.chromium.org/chromiumos/graphics-utils-go/hardware_probe/cmd/hardware_probe"
	"go.chromium.org/chromiumos/graphics-utils-go/platform_decoding/cmd/validate"
	"go.chromium.org/chromiumos/graphics-utils-go/sanity/cmd/pass"
	"go.chromium.org/chromiumos/graphics-utils-go/trace_profiling/cmd/analyze"
	"go.chromium.org/chromiumos/graphics-utils-go/trace_profiling/cmd/gen_db_result"
	"go.chromium.org/chromiumos/graphics-utils-go/trace_profiling/cmd/merge"
	"go.chromium.org/chromiumos/graphics-utils-go/trace_profiling/cmd/profile"
	"go.chromium.org/chromiumos/graphics-utils-go/trace_replay/cmd/trace_replay"
)

CROS_GO_VET=(
	"${CROS_GO_TEST[@]}"
)

inherit cros-go cros-workon
SRC_URI="$(cros-go_src_uri)"

DESCRIPTION="Portable graphics utils written in go"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/graphics/"

LICENSE="BSD-Google"
SLOT="0/0"
KEYWORDS="~*"
IUSE=""

DEPEND="
	chromeos-base/cros-config-api
	dev-go/crypto
	dev-go/errors
	dev-go/fogleman-gg
	dev-go/go-fonts-liberation
	dev-go/go-image
	dev-go/go-latex
	dev-go/go-pdf
	dev-go/golang-freetype
	dev-go/gonum-plot
	dev-go/protobuf
	dev-go/protobuf-legacy-api
	dev-go/readline
	dev-go/svgo
	dev-go/uuid
"

RDEPEND="${DEPEND}"

src_prepare() {
	# Disable cgo and PIE on building Tast binaries. See:
	# https://crbug.com/976196
	# https://github.com/golang/go/issues/30986#issuecomment-475626018
	export CGO_ENABLED=0
	export GOPIE=0

	default
}
