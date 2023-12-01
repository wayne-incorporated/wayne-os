# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_PROJECT="chromiumos/platform/tast"
CROS_WORKON_LOCALNAME="platform/tast"

CROS_GO_BINARIES=(
	"go.chromium.org/tast/core/cmd/remote_test_runner"
	"go.chromium.org/tast/core/cmd/tast"
)

CROS_GO_VERSION="${PF}"

CROS_GO_TEST=(
	"go.chromium.org/tast/core/cmd/remote_test_runner/..."
	"go.chromium.org/tast/core/cmd/tast/..."
	# Also test common code.
	"go.chromium.org/tast/..."
)
CROS_GO_VET=(
	"${CROS_GO_TEST[@]}"
)

inherit cros-go cros-workon

DESCRIPTION="Host executables for running integration tests"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/tast/"

LICENSE="BSD-Google"
SLOT="0/0"
KEYWORDS="~*"
IUSE="coverage"

# Build-time dependencies should be added to tast-build-deps, not here.
DEPEND="
	chromeos-base/tast-build-deps:=
	chromeos-base/cros-config-api
"

RDEPEND="
	app-arch/tar
	app-arch/xz-utils
	chromeos-base/google-breakpad
	chromeos-base/tast-build-deps
	chromeos-base/tast-vars
	net-misc/gsutil
	!chromeos-base/tast-common
"

src_prepare() {
	# Disable cgo and PIE on building Tast binaries. See:
	# https://crbug.com/976196
	# https://github.com/golang/go/issues/30986#issuecomment-475626018
	export CGO_ENABLED=0
	export GOPIE=0

	default
}

src_test() {
	# mapfile reads output from go_list into array
	mapfile -t pkglist < <(go_list "${CROS_GO_TEST[@]}")
	local coverage_path="${T}/coverage_logs"
	if use coverage; then
		mkdir -p "${coverage_path}"
		local pkg_cover="${PN}_cover.out"
		local pkg_report="${PN}.html"
		GO111MODULE=${GO111MODULE:-off} GOPATH="$(cros-go_gopath)" $(tc-getBUILD_GO) test -covermode=atomic \
		-short -coverprofile="${coverage_path}/${pkg_cover}" "${pkglist[@]}" || die
		GO111MODULE=${GO111MODULE:-off} GOPATH="$(cros-go_gopath)" $(tc-getBUILD_GO) tool cover \
			-html="${coverage_path}/${pkg_cover}" -o "${coverage_path}/${pkg_report}" || die
	else
		GO111MODULE=${GO111MODULE:-off} GOPATH="$(cros-go_gopath)" $(tc-getBUILD_GO) test -short "${pkglist[@]}" || die
	fi
}
