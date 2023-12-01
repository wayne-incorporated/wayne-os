# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"
CROS_WORKON_PROJECT="chromiumos/platform/crostestutils"
CROS_WORKON_LOCALNAME="../platform/crostestutils"

CROS_GO_WORKSPACE="${S}/go"
CROS_GO_BINARIES=(
	"go.chromium.org/fw-engprod-tools/cmd/dut_info:/usr/bin/fw_dut_info"
	"go.chromium.org/fw-engprod-tools/cmd/e2e_coverage_summarizer:/usr/bin/fw_e2e_coverage_summarizer"
	"go.chromium.org/fw-engprod-tools/cmd/lab_triage_helper:/usr/bin/fw_lab_triage_helper"
)

inherit cros-go cros-workon

DESCRIPTION="Tooling related to firmware release testing."
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/crostestutils/+/HEAD/go/src/firmware/"

LICENSE="BSD-Google"
SLOT="0/0"
KEYWORDS="~*"
IUSE=""

DEPEND="
	dev-go/crypto:=
	dev-go/gapi:=
	dev-go/exp:=
"
RDEPEND=""
