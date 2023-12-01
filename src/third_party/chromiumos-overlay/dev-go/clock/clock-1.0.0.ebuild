# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/cloudfoundry/clock:code.cloudfoundry.org/clock v${PV}"

CROS_GO_PACKAGES=(
	"code.cloudfoundry.org/clock/..."
)

inherit cros-go

DESCRIPTION="Time provider & rich fake for Go"
HOMEPAGE="https://github.com/cloudfoundry/clock"
SRC_URI="$(cros-go_src_uri)"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""

# Disable unit tests to avoid pulling a lot of test-only deps.
RESTRICT="binchecks strip test"
