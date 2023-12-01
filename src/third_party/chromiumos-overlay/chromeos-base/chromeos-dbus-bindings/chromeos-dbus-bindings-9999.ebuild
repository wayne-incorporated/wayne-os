# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_SUBTREE="chromeos-dbus-bindings"

inherit cros-go cros-workon

DESCRIPTION="Utility for building Chrome D-Bus bindings from an XML description"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/chromeos-dbus-bindings"

LICENSE="BSD-Google"
KEYWORDS="~*"
IUSE=""

# Note: mainly for the packages using this tool.
# in order to rebuild the packages using this tool on updating this package,
# they should have
#
#   DEPEND="chromeos-base/chromeos-dbus-bindings:="
#
# in addition to
#
#   BDEPEND="chromeos-base/chromeos-dbus-bindings"
#
# Background: there are two reasons that just having BDEPEND does not work.
# Due to b/187792813, currently BDEPEND dependencies are ignored on building
# sysroot.
# Also, even if it is not ignored, in the current portage build system,
# BDEPEND does not support SLOT nor SUBSLOT.
# Thus, to workaround them, we're using SUBSLOT of DEPEND. To make it work,
# this package leaves SLOT to cros-workon's default "0/${PVR}", and packages
# using this tool need to have DEPEND dependency.

CROS_GO_BINARIES=(
	"go.chromium.org/chromiumos/dbusbindings/cmd/generator:/usr/bin/go-generate-chromeos-dbus-bindings"
)
CROS_GO_TEST=(
	"go.chromium.org/chromiumos/dbusbindings/..."
)
CROS_GO_VET=(
	"${CROS_GO_TEST[@]}"
)

RDEPEND="dev-go/cmp"
DEPEND="${RDEPEND}"

src_unpack() {
	cros-workon_src_unpack
	CROS_GO_WORKSPACE="${S}/chromeos-dbus-bindings/go"
}
