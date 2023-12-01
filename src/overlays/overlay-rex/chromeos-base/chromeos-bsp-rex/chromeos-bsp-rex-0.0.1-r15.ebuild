# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="d2d95e8af89939f893b1443135497c1f5572aebc"
CROS_WORKON_TREE="776139a53bc86333de8672a51ed7879e75909ac9"
inherit appid cros-unibuild cros-workon

# This ebuild only cares about its own FILESDIR and ebuild file, so it tracks
# the canonical empty project.
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* amd64 x86"
IUSE="vpu_driver nnapi vendor-nnhal nnapi_custom_ops modemfwd rex-arc-t"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
	chromeos-base/touch_updater
	chromeos-base/sof-binary:=
	chromeos-base/sof-topology:=
	vpu_driver? (
		chromeos-base/intel-vpu-umd:=
	)
	nnapi? (
		vendor-nnhal? (
			chromeos-base/intel-nnhal:=
		)
	)
	nnapi_custom_ops? (
		sci-libs/tensorflow:=
	)
	modemfwd? (
		chromeos-base/modemfwd-helpers
	)
"
DEPEND="
	${RDEPEND}
"

src_install() {
	if use rex-arc-t; then
		doappid "{2A32B309-108B-421D-8DFD-CBC48790E12B}" "CHROMEBOOK"
	else
		doappid "{2B8D1068-48CF-4256-A2D5-335849F11718}" "REFERENCE"
	fi

	# Install audio config files
	unibuild_install_files audio-files
}
