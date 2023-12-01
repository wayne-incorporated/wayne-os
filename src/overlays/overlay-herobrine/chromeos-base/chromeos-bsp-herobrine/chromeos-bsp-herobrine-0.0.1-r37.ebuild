# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

# This ebuild only cares about its own FILESDIR and ebuild file, so it tracks
# the canonical empty project.
CROS_WORKON_COMMIT="d2d95e8af89939f893b1443135497c1f5572aebc"
CROS_WORKON_TREE="776139a53bc86333de8672a51ed7879e75909ac9"
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

inherit appid cros-unibuild cros-workon

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* arm64 arm"
IUSE="herobrine-angle herobrine-kernelnext herobrine-userdebug"

RDEPEND="
	chromeos-base/chromeos-bsp-baseboard-herobrine
"
DEPEND="
	${RDEPEND}
	chromeos-base/chromeos-config:=
"

src_install() {
	if use herobrine-angle; then
		doappid "{DB304C1C-FDE6-4487-93BC-75D4C8F075FA}" "CHROMEBOOK"
	elif use herobrine-kernelnext; then
		doappid "{67EAF43A-C8C0-4190-9066-C7A628C9FF19}" "CHROMEBOOK"
	elif use herobrine-userdebug; then
		doappid "{07687309-6925-4A46-CA80-671B57B30166}" "CHROMEBOOK"
	else
		doappid "{C5ED9176-A346-217C-DE59-1896036F7C8A}" "CHROMEBOOK"
	fi

	# Install audio config files
	unibuild_install_files audio-files
}
