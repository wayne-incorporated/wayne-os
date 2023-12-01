# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the BSD license.

EAPI=7
CROS_WORKON_COMMIT="d26c7285f00ef6dc54b706cc18adc2ea36aa140d"
CROS_WORKON_TREE="70d4e046d49094bcb0342510a5885eed50f14a00"
CROS_WORKON_PROJECT="chromiumos/platform/touch_updater"
CROS_WORKON_LOCALNAME="platform/touch_updater"
CROS_WORKON_SUBTREE="common"
CROS_WORKON_OUTOFTREE_BUILD=1

inherit cros-workon

DESCRIPTION="Common shell libraries for touch firmware updater wrapper scripts"
HOMEPAGE="https://www.chromium.org/chromium-os"

LICENSE="BSD-Google"
SLOT="0/0"
KEYWORDS="*"

RDEPEND="
	chromeos-base/chromeos-config-tools
	chromeos-base/vboot_reference
	!<chromeos-base/touch_updater-0.0.1-r167
"

src_install() {
	insinto "/opt/google/touch/scripts"
	doins common/scripts/*.sh
}
