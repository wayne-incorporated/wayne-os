# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

CROS_WORKON_COMMIT="c4e849d3bb52211b2327d556852bf18a036f58d4"
CROS_WORKON_TREE="1e8e2bf920c9afdb2bed006b406e6db164c0ae91"
CROS_WORKON_PROJECT="chromiumos/third_party/kernel"
# TODO: Fix it when the official CrOS kernel branch is created.
CROS_WORKON_LOCALNAME="kernel/v6.1"
CROS_WORKON_MANUAL_UPREV="1"

inherit cros-workon cros-kernel2

HOMEPAGE="https://www.chromium.org/chromium-os/chromiumos-design-docs/chromium-os-kernel"
# TODO: Fix it when the official CrOS kernel branch is created.
DESCRIPTION="Chrome OS Linux Kernel 6.1 with Geralt private patches."
KEYWORDS="*"

# This is for MT8188G only.
# It had been developing with chromeos-kernel-upstream before the 6.1 kernel
# was ready in the early stage.
# This ensures that the old kernel target will be rejected and cleared when
# building the new 6.1 kernel.
# CQ should be fine without this, but just in case so that Portage cleans up
# the dependency properly in developers' local incremental builds.
RDEPEND="
	!sys-kernel/chromeos-kernel-upstream
"
