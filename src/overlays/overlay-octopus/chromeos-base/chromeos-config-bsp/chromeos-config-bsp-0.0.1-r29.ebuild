# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

# cros_workon applies only to ebuild and files directory. Use the
# canonical empty project.
CROS_WORKON_COMMIT="d2d95e8af89939f893b1443135497c1f5572aebc"
CROS_WORKON_TREE="776139a53bc86333de8672a51ed7879e75909ac9"
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

inherit cros-workon cros-unibuild

DESCRIPTION="ChromeOS model configuration"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/chromeos-config/README.md"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
RDEPEND="!chromeos-base/chromeos-config-bsp-octopus"
IUSE="kernel-4_14"

src_install() {
	insinto "${UNIBOARD_YAML_DIR}"
	doins "${FILESDIR}/model.yaml"

	insinto "${UNIBOARD_YAML_DIR}/include"
	if use kernel-4_14; then
		newins "${FILESDIR}/include/kernel-info_kernel_4_14.yaml" "kernel-info.yaml"
	else
		doins "${FILESDIR}/include/kernel-info.yaml"
	fi
}
