# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI="7"

# No git repo for this so use empty-project.
CROS_WORKON_COMMIT="d2d95e8af89939f893b1443135497c1f5572aebc"
CROS_WORKON_TREE="776139a53bc86333de8672a51ed7879e75909ac9"
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

inherit cros-workon tmpfiles

DESCRIPTION="Ebuild to support running Prometheus Node Exporter on ChromeOS."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""

RDEPEND=""
DEPEND=""

src_install() {
	dotmpfiles "${FILESDIR}"/tmpfiles.d/*.conf

	insinto /etc/init
	doins "${FILESDIR}"/init/*.conf

	insinto /etc/rsyslog.d
	doins "${FILESDIR}"/rsyslog.d/*.conf
}
