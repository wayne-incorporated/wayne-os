# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI="7"

# No git repo for this so use empty-project.
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

inherit cros-workon tmpfiles

DESCRIPTION="Ebuild to support running Prometheus Node Exporter on ChromeOS."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="~*"
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
