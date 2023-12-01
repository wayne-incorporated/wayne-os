# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Virtual package installing files define the capability of DUTs. We
run or skip test cases base on those capabilities. See README.md for details."
LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"

RDEPEND="chromeos-base/autotest-capability-default"
