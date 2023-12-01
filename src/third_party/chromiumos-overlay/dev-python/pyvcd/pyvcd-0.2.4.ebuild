# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

PYTHON_COMPAT=( python3_{6..9} )
inherit distutils-r1

DESCRIPTION="Python package for writing Value Change Dump (VCD) files."
HOMEPAGE="https://github.com/westerndigitalcorporation/pyvcd"

SRC_URI="https://github.com/westerndigitalcorporation/${PN}/archive/${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"

BDEPEND="
	dev-python/setuptools_scm[${PYTHON_USEDEP}]
"

# Provide the version since `setuptools_scm` breaks emerging snapshot ebuilds.
export SETUPTOOLS_SCM_PRETEND_VERSION="${PV}"

distutils_enable_tests pytest
