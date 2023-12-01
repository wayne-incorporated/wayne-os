# Copyright 2016 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_COMMIT="f661990d0379f1030bdaa93c573ef4a50e9c6e66"
CROS_WORKON_TREE="f05776e43faaedc4b58f8b38e20bdf050a59b264"
CROS_WORKON_PROJECT="chromiumos/graphyte"
CROS_WORKON_LOCALNAME="platform/graphyte"
PYTHON_COMPAT=( python3_{6..9} )

inherit cros-workon distutils-r1

DESCRIPTION="Graphyte RF testing framework"
HOMEPAGE="https://sites.google.com/a/google.com/graphyte/home"

LICENSE="BSD-Google"
KEYWORDS="*"

RDEPEND=""
BDEPEND="dev-python/setuptools[${PYTHON_USEDEP}]"
