# Copyright 2023 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DISTUTILS_USE_SETUPTOOLS=rdepend
PYTHON_COMPAT=( python3_{6..9} pypy3 )
inherit distutils-r1

DESCRIPTION="OpenTelemetry Python API"
HOMEPAGE="https://github.com/open-telemetry/opentelemetry-python"
SRC_URI="mirror://pypi/${PN:0:1}/${PN}/opentelemetry-semantic-conventions-0.33b0.tar.gz"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"

S="${WORKDIR}/opentelemetry-semantic-conventions-0.33b0"

RDEPEND="
	dev-python/setuptools[${PYTHON_USEDEP}]
	dev-python/deprecated[${PYTHON_USEDEP}]"
