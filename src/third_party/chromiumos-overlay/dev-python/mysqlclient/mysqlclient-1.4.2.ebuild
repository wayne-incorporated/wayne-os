# Copyright 1999-2019 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

PYTHON_COMPAT=( python3_{6..8} )

inherit distutils-r1

DESCRIPTION="Fork of MySQL-python"
HOMEPAGE="https://pypi.org/project/mysqlclient/ https://github.com/PyMySQL/mysqlclient-python"
SRC_URI="mirror://pypi/${PN:0:1}/${PN}/${P}.post1.tar.gz -> ${P}-r2.tar.gz"
S="${WORKDIR}/${P}.post1"

SLOT="0"
LICENSE="GPL-2"
KEYWORDS="*"
IUSE="doc"

RDEPEND="
	!dev-python/mysql-python
	dev-db/mariadb-connector-c[mysqlcompat]"
DEPEND="${RDEPEND}
	dev-python/setuptools[${PYTHON_USEDEP}]
	doc? ( dev-python/sphinx[${PYTHON_USEDEP}] )"

DOCS=( README.md doc/{FAQ,MySQLdb}.rst )

python_compile_all() {
	use doc && sphinx-build -b html doc doc/_build/
}

python_install_all() {
	use doc && local HTML_DOCS=( doc/_build/. )
	distutils-r1_python_install_all
}
