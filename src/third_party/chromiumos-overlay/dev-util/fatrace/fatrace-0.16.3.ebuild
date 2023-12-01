# Copyright 1999-2018 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit linux-info

DESCRIPTION="report file access events from all running processes"
HOMEPAGE="https://github.com/martinpitt/fatrace"
SRC_URI="https://github.com/martinpitt/fatrace/archive/refs/tags/${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="GPL-3"
SLOT="0"
KEYWORDS="*"

RDEPEND=""
DEPEND="${RDEPEND}"

CONFIG_CHECK="~FANOTIFY"

src_install() {
	dosbin fatrace
	doman fatrace.8
	dodoc NEWS
}
