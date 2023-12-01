# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

PYTHON_COMPAT=( python3_{6..8} )
inherit distutils-r1

DESCRIPTION="Tools to interact with the kernel's HID subsystem"
HOMEPAGE="https://gitlab.freedesktop.org/libevdev/hid-tools"
SRC_URI="https://gitlab.freedesktop.org/libevdev/${PN}/-/archive/${PV}/${P}.tar.gz"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="*"
IUSE=""

RDEPEND="
	dev-python/click[${PYTHON_USEDEP}]
	dev-python/pyyaml[${PYTHON_USEDEP}]
	dev-python/parse[${PYTHON_USEDEP}]
"
DEPEND="${RDEPEND}"

PATCHES=(
	"${FILESDIR}/${P}-utf-8.patch"
)
