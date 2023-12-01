# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

PYTHON_COMPAT=( python3_{6..9} )
DISTUTILS_USE_SETUPTOOLS=rdepend
inherit distutils-r1

DESCRIPTION="The LiteX framework provides a convenient and efficient infrastructure to
create FPGA Cores/SOCs, to create FPGA Cores/SoCs, to explore various digital design
architectures and create full FPGA based systems."
HOMEPAGE="https://github.com/enjoy-digital/litex"

SRC_URI="https://github.com/enjoy-digital/${PN}/archive/${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="BSD-2"
SLOT="0"
KEYWORDS="*"

RDEPEND="
	sci-electronics/migen[${PYTHON_USEDEP}]
	sci-electronics/pythondata-software-compiler_rt[${PYTHON_USEDEP}]
	dev-python/pyserial[${PYTHON_USEDEP}]
	dev-python/requests[${PYTHON_USEDEP}]
"

PATCHES=(
	"${FILESDIR}/${P}-add-riscv-cros-elf-to-known-riscv-toolchains.patch"
)

distutils_enable_tests unittest

src_test() {
	# ECC tests require 'litedram' which in turn requires 'litex' for testing.
	# Let's just skip them.
	mv test/{,skipped-}test_ecc.py || die
	# Similarly, the CPU tests require liteeth.
	mv test/{,skipped-}test_cpu.py || die

	distutils-r1_src_test
}
