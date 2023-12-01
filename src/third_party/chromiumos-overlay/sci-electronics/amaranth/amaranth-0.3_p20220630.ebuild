# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

PYTHON_COMPAT=( python3_{6..9} )
DISTUTILS_USE_SETUPTOOLS=rdepend
inherit distutils-r1

DESCRIPTION="Hardware definition language for building complex digital hardware"
HOMEPAGE="https://github.com/amaranth-lang/amaranth"

GIT_REV="db49294cf722e9463666bd06f81a86f930b8707c"
SRC_URI="https://github.com/amaranth-lang/${PN}/archive/${GIT_REV}.tar.gz -> ${PN}-${GIT_REV}.tar.gz"

# Provide the version since `setuptools_scm` breaks emerging snapshot ebuilds.
# `python3 -m setuptools_scm` can be used inside a repository to print version
# corresponding to the checked-out commit.
export SETUPTOOLS_SCM_PRETEND_VERSION="0.4.dev21+gdb49294"

LICENSE="BSD-2"
SLOT="0"
KEYWORDS="*"

# Versioned setup.py deps: "pyvcd>=0.2.2,<0.4", "Jinja2~=3.0"
RDEPEND="
	$(python_gen_cond_dep '
		dev-python/importlib_metadata[${PYTHON_USEDEP}]
	' python3_{6..7})
	>=dev-python/pyvcd-0.2.2[${PYTHON_USEDEP}] <dev-python/pyvcd-0.4
	>=sci-electronics/yosys-0.10
	!sci-electronics/nmigen
"
BDEPEND="
	dev-python/setuptools_scm[${PYTHON_USEDEP}]
"

S="${WORKDIR}/${PN}-${GIT_REV}"

PATCHES=(
	"${FILESDIR}/${P}-fix-setup.patch"
)

src_test() {
	if ! has_version sci-electronics/symbiyosys; then
		ewarn "SymbiYosys not found; skipping tests that require it."
		eapply "${FILESDIR}/${P}-skip-tests-using-symbiyosys.patch"
	fi

	distutils-r1_src_test
}

# Apart from declaring `python_test`, `distutils_enable_tests` also manages test
# dependencies and flags. Let's keep it even though the function is overridden.
distutils_enable_tests unittest
python_test() {
	distutils_install_for_testing

	"${EPYTHON}" -m unittest discover -v || die "Tests fail with ${EPYTHON}"
}
