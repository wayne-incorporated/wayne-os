# Copyright 1999-2022 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

FORTRAN_NEEDED="test"
inherit cmake cuda fortran-2

DESCRIPTION="C++ template library for linear algebra"
HOMEPAGE="https://eigen.tuxfamily.org/index.php?title=Main_Page"

# Commit ID must be kept in sync with repo manifest.
EIGEN_GIT_COMMIT=c18f94e3b017104284cd541e553472e62e85e526

# The file uploaded to the local mirror has the "eigen-" prefix.
SRC_URI="https://chromium.googlesource.com/external/gitlab.com/libeigen/eigen/+archive/${EIGEN_GIT_COMMIT}.tar.gz -> eigen-${EIGEN_GIT_COMMIT}.tar.gz"

# Use custom build directory to match the folder layout of the tar.gz archive.
S="${WORKDIR}"

LICENSE="MPL-2.0"
SLOT="3"
KEYWORDS="*"
IUSE="cpu_flags_arm_neon cpu_flags_ppc_altivec cpu_flags_ppc_vsx cuda debug doc openmp test" #zvector

# Tests failing again because of compiler issues
RESTRICT="!test? ( test ) test"

BDEPEND="
	doc? (
		app-doc/doxygen[dot]
		dev-texlive/texlive-bibtexextra
		dev-texlive/texlive-fontsextra
		dev-texlive/texlive-fontutils
		dev-texlive/texlive-latex
		dev-texlive/texlive-latexextra
	)
	test? ( virtual/pkgconfig )
"
DEPEND="
	cuda? ( dev-util/nvidia-cuda-toolkit )
	test? (
		dev-libs/gmp:0
		dev-libs/mpfr:0
		media-libs/freeglut
		media-libs/glew
		sci-libs/adolc[sparse]
		sci-libs/cholmod
		sci-libs/fftw:3.0
		sci-libs/pastix
		sci-libs/scotch
		sci-libs/spqr
		sci-libs/superlu
		sci-libs/umfpack
		virtual/opengl
	)
"
# Missing:
# METIS-5
# GOOGLEHASH

src_prepare() {
	cmake_src_prepare

	cmake_comment_add_subdirectory demos

	if ! use test; then
		sed -e "/add_subdirectory(test/s/^/#DONOTCOMPILE /g" \
			-e "/add_subdirectory(blas/s/^/#DONOTCOMPILE /g" \
			-e "/add_subdirectory(lapack/s/^/#DONOTCOMPILE /g" \
			-i CMakeLists.txt || die
	fi

	use cuda && cuda_src_prepare
}

src_configure() {
	use test && mycmakeargs+=(
		# the OpenGL testsuite is extremely brittle, bug #712808
		-DEIGEN_TEST_NO_OPENGL=ON
		# the cholmod tests are broken and always fail
		-DCMAKE_DISABLE_FIND_PACKAGE_Cholmod=ON
		-DEIGEN_TEST_CXX11=ON
		-DEIGEN_TEST_NOQT=ON
		-DEIGEN_TEST_ALTIVEC=$(usex cpu_flags_ppc_altivec)
		-DEIGEN_TEST_CUDA=$(usex cuda)
		-DEIGEN_TEST_OPENMP=$(usex openmp)
		-DEIGEN_TEST_NEON64=$(usex cpu_flags_arm_neon)
		-DEIGEN_TEST_VSX=$(usex cpu_flags_ppc_vsx)
	)
	cmake_src_configure
}

src_compile() {
	cmake_src_compile
	if use doc; then
		cmake_src_compile doc
		HTML_DOCS=( "${BUILD_DIR}"/doc/html/. )
	fi
	if use test; then
		cmake_src_compile blas
		cmake_src_compile buildtests

		# tests generate random data, which
		# obviously fails for some seeds
		export EIGEN_SEED=712808
	fi
}
