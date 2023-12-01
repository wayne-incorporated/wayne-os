# Copyright 1999-2021 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit bash-completion-r1 java-pkg-2 multiprocessing

DESCRIPTION="Fast and correct automated build system"
HOMEPAGE="https://bazel.build/"

SRC_URI="https://github.com/bazelbuild/bazel/releases/download/${PV}/${P}-dist.zip"

LICENSE="Apache-2.0"
SLOT="$(ver_cut 1)"
KEYWORDS="*"
IUSE="examples tools prefix static-libs"
REQUIRED_USE="prefix? ( static-libs )"
# strip corrupts the bazel binary
# test fails with network-sandbox: An error occurred during the fetch of repository 'io_bazel_skydoc' (bug 690794)
RESTRICT="strip test"
RDEPEND=">=virtual/jdk-11:*"
DEPEND="${RDEPEND}
	app-arch/unzip
"
# bazel-4.2.2-r1 installed itself as /usr/bin/bazel. Since this ebuild also does
# that, we need a soft blocker.
RDEPEND+="
	!<=dev-util/bazel-4.2.2-r1
"

S="${WORKDIR}"

bazel-get-flags() {
	local i fs=()
	for i in ${CFLAGS}; do
		fs+=( "--copt=${i}" "--host_copt=${i}" )
	done
	for i in ${CXXFLAGS}; do
		fs+=( "--cxxopt=${i}" "--host_cxxopt=${i}" )
	done
	for i in ${CPPFLAGS}; do
		fs+=( "--copt=${i}" "--host_copt=${i}" )
		fs+=( "--cxxopt=${i}" "--host_cxxopt=${i}" )
	done
	for i in ${LDFLAGS}; do
		fs+=( "--linkopt=${i}" "--host_linkopt=${i}" )
	done
	echo "${fs[*]}"
}

pkg_setup() {
	echo ${PATH} | grep -q ccache && \
		ewarn "${PN} usually fails to compile with ccache, you have been warned"
	java-pkg-2_pkg_setup
}

src_prepare() {
	default

	# F: fopen_wr
	# S: deny
	# P: /proc/self/setgroups
	# A: /proc/self/setgroups
	# R: /proc/24939/setgroups
	# C: /usr/lib/systemd/systemd
	addpredict /proc
}

src_compile() {
	local BAZEL_ARGS=(
		"--jobs=$(makeopts_jobs)"
		# These settings tell Bazel to use the locally available JDK rather
		# than try to download a remote bundled version.
		"--java_runtime_version=$(java-pkg_get-vm-version)"
		"--tool_java_runtime_version=$(java-pkg_get-vm-version)"
		"--extra_toolchains=@local_jdk//:all"
		# C++ module maps are enabled in the default clang toolchain but cause
		# the build of GRPC to fail due to the implicit inclusion of those
		# .cppmap files not being declared to Bazel.
		"--features=-module_maps"
	)
	export EXTRA_BAZEL_ARGS="${BAZEL_ARGS[*]} $(bazel-get-flags)"
	if use static-libs; then
		export BAZEL_LINKOPTS=-static-libs:-static-libgcc BAZEL_LINKLIBS=-l%:libstdc++.a:-lm
	fi
	VERBOSE=yes ./compile.sh || die

	echo "BAZEL=\"bazel-$(ver_cut 1)\"" > "${T}/bazel-$(ver_cut 1)-header.bash"

	./scripts/generate_bash_completion.sh \
		--bazel=output/bazel \
		--output=bazel-complete.bash \
		--prepend="${T}/bazel-$(ver_cut 1)-header.bash" \
		--prepend=scripts/bazel-complete-header.bash \
		--prepend=scripts/bazel-complete-template.bash
}

src_test() {
	output/bazel test \
		--verbose_failures \
		--spawn_strategy=standalone \
		--genrule_strategy=standalone \
		--verbose_test_summary \
		examples/cpp:hello-success_test || die
	output/bazel shutdown
}

src_install() {
	local ver="$(ver_cut 1)"
	newbin output/bazel bazel-"${ver}"
	newbashcomp bazel-complete.bash "${PN}-${ver}"
}
