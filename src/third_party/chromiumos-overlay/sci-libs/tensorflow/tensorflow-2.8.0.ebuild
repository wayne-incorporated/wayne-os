# Copyright 1999-2020 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DISTUTILS_OPTIONAL=1
PYTHON_COMPAT=( python3_{6,7,8} )
DISTUTILS_USE_SETUPTOOLS=rdepend
MY_PV=${PV/_rc/-rc}
MY_P=${PN}-${MY_PV}

# shellcheck disable=SC2034 # Used by bazel.eclass.
BAZEL_BINARY="bazel-5"

# s/bazel/cros-bazel/ instead of bazel to fix downloading dependencies.
# s/prefix// because ChromeOS doesn't need it.
inherit cros-bazel distutils-r1 flag-o-matic toolchain-funcs

DESCRIPTION="Computation framework using data flow graphs for scalable machine learning"
HOMEPAGE="https://www.tensorflow.org/"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE="mpi +python xla xnnpack tflite_opencl_profiling ubsan nnapi_custom_ops"

# distfiles that bazel uses for the workspace, will be copied to basel-distdir
bazel_external_uris="
	https://github.com/bazelbuild/platforms/releases/download/0.0.2/platforms-0.0.2.tar.gz -> bazelbuild-platforms-0.0.2.tar.gz
	https://github.com/bazelbuild/apple_support/releases/download/0.10.0/apple_support.0.10.0.tar.gz -> bazelbuild-apple_support.0.10.0.tar.gz
	https://github.com/bazelbuild/bazel-toolchains/archive/dfc67056200b674accd08d8f9a21e328098c07e2.tar.gz -> bazel-toolchains-dfc67056200b674accd08d8f9a21e328098c07e2.tar.gz
	https://github.com/bazelbuild/bazel-skylib/releases/download/1.0.3/bazel-skylib-1.0.3.tar.gz -> bazel-skylib-1.0.3.tar.gz
	https://github.com/bazelbuild/rules_android/archive/v0.1.1.zip -> bazelbuild-rules_android-v0.1.1.zip
	https://github.com/bazelbuild/rules_apple/releases/download/0.31.3/rules_apple.0.31.3.tar.gz -> bazelbuild-rules_apple.0.31.3.tar.gz
	https://github.com/bazelbuild/rules_cc/archive/40548a2974f1aea06215272d9c2b47a14a24e556.tar.gz -> bazelbuild-rules_cc-40548a2974f1aea06215272d9c2b47a14a24e556.tar.gz
	https://github.com/bazelbuild/rules_closure/archive/308b05b2419edb5c8ee0471b67a40403df940149.tar.gz -> bazelbuild-rules_closure-308b05b2419edb5c8ee0471b67a40403df940149.tar.gz
	https://github.com/bazelbuild/rules_java/archive/7cf3cefd652008d0a64a419c34c13bdca6c8f178.zip -> bazelbuild-rules_java-7cf3cefd652008d0a64a419c34c13bdca6c8f178.zip
	https://github.com/bazelbuild/rules_swift/releases/download/0.21.0/rules_swift.0.21.0.tar.gz -> bazelbuild-rules_swift.0.21.0.tar.gz
	https://github.com/bazelbuild/rules_pkg/releases/download/0.2.5/rules_pkg-0.2.5.tar.gz -> bazelbuild-rules_pkg-0.2.5.tar.gz
	https://github.com/bazelbuild/rules_proto/archive/a0761ed101b939e19d83b2da5f59034bffc19c12.zip -> bazelbuild-rules_proto-a0761ed101b939e19d83b2da5f59034bffc19c12.zip
	https://github.com/google/farmhash/archive/0d859a811870d10f53a594927d0d0b97573ad06d.tar.gz -> farmhash-0d859a811870d10f53a594927d0d0b97573ad06d.tar.gz
	https://github.com/google/gemmlowp/archive/fda83bdc38b118cc6b56753bd540caa49e570745.zip -> gemmlowp-fda83bdc38b118cc6b56753bd540caa49e570745.zip
	https://github.com/google/ruy/archive/e6c1b8dc8a8b00ee74e7268aac8b18d7260ab1ce.zip -> ruy-e6c1b8dc8a8b00ee74e7268aac8b18d7260ab1ce.zip
	https://github.com/intel/ARM_NEON_2_x86_SSE/archive/1200fe90bb174a6224a525ee60148671a786a71f.tar.gz -> ARM_NEON_2_x86_SSE-1200fe90bb174a6224a525ee60148671a786a71f.tar.gz	https://github.com/googleapis/googleapis/archive/541b1ded4abadcc38e8178680b0677f65594ea6f.zip -> googleapis-541b1ded4abadcc38e8178680b0677f65594ea6f.zip
	https://github.com/petewarden/OouraFFT/archive/v1.0.tar.gz -> OouraFFT-v1.0.tar.gz
	https://github.com/pytorch/cpuinfo/archive/5916273f79a21551890fd3d56fc5375a78d1598d.zip -> pytorch-cpuinfo-5916273f79a21551890fd3d56fc5375a78d1598d.zip
	https://github.com/pytorch/cpuinfo/archive/d5e37adf1406cf899d7d9ec1d317c47506ccb970.tar.gz -> pytorch-cpuinfo-d5e37adf1406cf899d7d9ec1d317c47506ccb970.tar.gz
	https://github.com/Maratyszcza/FP16/archive/4dfe081cf6bcd15db339cf2680b9281b8451eeb3.zip -> FP16-4dfe081cf6bcd15db339cf2680b9281b8451eeb3.zip
	https://github.com/Maratyszcza/FXdiv/archive/63058eff77e11aa15bf531df5dd34395ec3017c8.zip -> FXdiv-63058eff77e11aa15bf531df5dd34395ec3017c8.zip
	https://github.com/Maratyszcza/pthreadpool/archive/b8374f80e42010941bda6c85b0e3f1a1bd77a1e0.zip -> pthreadpool-b8374f80e42010941bda6c85b0e3f1a1bd77a1e0.zip
	https://github.com/tensorflow/toolchains/archive/v1.3.2.tar.gz -> tensorflow_toolchains_v1.3.2.tar.gz
	https://github.com/tensorflow/runtime/archive/c3e082762b7664bbc7ffd2c39e86464928e27c0c.tar.gz -> tf_runtime-c3e082762b7664bbc7ffd2c39e86464928e27c0c.tar.gz
	https://gitlab.com/libeigen/eigen/-/archive/085c2fc5d53f391afcccce21c45e15f61c827ab1/eigen-085c2fc5d53f391afcccce21c45e15f61c827ab1.tar.gz -> eigen-085c2fc5d53f391afcccce21c45e15f61c827ab1.tar.gz
	https://github.com/KhronosGroup/OpenCL-Headers/archive/0d5f18c6e7196863bc1557a693f1509adfcee056.tar.gz -> OpenCL-Headers-0d5f18c6e7196863bc1557a693f1509adfcee056.tar.gz
	https://github.com/KhronosGroup/Vulkan-Headers/archive/ec2db85225ab410bc6829251bef6c578aaed5868.tar.gz -> Vulkan-Headers-ec2db85225ab410bc6829251bef6c578aaed5868.tar.gz
	https://github.com/abseil/abseil-cpp/archive/997aaf3a28308eba1b9156aa35ab7bca9688e9f6.tar.gz -> abseil-cpp-997aaf3a28308eba1b9156aa35ab7bca9688e9f6.tar.gz
	https://github.com/google/XNNPACK/archive/113092317754c7dea47bfb3cb49c4f59c3c1fa10.zip -> xnnpack-113092317754c7dea47bfb3cb49c4f59c3c1fa10.zip
	https://storage.googleapis.com/mirror.tensorflow.org/storage.cloud.google.com/download.tensorflow.org/tflite/hexagon_nn_headers_v1.20.0.3.tgz -> hexagon_nn_headers_v1.20.0.3.tgz
	https://github.com/google/nsync/archive/1.22.0.tar.gz -> nsync-1.22.0.tar.gz
	https://github.com/google/re2/archive/506cfa4bffd060c06ec338ce50ea3468daa6c814.tar.gz -> re2-506cfa4bffd060c06ec338ce50ea3468daa6c814.tar.gz
	https://github.com/google/highwayhash/archive/fd3d9af80465e4383162e4a7c5e2f406e82dd968.tar.gz -> highwayhash-fd3d9af80465e4383162e4a7c5e2f406e82dd968.tar.gz
	https://storage.googleapis.com/mirror.tensorflow.org/pilotfiber.dl.sourceforge.net/project/giflib/giflib-5.2.1.tar.gz -> giflib-5.2.1.tar.gz
	https://storage.googleapis.com/mirror.tensorflow.org/storage.cloud.google.com/download.tensorflow.org/tflite/hexagon_nn_headers_v1.20.0.9.tgz -> hexagon_nn_headers_v1.20.0.9.tgz
"

SRC_URI="
	https://github.com/${PN}/${PN}/archive/v${MY_PV}.tar.gz -> ${P}.tar.gz
	${bazel_external_uris}
	"

RDEPEND="
	x11-drivers/opengles-headers:=
	virtual/opengles:=
	>=dev-libs/flatbuffers-1.12.0:=
	dev-libs/libpcre
	dev-libs/openssl:0=
	>=dev-libs/protobuf-3.8.0:=
	>=dev-libs/re2-0.2019.06.01
	media-libs/libjpeg-turbo
	media-libs/libpng:0
	net-misc/curl
	sys-libs/zlib
	mpi? ( virtual/mpi )
	python? (
		${PYTHON_DEPS}
		dev-python/absl-py[${PYTHON_USEDEP}]
		>=dev-python/astor-0.7.1[${PYTHON_USEDEP}]
		dev-python/astunparse[${PYTHON_USEDEP}]
		>=dev-python/gast-0.3.3[${PYTHON_USEDEP}]
		dev-python/h5py[${PYTHON_USEDEP}]
		>=dev-python/numpy-1.19[${PYTHON_USEDEP}]
		>=dev-python/google-pasta-0.1.8[${PYTHON_USEDEP}]
		dev-python/opt-einsum[${PYTHON_USEDEP}]
		>=dev-python/protobuf-python-3.8.0[${PYTHON_USEDEP}]
		dev-python/pybind11[${PYTHON_USEDEP}]
		dev-python/six[${PYTHON_USEDEP}]
		dev-python/termcolor[${PYTHON_USEDEP}]
		>=dev-python/grpcio-1.28[${PYTHON_USEDEP}]
		>=dev-python/wrapt-1.11.1[${PYTHON_USEDEP}]
		>=net-libs/google-cloud-cpp-0.10.0
		>=sci-libs/keras-applications-1.0.8[${PYTHON_USEDEP}]
		>=sci-libs/keras-preprocessing-1.1.0[${PYTHON_USEDEP}]
		>=sci-visualization/tensorboard-2.3.0[${PYTHON_USEDEP}]
		dev-python/dill[${PYTHON_USEDEP}]
		dev-python/tblib[${PYTHON_USEDEP}]
	)"
DEPEND="${RDEPEND}
	python? (
		dev-python/mock
		dev-python/setuptools
	)"
PDEPEND="python? (
		>=sci-libs/tensorflow-estimator-2.3.0[${PYTHON_USEDEP}]
	)"
BDEPEND="
	app-arch/unzip
	>=dev-libs/protobuf-3.8.0
	dev-java/java-config
	dev-lang/swig
	=dev-util/bazel-5*
	${PYTHON_DEPS}
	python? (
		dev-python/cython
		dev-python/mock
		>=dev-python/grpcio-tools-1.28
	)"
REQUIRED_USE="${PYTHON_REQUIRED_USE}"

PATCHES=(
	"${FILESDIR}/tensorflow-2.8.0-0001-workspace.patch"
	"${FILESDIR}/tensorflow-2.8.0-0002-ashmem-create.patch"
	"${FILESDIR}/tensorflow-2.8.0-0003-nnapi-delegates.patch"
	"${FILESDIR}/tensorflow-2.8.0-0004-cpuinfo-arm-fix.patch"
	"${FILESDIR}/tensorflow-2.8.0-0005-gpu.patch"
	"${FILESDIR}/tensorflow-2.8.0-0006-nnapi-loading-errors.patch"
	"${FILESDIR}/tensorflow-2.8.0-0007-protobuff-cc-toolchain.patch"
	"${FILESDIR}/tensorflow-2.8.0-0008-remove-llvm-repo.patch"
	"${FILESDIR}/tensorflow-2.8.0-0009-resolve-overflow.patch"
	"${FILESDIR}/tensorflow-2.8.0-0011-Convolution2DTransposeBias.patch"
	"${FILESDIR}/tensorflow-2.8.0-0012-clvk.patch"
	"${FILESDIR}/tensorflow-2.8.0-0013-generate-pc-tflite.patch"
	"${FILESDIR}/tensorflow-2.8.0-0014-use-bazel-5.patch"
)

S="${WORKDIR}/${MY_P}"

DOCS=( AUTHORS CONTRIBUTING.md ISSUE_TEMPLATE.md README.md RELEASE.md )

# Echos the CPU string that TensorFlow uses to refer to the given architecture.
get-cpu-str() {
	local arch
	arch="$(tc-arch "${1}")"

	case "${arch}" in
	amd64) echo "k8";;
	arm) echo "arm";;
	arm64) echo "aarch64";;
	*) die "Unsupported architecture '${arch}'."
	esac
}

pkg_setup() {
	local num_pythons_enabled
	num_pythons_enabled=0
	count_impls(){
		num_pythons_enabled=$((num_pythons_enabled + 1))
	}
	use python && python_foreach_impl count_impls
}

src_unpack() {
	# Only unpack the main distfile
	unpack "${P}.tar.gz"
	bazel_load_distfiles "${bazel_external_uris}"
}

src_prepare() {
	if use nnapi_custom_ops; then
		PATCHES+=("${FILESDIR}/tensorflow-2.8.0-0010-Convolution2DTransposeBias-nnapi.patch")
	fi

	export JAVA_HOME=$(ROOT="${BROOT}" java-config --jdk-home)

	# Relax version checks in setup.py
	sed -i "/^    '/s/==/>=/g" tensorflow/tools/pip_package/setup.py || die

	bazel_setup_bazelrc
	bazel_setup_crosstool "$(get-cpu-str "${CBUILD}")" "$(get-cpu-str "${CHOST}")"

	default
	use python && python_copy_sources
}

src_configure() {
	export JAVA_HOME=$(ROOT="${BROOT}" java-config --jdk-home)

	do_configure() {
		export CC_OPT_FLAGS=" "
		export TF_ENABLE_XLA=$(usex xla 1 0)
		export TF_NEED_OPENCL_SYCL=0
		export TF_NEED_OPENCL=0
		export TF_NEED_COMPUTECPP=0
		export TF_NEED_ROCM=0
		export TF_NEED_MPI=$(usex mpi 1 0)
		export TF_SET_ANDROID_WORKSPACE=0

		if use python; then
			export PYTHON_BIN_PATH="${PYTHON}"
			export PYTHON_LIB_PATH="$(python_get_sitedir)"
		else
			python_setup
			export PYTHON_BIN_PATH="${PYTHON}"
			# PYTHON_LIB_PATH is inferred automatically
		fi

		export TF_NEED_CUDA=0
		export TF_DOWNLOAD_CLANG=0
		export TF_CUDA_CLANG=0
		export TF_NEED_TENSORRT=0

		local SYSLIBS=(
			absl_py
			astor_archive
			astunparse_archive
			boringssl
			com_github_googleapis_googleapis
			com_github_googlecloudplatform_google_cloud_cpp
			com_github_grpc_grpc
			com_google_protobuf
			curl
			cython
			dill_archive
			double_conversion
			enum34_archive
			flatbuffers
			functools32_archive
			gast_archive
			hwloc
			icu
			jsoncpp_git
			libjpeg_turbo
			lmdb
			nasm
			opt_einsum_archive
			org_sqlite
			pasta
			pcre
			png
			pybind11
			six_archive
			snappy
			swig
			tblib_archive
			termcolor_archive
			wrapt
			zlib
		)

		export TF_SYSTEM_LIBS="${SYSLIBS[*]}"
		export TF_IGNORE_MAX_BAZEL_VERSION=1

		# This is not autoconf
		./configure || die

		echo 'build --config=noaws --config=nohdfs' >> .bazelrc || die
		echo 'build --define tensorflow_mkldnn_contraction_kernel=0' >> .bazelrc || die

		# The ruy library is faster than the default libeigen on arm, but
		# MUCH slower on amd64. See b/178593695 for more discussion.
		case "${ARCH}" in
			arm | arm64) echo 'build --define=tflite_with_ruy=true' >> .bazelrc || die ;;
		esac
	}
	if use python; then
		python_foreach_impl run_in_build_dir do_configure
	else
		do_configure
	fi
}

src_compile() {
	export JAVA_HOME=$(ROOT="${BROOT}" java-config --jdk-home)

	if use python; then
		python_setup
		BUILD_DIR="${S}-${EPYTHON/./_}"
		cd "${BUILD_DIR}" || die
	fi

	local bazel_args=()
	bazel_args+=("tensorflow/lite:libtensorflowlite.so")
	bazel_args+=("//tensorflow/lite/kernels/internal:install_nnapi_extra_headers")
	if ! use ubsan; then
		bazel_args+=("//tensorflow/lite/tools/evaluation/tasks/inference_diff:run_eval")
		bazel_args+=("//tensorflow/lite/tools/evaluation/tasks/coco_object_detection:run_eval")
		bazel_args+=("//tensorflow/lite/tools/benchmark:benchmark_model")
	fi

	if use tflite_opencl_profiling; then
		bazel_args+=("//tensorflow/lite/delegates/gpu/cl/testing:performance_profiling")
	fi

	# fail early if any deps are missing
	ebazel build -k --nobuild "${bazel_args[@]}"

	# build if deps are present
	ebazel build --copt=-DTFLITE_SUPPORTS_GPU_DELEGATE=1 \
		--copt=-DEGL_NO_X11 --cxxopt=-std=c++17          \
		--define tflite_keep_symbols=true                \
		"${bazel_args[@]}"

	do_compile() {
		ebazel build //tensorflow/tools/pip_package:build_pip_package
	}
	BUILD_DIR="${S}"
	cd "${BUILD_DIR}" || die
	use python && python_foreach_impl run_in_build_dir do_compile
	ebazel shutdown

	einfo "Generate pkg-config file"
	chmod +x ${PN}/lite/generate-pc.sh
	${PN}/lite/generate-pc.sh --prefix="${EPREFIX}"/usr --libdir="$(get_libdir)" --version=${MY_PV} || die
}

src_install() {
	local i
	export JAVA_HOME=$(ROOT="${BROOT}" java-config --jdk-home)

	einfo "Installing TF lite headers"

	local HEADERS_TMP
	HEADERS_TMP="${WORKDIR}/headers_tmp"
	mkdir -p "${HEADERS_TMP}"

	# From tensorflow/lite/lib_package/create_ios_frameworks.sh
	find ${PN}/lite -name "*.h" \
		-not -path "${PN}/lite/tools/*" \
		-not -path "${PN}/lite/examples/*" \
		-not -path "${PN}/lite/gen/*" \
		-not -path "${PN}/lite/toco/*" \
		-not -path "${PN}/lite/java/*" |
	while read -r i; do
		mkdir -p "${HEADERS_TMP}/${i%/*}"
		cp "${i}" "${HEADERS_TMP}/${i%/*}"
	done

	insinto "/usr/include/${PN}"
	doins -r "${HEADERS_TMP}/tensorflow"

	einfo "Installing selected TF core headers"
	local selected=( lib/bfloat16/bfloat16.h platform/byte_order.h platform/macros.h platform/bfloat16.h )
	for i in "${selected[@]}"; do
		insinto "/usr/include/${PN}/${PN}/core/${i%/*}"
		doins "${PN}/core/${i}"
	done

	einfo "Installing NNAPI headers"
	insinto /usr/include/${PN}/nnapi/
	doins -r bazel-bin/tensorflow/lite/kernels/internal/include

	einfo "Installing ruy headers"
	insinto /usr/include/${PN}/ruy/
	doins -r "../tensorflow-${PV}-bazel-base/external/ruy/ruy"/*

	einfo "Installing fp16 headers"
	insinto /usr/include/${PN}/
	doins -r "../tensorflow-${PV}-bazel-base/external/FP16/include"/*

	einfo "Installing TF lite libraries"
	dolib.so bazel-bin/tensorflow/lite/lib${PN}lite.so

	if ! use ubsan; then
		into /usr/local
		einfo "Install benchmark_model tool to /usr/local/bin"
		dobin bazel-bin/tensorflow/lite/tools/benchmark/benchmark_model
		einfo "Install inference diff evaluation tool"
		newbin bazel-bin/tensorflow/lite/tools/evaluation/tasks/inference_diff/run_eval inference_diff_eval
		einfo "Install object detection evaluation tool"
		newbin bazel-bin/tensorflow/lite/tools/evaluation/tasks/coco_object_detection/run_eval object_detection_eval
	fi

	if use tflite_opencl_profiling; then
		into /usr/local/
		einfo "Install performance_profiling tool"
		dobin bazel-bin/tensorflow/lite/delegates/gpu/cl/testing/performance_profiling
	fi

	if use xnnpack; then
		einfo "Installing XNNPACK headers and libs"
		local bindir="../tensorflow-${PV}-bazel-base/execroot/org_tensorflow/bazel-out/$(get-cpu-str "${CHOST}")-opt/bin/external/"
		insinto /usr/include/${PN}/xnnpack/
		doins "../tensorflow-${PV}-bazel-base/external/XNNPACK/include/xnnpack.h"
		doins "../tensorflow-${PV}-bazel-base/external/pthreadpool/include/pthreadpool.h"
		dolib.a "${bindir}/clog/libclog.a"
		dolib.a "${bindir}/cpuinfo/libcpuinfo_impl.pic.a"
		dolib.a "${bindir}/pthreadpool/libpthreadpool.a"
		# The lib names vary wildly between amd64 and arm, so
		# easier just to scan for them rather than explicitly
		# listing them and switching on ${ARCH}.
		find "${bindir}/XNNPACK/" -name "*.a" |
		while read -r i; do
			dolib.a "${i}"
		done
	fi

	einfo "Installing pkg-config file"
	insinto /usr/"$(get_libdir)"/pkgconfig
	doins ${PN}lite.pc

	einstalldocs
}
