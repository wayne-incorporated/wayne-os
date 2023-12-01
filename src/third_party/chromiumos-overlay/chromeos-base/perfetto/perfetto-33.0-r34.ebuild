# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="33ef47cfb7c59eb02c1b5fbddd349ad3f6e31639"
CROS_WORKON_TREE="0e94979f394c051fcd8e2d516fc49dcde9a7cb32"
inherit cros-constants

# This ebuild is upreved via PuPR, so disable the normal uprev process for
# cros-workon ebuilds.
CROS_WORKON_MANUAL_UPREV=1
CROS_WORKON_LOCALNAME="aosp/external/perfetto"
CROS_WORKON_PROJECT="platform/external/perfetto"
CROS_WORKON_REPO="${CROS_GIT_AOSP_URL}"
CROS_WORKON_EGIT_BRANCH="master"

inherit cros-workon ninja-utils tmpfiles toolchain-funcs user

DESCRIPTION="An open-source project for performance instrumentation and tracing."
HOMEPAGE="https://perfetto.dev/"

KEYWORDS="*"
IUSE="cros_host"
LICENSE="Apache-2.0"
SLOT="0"

# protobuf dep is for using protoc at build-time to generate perfetto's headers.
# It is included in DEPEND as a hack to trigger a rebuild when protoc is
# upgraded.
BDEPEND="
	dev-util/gn
	dev-util/ninja
	dev-libs/protobuf
"
# sqlite is used in building trace_processor_shell
DEPEND="
	dev-db/sqlite
	dev-libs/protobuf:=
"

BUILD_OUTPUT="${WORKDIR}/out_cros/"

src_configure() {
	tc-export CC CXX AR STRIP BUILD_CC BUILD_CXX BUILD_AR BUILD_STRIP
	local target_cpu="${ARCH}"
	# Make the "amd64" -> "x64" conversion for the GN arg |target_cpu|.
	if [[ "${target_cpu}" == "amd64" ]]; then
		target_cpu="x64"
	fi

	# Don't turn on is_debug in building the system tracing service daemon.
	# Running a debug build traced with a release build producer will likely
	# cause crashes.
	local is_debug="false"

	local warn_flags=(
		"-Wno-suggest-destructor-override"
		"-Wno-suggest-override"
		"-Wno-reserved-identifier"
	)
	append-cflags "${warn_flags[*]}"
	append-cxxflags "${warn_flags[*]}"
	# Specify the linker to be used, this will be invoked by
	# perfetto build as link argument "-fuse-ld=<>" so it needs to be
	# the linker name bfd/gold/lld etc. that clang/gcc understand.
	local linker_name="bfd"
	tc-ld-is-gold && linker_name="gold"
	tc-ld-is-lld && linker_name="lld"

	# Cross-compilation args.
	GN_ARGS="
is_system_compiler=true
ar=\"${BUILD_AR}\"
cc=\"${BUILD_CC}\"
cxx=\"${BUILD_CXX}\"
strip=\"${BUILD_STRIP}\"
linker=\"${linker_name}\"
target_ar=\"${AR}\"
target_cc=\"${CC}\"
target_cxx=\"${CXX}\"
target_linker=\"${linker_name}\"
target_strip=\"${STRIP}\"
target_cpu=\"${target_cpu}\"
target_triplet=\"${CHOST}\"
extra_target_cflags=\"${CFLAGS}\"
extra_target_cxxflags=\"${CXXFLAGS}\"
extra_target_ldflags=\"${LDFLAGS}\"
"

	# Extra args to make the targets build.
	GN_ARGS+="
is_debug=${is_debug}
enable_perfetto_stderr_crash_dump=false
enable_perfetto_trace_processor_json=false
monolithic_binaries=true
use_custom_libcxx=false
is_hermetic_clang=false
enable_perfetto_zlib=false
skip_buildtools_check=true
perfetto_use_system_protobuf=true
enable_perfetto_x64_cpu_opt=false
"
	# Extra args for trace_processor_shell.
	GN_ARGS+="
perfetto_use_system_sqlite=true
enable_perfetto_trace_processor_percentile=false
enable_perfetto_trace_processor_linenoise=false
enable_perfetto_llvm_demangle=false
"

	einfo "GN_ARGS = ${GN_ARGS}"
	gn gen "${BUILD_OUTPUT}" --args="${GN_ARGS}" || die

	# Extra build flags for building the SDK:
	# * Override the -fvisibility=hidden setting in the build config so the
	#   SDK can be linked into a shared library and then used by an
	#   executable.
	# * Re-enable RTTI: RTTI is disabled in the build config. The SDK needs
	#   to enable RTTI since ChromeOS packages are built with RTTI.
	append-cflags "-fvisibility=default -frtti"
	append-cxxflags "-fvisibility=default -frtti"
	# Add extra GN args in generating the SDK source:
	# * Force disable PERFETTO_DCHECK() in the SDK to avoid inconsistency
	#   of PERFETTO_DCHECK_IS_ON() in the header and the static library
	#   caused by cros-debug.
	# * Disable runloop watchdog.
	local sdk_gn_args="${GN_ARGS}
perfetto_force_dcheck=\"off\"
enable_perfetto_watchdog=false
extra_target_cflags=\"${CFLAGS}\"
extra_target_cxxflags=\"${CXXFLAGS}\"
"
	# Prepare the SDK source.
	# --system_buildtools: use gn, ninja and clang++ of the system. Do not
	#   rely on ${S}/tools/install-build-deps to install build tools. Note
	#   that unprefixed clang++ is used in this script to generate the
	#   source, not to build the SDK static library.
	# --output: where to write the SDK source to.
	# --gn_args: the extra GN args to pass to the script.
	# --out: the temporary build output is stored in ${S}/out/sdk_gen
	# --keep: keep the temporary build output for eninja to build the SDK
	#   library.
	"${S}/tools/gen_amalgamated" --system_buildtools \
		--output "${BUILD_OUTPUT}/sdk/perfetto" \
		--gn_args "${sdk_gn_args}" --out sdk_gen --keep || \
		die "Failed to generate the amalgamated SDK"
}

src_compile() {
	eninja -C "${BUILD_OUTPUT}" traced traced_probes perfetto trace_processor_shell

	# The SDK build folder is generated under ${S}/out/sdk_gen.
	eninja -C "${S}/out/sdk_gen" libperfetto_client_experimental
}

src_install() {
	dobin "${BUILD_OUTPUT}/traced"
	dobin "${BUILD_OUTPUT}/traced_probes"
	dobin "${BUILD_OUTPUT}/perfetto"

	dotmpfiles "${FILESDIR}"/tmpfiles.d/*.conf

	insinto /etc/init
	doins "${FILESDIR}/init/traced.conf"
	doins "${FILESDIR}/init/traced_probes.conf"

	if ! use cros_host ; then
		# Install boot tracing config files.
		insinto /usr/local/share/boottrace
		doins "${FILESDIR}/boottrace/boottrace.pbtxt"
	fi

	insinto /usr/share/policy
	newins "${FILESDIR}/seccomp/traced-${ARCH}.policy" traced.policy
	newins "${FILESDIR}/seccomp/traced_probes-${ARCH}.policy" traced_probes.policy

	sdk_install
	# Change install location to /usr/local/bin for non-host build so
	# the trace processor will skip non-test images.
	use cros_host || into /usr/local
	dobin "${BUILD_OUTPUT}/trace_processor_shell"
}

sdk_install() {
	local sdk_root="${BUILD_OUTPUT}/sdk"
	[[ -d "${sdk_root}" ]] || die "SDK root not found"

	insinto /usr/include/perfetto
	# Both source and lib are provided for convenience.
	doins "${sdk_root}/perfetto.cc"
	doins "${sdk_root}/perfetto.h"
	newlib.a "${S}/out/sdk_gen/libperfetto_client_experimental.a" libperfetto_sdk.a
	doins "${S}/out/sdk_gen/gen/build_config/perfetto_build_flags.h"

	insinto "/usr/$(get_libdir)/pkgconfig"
	local v=$("${S}/tools/write_version_header.py" --stdout)
	sed \
		-e "s/@version@/${v}/g" \
		-e "s/@lib@/$(get_libdir)/g" \
		"${FILESDIR}/pkg-configs/perfetto.pc.in" > "${sdk_root}/perfetto.pc" \
		|| die
	doins "${sdk_root}/perfetto.pc"

	insinto /usr/include/perfetto
	doins -r include/perfetto
	insinto /usr/include/perfetto/protos
	doins -r "${BUILD_OUTPUT}/gen/protos/perfetto"
	insinto /usr/include/perfetto/perfetto/base
}

pkg_preinst() {
	enewuser "traced"
	enewgroup "traced"
	enewuser "traced-probes"
	enewgroup "traced-probes"
	enewgroup "traced-producer"
	enewgroup "traced-consumer"
}
