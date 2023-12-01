# Copyright 2009 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit cros-constants

CROS_WORKON_LOCALNAME="platform/minijail"
CROS_WORKON_PROJECT="chromiumos/platform/minijail"
CROS_WORKON_EGIT_BRANCH="main"

PYTHON_COMPAT=( python3_{6..9} )

# TODO(crbug.com/689060): Re-enable on ARM.
CROS_COMMON_MK_NATIVE_TEST="yes"

DISTUTILS_OPTIONAL=1

inherit cros-debug cros-sanitizers cros-workon cros-common.mk toolchain-funcs distutils-r1

DESCRIPTION="helper binary and library for sandboxing & restricting privs of services"
HOMEPAGE="https://google.github.io/minijail/"

LICENSE="BSD-Google"
KEYWORDS="~*"
IUSE="asan cros-debug default-ret-log +seccomp test"

REQUIRED_USE="default-ret-log? ( cros-debug )"

COMMON_DEPEND="sys-libs/libcap:=
	!<chromeos-base/chromeos-minijail-1"
RDEPEND="${COMMON_DEPEND}"
DEPEND="${COMMON_DEPEND}
	cros_host? (
		${PYTHON_DEPS}
		$(python_gen_cond_dep 'dev-python/setuptools[${PYTHON_USEDEP}]')
	)
	test? (
		dev-cpp/gtest:=
	)"

src_configure() {
	sanitizers-setup-env
	cros-common.mk_src_configure
	export LIBDIR="/$(get_libdir)"
	export USE_seccomp=$(usex seccomp)
	export ALLOW_DEBUG_LOGGING=$(usex cros-debug)
	export SECCOMP_DEFAULT_RET_LOG=$(usex default-ret-log)
	export USE_SYSTEM_GTEST=yes
	export DEFAULT_PIVOT_ROOT=/mnt/empty
	export BLOCK_SYMLINKS_IN_BINDMOUNT_PATHS=yes
	export BINDMOUNT_ALLOWED_PREFIXES=/dev,/sys,/var/log/power_manager
	export BLOCK_SYMLINKS_IN_NONINIT_MOUNTNS_TMP=yes
	use cros_host && distutils-r1_src_configure
}

# Use qemu-user to run the platform-specific dump_constants binary in order to
# generate constants.json.
generate_constants_json() {
	local cmd
	case "${ARCH}" in
	x86)   cmd=( "${OUT}"/dump_constants ) ;;
	amd64) cmd=( "${WORKDIR}"/sdk/dump_constants ) ;;
	arm)   cmd=( qemu-arm "${OUT}"/dump_constants ) ;;
	arm64) cmd=( qemu-aarch64 "${OUT}"/dump_constants ) ;;
	*) die "Unsupported architecture in generate_constants_json(): ${ARCH}."
	esac
	echo "+" "${cmd[@]}" ">${OUT}/constants.json"
	"${cmd[@]}" >"${OUT}"/constants.json || die
}

# Install policies for minijail default runtime environment.
default_policy_install() {
	local policy="v0.bin"

	tools/compile_seccomp_policy.py --arch-json "${OUT}/constants.json" \
		policies/cros_default_v0.policy "${policy}" --denylist \
		|| die

	insinto "/etc/security/minijail"
	doins "${policy}"
}

src_compile() {
	# Avoid confusing people with our docs.
	sed -i "s:/var/empty:${DEFAULT_PIVOT_ROOT}:g" minijail0.[15] || die

	local minijail_targets=( all )

	# We need to generate & run dump_constants.  Intel/AMD targets often use newer
	# ISAs than our build systems & QEMU supports.  The constants care about kernel
	# headers (for the most part), and our build keeps SDK & board headers in sync,
	# so using the SDK compiler here should be safe for our needs.
	if ! use cros_host; then
		if use amd64; then
			tc-env_build emake OUT="${WORKDIR}/sdk" dump_constants
		else
			minijail_targets+=( dump_constants )
		fi
	fi

	cros-common.mk_src_compile "${minijail_targets[@]}"
	if use cros_host ; then
		BUILD_DIR="${OUT}" distutils-r1_src_compile
	else
		generate_constants_json
	fi
}

src_install() {
	into /
	dosbin "${OUT}"/minijail0
	dolib.so "${OUT}"/libminijail{,preload}.so

	doman minijail0.[15]

	if use cros_host ; then
		distutils-r1_src_install
	else
		insinto /build/share
		doins "${OUT}"/constants.json
	fi

	local include_dir="/usr/include/chromeos"

	"${S}"/platform2_preinstall.sh "${PV}" "${include_dir}"
	insinto "/usr/$(get_libdir)/pkgconfig"
	doins libminijail.pc

	insinto "${include_dir}"
	doins libminijail.h
	doins scoped_minijail.h

	if ! use cros_host; then
		default_policy_install
	fi
}
