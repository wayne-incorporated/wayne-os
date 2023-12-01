# Copyright 2006 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: /var/cvsroot/gentoo-x86/profiles/base/profile.bashrc,v 1.3 2009/07/21 00:08:05 zmedico Exp $

# Since unittests on the buildbots don't automatically get access to an
# X server, don't let local dev stations get access either.  If a test
# really needs an X server, they should launch their own with Xvfb.
unset DISPLAY

if ! declare -F elog >/dev/null ; then
	elog() {
		einfo "$@"
	}
fi

# Dumping ground for build-time helpers to utilize since SYSROOT/tmp/
# can be nuked at any time.
CROS_BUILD_BOARD_TREE="${SYSROOT}/build"
CROS_BUILD_BOARD_BIN="${CROS_BUILD_BOARD_TREE}/bin"

CROS_ADDONS_TREE="/mnt/host/source/src/third_party/chromiumos-overlay/chromeos"

# Are we merging for the board sysroot, or for the cros sdk, or for
# the target hardware?  Returns a string:
#  - cros_host (the sdk)
#  - board_sysroot
#  - target_image
# We can't rely on "use cros_host" as USE gets filtred based on IUSE,
# and not all packages have IUSE=cros_host.
cros_target() {
	if [[ ${CROS_SDK_HOST} == "cros-sdk-host" ]] ; then
		echo "cros_host"
	elif [[ "${SYSROOT:-/}" != "/" && "${ROOT%/}" == "${SYSROOT%/}" ]] ; then
		echo "board_sysroot"
	else
		echo "target_image"
	fi
}

# Load all additional bashrc files we have for this package.
cros_stack_bashrc() {
	local cfg cfgd
	cfgd="/mnt/host/source/src/third_party/chromiumos-overlay/${CATEGORY}/${PN}"
	export BASHRC_FILESDIR="${cfgd}/files"
	for cfg in ${PN} ${P} ${PF} ; do
		cfg="${cfgd}/${cfg}.bashrc"
		[[ -f ${cfg} ]] && . "${cfg}"
	done
}
cros_stack_bashrc

# The standard bashrc hooks do not stack.  So take care of that ourselves.
# Now people can declare:
#   cros_pre_pkg_preinst_foo() { ... }
# And we'll automatically execute that in the pre_pkg_preinst func.
#
# Note: profile.bashrc's should avoid hooking phases that differ across
# EAPI's (src_{prepare,configure,compile} for example).  These are fine
# in the per-package bashrc tree (since the specific EAPI is known).
cros_lookup_funcs() {
	declare -f | egrep "^$1 +\(\) +$" | awk '{print $1}'
}
cros_stack_hooks() {
	local phase=$1 func
	local header=true

	for func in $(cros_lookup_funcs "cros_${phase}_[-_[:alnum:]]+") ; do
		if ${header} ; then
			einfo "Running stacked hooks for ${phase}"
			header=false
		fi
		ebegin "   ${func#cros_${phase}_}"
		${func}
		eend $?
	done
}
cros_setup_hooks() {
	# Avoid executing multiple times in a single build.
	[[ ${cros_setup_hooks_run+set} == "set" ]] && return

	local phase
	for phase in {pre,post}_{src_{unpack,prepare,configure,compile,test,install},pkg_{{pre,post}{inst,rm},setup,nofetch}} ; do
		eval "${phase}() { cros_stack_hooks ${phase} ; }"
	done
	export cros_setup_hooks_run="booya"
}
cros_setup_hooks

cros_post_pkg_nofetch_distdir() {
	# Let the user know where to find DISTDIR when they need to manually
	# download a package.
	einfo "On Chromium OS, DISTDIR is /var/cache/distfiles/ inside the chroot"
	einfo "and ~/chromiumos/.cache/distfiles/ outside the chroot."
}

# If we ran clang-tidy during the compile phase, we need to capture the build
# logs, which contain the actual clang-tidy warnings.
cros_pre_src_install_tidy_setup() {
	if [[ -v WITH_TIDY ]] ; then
		if [[ ${WITH_TIDY} -eq 1 ]] ; then
			clang_tidy_logs_dir="/tmp/clang-tidy-logs/${BOARD}"
			mkdir -p ${clang_tidy_logs_dir}
			cp "${PORTAGE_LOG_FILE}" "${clang_tidy_logs_dir}"
			sudo chmod 644 "${clang_tidy_logs_dir}"/*
		fi
	fi
}

# Since we're storing the wrappers in a board sysroot, make sure that
# is actually in our PATH.
cros_pre_pkg_setup_sysroot_build_bin_dir() {
	PATH+=":${CROS_BUILD_BOARD_BIN}"
}

# We don't want builds to run tools directly like `gcc` or `clang` or
# `pkg-config`.  This indicates the packages are written incorrectly and
# would use the wrong toolchain for the board.  They might seem to work for
# x86_64 boards (since the SDK is x86_64), but it's still unreliable.
# https://crbug.com/985180
cros_pre_src_prepare_build_toolchain_catch() {
	local targetenv
	if [[ $(cros_target) == "cros_host" ]]; then
		targetenv="sdk"
	else
		targetenv="board"
	fi

	# Note: Do not add any more packages to these lists.  Fix the bugs instead.

	# TODO(vapier): Finish fixing these packages.
	_sdk_build_filter_pkg_config() {
		case ${CATEGORY}/${PN}:${PV} in
		*/gdb:*) return 1;;
		# Haskell has some internal logic that invokes `pkg-config --version`.
		app-admin/haskell-updater:*) return 1;;
		dev-embedded/u-boot-tools:2018.05*) return 1;;
		dev-util/shellcheck:*) return 1;;
		dev-haskell/*) return 1;;
		dev-lang/ghc:*) return 1;;
		dev-python/pycairo:1.20*) return 1;;
		media-video/ffmpeg:4.4*) return 1;;
		net-analyzer/wireshark:3.4.*) return 1;;
		# Used during `aclocal` to find glib macros.
		x11-libs/cairo:*) return 1;;
		esac
	}
	_sdk_build_filter_cc() {
		case ${CATEGORY}/${PN}:${PV} in
		*/binutils:*|\
		*/gcc:*|\
		*/gdb:*|\
		app-text/xmlto:0.0.28|\
		cross-*/gdb:*|\
		dev-embedded/u-boot-tools:2018.05*|\
		dev-libs/libffi:3.1*|\
		dev-libs/libusb-compat:0.1.5*|\
		dev-libs/lzo:2.10*|\
		dev-python/grpcio:1.23.0|\
		dev-python/psutil:5.5.0|\
		dev-util/patchutils:0.3.3|\
		net-libs/libmnl:1.0.4*|\
		sys-apps/groff:1.22*|\
		sys-devel/m4:1.4.18*|\
		sys-libs/binutils-libs:*|\
		x11-libs/gdk-pixbuf:2.42.8) return 1;;
		esac
	}
	_sdk_build_filter_gcc() {
		# We need to add gcc to the allow list because the gcc ./configure script
		# will try and compile an ada file using clang. Since clang doesn't know
		# how to compile ada, it forks gcc to try and build it.
		case ${CATEGORY}/${PN}:${PV} in
		cross-*/glibc:*|\
		*/gcc:*|\
		*/linux-headers:4*|\
		dev-embedded/u-boot-tools:2018.05*|\
		dev-python/numpy:1.19.4|\
		dev-util/ragel:6.10|\
		net-misc/socat:1.7.3.2*|\
		sys-boot/syslinux:6.04*|\
		sys-libs/binutils-libs:*|\
		sys-libs/libselinux:3.0) return 1;;
		esac
	}
	_sdk_build_filter_g++() {
		return 0
	}
	_sdk_build_filter_clang() {
		return 0
	}
	_sdk_build_filter_clang++() {
		return 0
	}
	_sdk_build_filter_ld() {
		case ${CATEGORY}/${PN}:${PV} in
		cross-*/gcc:*|\
		cross-*/go:*|\
		dev-embedded/coreboot-sdk:*|\
		dev-lang/go:*) return 1;;
		esac
	}
	_sdk_build_filter_as() {
		case ${CATEGORY}/${PN}:${PV} in
		dev-embedded/coreboot-sdk:*) return 1;;
		esac
	}

	_board_build_filter_pkg_config() {
		case ${CATEGORY}/${PN}:${PV} in
		app-benchmarks/lmbench:3.0*|\
		app-emulation/docker:19*|\
		app-emulation/docker:20*|\
		app-text/ghostscript-gpl:9.55*|\
		media-libs/arc-cros-gralloc:*|\
		media-libs/arc-img-ddk:*|\
		media-libs/arc-mali-drivers:*|\
		media-libs/arc-mali-drivers-bifrost:25.*|\
		media-libs/arc-mesa:*|\
		media-libs/arc-mesa-amd:*|\
		media-libs/arc-mesa-freedreno:*|\
		media-libs/arc-mesa-img:*|\
		media-libs/arc-mesa-iris:*|\
		media-libs/arc-mesa-virgl:*|\
		media-libs/mali-drivers-bifrost:32.*|\
		media-libs/mali-drivers-valhall:32.*|\
		media-libs/mesa:*|\
		media-libs/mesa-amd:*|\
		media-libs/mesa-llvmpipe:*|\
		net-analyzer/wireshark:*|\
		net-dns/dnsmasq:2.85*|\
		net-misc/dhcpcd:*|\
		sys-apps/fwupd:1.8*|\
		sys-boot/coreboot:*|\
		sys-boot/depthcharge:*|\
		sys-boot/loonix-u-boot:*|\
		sys-boot/u-boot:*|\
		sys-devel/arc-llvm:*|\
		sys-devel/gdb:*|\
		sys-kernel/arcvm-kernel-ack-5_10:*|\
		sys-kernel/chromeos-kernel-4_14:*|\
		sys-kernel/chromeos-kernel-4_19:*|\
		sys-kernel/chromeos-kernel-4_4:*|\
		sys-kernel/chromeos-kernel-5_4:*|\
		sys-kernel/chromeos-kernel-experimental:4.*|\
		sys-kernel/chromeos-kernel-next:*|\
		sys-kernel/gasket:*|\
		sys-kernel/loonix-kernel-*:*|\
		sys-kernel/raspberrypi-kernel:*|\
		sys-kernel/ti-nokia-kernel:*|\
		sys-kernel/upstream-kernel-*:*|\
		x11-base/xwayland:1.20.8|\
		x11-libs/arc-libdrm:*|\
		x11-libs/cairo:1.17.4) return 1;;
		esac
	}
	_board_build_filter_cc() {
		case ${CATEGORY}/${PN}:${PV} in
		app-benchmarks/sysbench:1.0.10|\
		dev-libs/libdaemon:*|\
		dev-libs/libffi:3.1*|\
		dev-libs/libusb-compat:0.1.5*|\
		dev-python/grpcio:*|\
		dev-python/psutil:5.5.0|\
		media-libs/libogg:1.3.5|\
		net-dns/avahi:*|\
		net-libs/libmnl:*|\
		net-libs/libnetfilter_cthelper:*|\
		net-libs/libnetfilter_cttimeout:*|\
		net-libs/libnetfilter_queue:*|\
		net-libs/libnfnetlink:*|\
		sys-apps/groff:*|\
		sys-apps/kbd:*|\
		sys-apps/ureadahead:*|\
		sys-block/parted:*|\
		sys-boot/arria10-u-boot:*|\
		sys-boot/loonix-u-boot:*|\
		sys-devel/binutils:*|\
		sys-devel/gdb:*|\
		sys-devel/m4:*|\
		sys-fs/rar2fs:1.29.5|\
		sys-libs/binutils-libs:*|\
		x11-libs/gdk-pixbuf:*) return 1;;
		esac
	}
	_board_build_filter_gcc() {
		case ${CATEGORY}/${PN}:${PV} in
		app-emulation/docker:19*|\
		app-emulation/docker:20*|\
		chromeos-base/autotest-tests:*|\
		chromeos-base/chromeos-ec:*|\
		chromeos-base/chromeos-ish:*|\
		dev-go/syzkaller:*|\
		dev-python/numpy:1.19.4|\
		media-libs/arc-img-ddk:*|\
		media-libs/img-ddk:*|\
		media-sound/gsm:1.0.13|\
		net-fs/autofs:*|\
		net-misc/socat:1.7.3.2*|\
		sys-block/blktrace:*|\
		sys-boot/chromeos-mrc:*|\
		sys-boot/coreboot:*|\
		sys-boot/depthcharge:*|\
		sys-boot/syslinux:6.04*|\
		sys-firmware/chromeos-fpmcu-release-bloonchipper:*|\
		sys-firmware/chromeos-fpmcu-release-dartmonkey:*|\
		sys-firmware/chromeos-fpmcu-release-nami:*|\
		sys-firmware/chromeos-fpmcu-release-nocturne:*|\
		sys-fs/mdadm:4.1*|\
		sys-kernel/linux-headers:*) return 1;;
		esac
	}
	_board_build_filter_g++() {
		case ${CATEGORY}/${PN}:${PV} in
		media-libs/img-ddk:*|\
		net-print/hplip:3.21.8*|\
		sys-boot/qca-framework:*) return 1;;
		esac
	}
	_board_build_filter_clang() {
		case ${CATEGORY}/${PN}:${PV} in
		chromeos-base/autotest-tests-lakitu:*|\
		chromeos-base/chromeos-ec:*|\
		media-libs/arc-mali-drivers-bifrost:25.*|\
		media-libs/mali-drivers-bifrost:32.*|\
		media-libs/mali-drivers-valhall:32.*|\
		net-libs/nodejs:12*|\
		sys-boot/coreboot:*|\
		sys-devel/arc-llvm:*|\
		sys-devel/llvm:*) return 1;;
		esac
	}
	_board_build_filter_clang++() {
		case ${CATEGORY}/${PN}:${PV} in
		media-libs/arc-mali-drivers-bifrost:25.*|\
		media-libs/mali-drivers-bifrost:32.*|\
		media-libs/mali-drivers-valhall:32.*|\
		net-libs/nodejs:12*|\
		sys-devel/arc-llvm:*|\
		sys-devel/llvm:*) return 1;;
		esac
	}
	_board_build_filter_ld() {
		case ${CATEGORY}/${PN}:${PV} in
		media-libs/arc-mali-drivers-bifrost:25.*|\
		media-libs/mali-drivers-bifrost:32.*|\
		sys-kernel/raspberrypi-kernel:*) return 1;;
		esac
	}
	_board_build_filter_as() {
		case ${CATEGORY}/${PN}:${PV} in
		dev-embedded/coreboot-sdk:*|\
		sys-boot/coreboot:*) return 1;;
		esac
	}

	local dir="${T}/build-toolchain-wrappers"
	mkdir -p "${dir}"
	local tool tcvar
	for tool in as ld clang clang++ c++ g++ cc gcc pkg-config; do
		case ${tool} in
		clang|gcc)
			tcvar="CC"
			;;
		clang++|[cg]++)
			tcvar="CXX"
			;;
		*)
			tcvar=${tool^^}
			tcvar=${tcvar//-/_}
			;;
		esac

		case ${tool} in
		as|cc|clang|clang++|g++|gcc|ld|pkg-config)
			_${targetenv}_build_filter_${tool//-/_} || continue
			;;
		esac

		cat <<EOF > "${dir}/${tool}"
#!/bin/bash
ppid="self"
declare -i depth=0
while [[ -n "\${ppid}" ]]; do
	if [[ "\$(readlink -f "/proc/\${ppid}/fd/2")" != "/dev/null" ]]; then
		break
	fi
	depth+=1
	ppid="\$(awk '\$1 == "PPid:" {print \$NF}' /proc/\${ppid}/status)"
done

# Configure scripts like to invoke these utilities with stderr redirected to
# /dev/null. This means the errors get gobbled up. To work around that we
# redirect our stderr to the first stderr that isn't /dev/null.
if [[ "\${depth}" -gt 0 && -n "\${ppid}" ]]; then
	exec 2>"/proc/\${ppid}/fd/2"
fi

$(type -P eerror) "\$(
err() { echo "${tool}: ERROR: \$*"; }
err "Do not call unprefixed tools directly."
err "For board tools, use \\\`tc-export ${tcvar}\\\`."
err "For build-time-only tools, \\\`tc-export BUILD_${tcvar}\\\`."
pstree -a -A -s -l \$\$
)"
$(type -P die) "Bad ${tool} [\$*] invocation"
exit 1
EOF
		chmod a+rx "${dir}/${tool}"
	done

	# Block uses of unallowed GCC/Binutils usage in ${ABI}-tool format.
	# Temporarily allow haskell, and bootstub (for objcopy) packages.
	local prefixed_tool gnu_gcc_binutils_tools
	mkdir -p "${dir}/gnu_tools"
	gnu_gcc_binutils_tools=(ar gcc ld nm objcopy ranlib strip)
	for tool in "${gnu_gcc_binutils_tools[@]}"; do
		case ${CATEGORY}/${PN}:${PV} in
			app-admin/haskell-updater:*|\
			dev-haskell/*:*|\
			dev-lang/ghc:*|\
			dev-util/shellcheck:*|\
			sys-boot/bootstub:*|\
			*/linux-headers:*) continue
			;;
		esac
		for prefixed_tool in "${CHOST}-${tool}" "${CBUILD}-${tool}"; do
			cat <<EOF2 > "${dir}/gnu_tools/${prefixed_tool}"
#!/bin/bash
ppid="self"
declare -i depth=0
while [[ -n "\${ppid}" ]]; do
	if [[ "\$(readlink -f "/proc/\${ppid}/fd/2")" != "/dev/null" ]]; then
		break
	fi
	depth+=1
	ppid="\$(awk '\$1 == "PPid:" {print \$NF}' /proc/\${ppid}/status)"
done

# Configure scripts like to invoke these utilities with stderr redirected to
# /dev/null. This means the errors get gobbled up. To work around that we
# redirect our stderr to the first stderr that isn't /dev/null.
if [[ "\${depth}" -gt 0 && -n "\${ppid}" ]]; then
	exec 2>"/proc/\${ppid}/fd/2"
fi

$(type -P eerror) "\$(
err() { echo "${prefixed_tool}: ERROR: \$*"; }
err "Unexpected use of GCC/GNU Binutils."
err "If this use is necessary, please call cros_allow_gnu_build_tools in the ebuild"
pstree -a -A -s -l \$\$
)"
$(type -P die) "Unexpected ${prefixed_tool} [\$*] invocation"
exit 1
EOF2
			chmod a+rx "${dir}/gnu_tools/${prefixed_tool}"
		done
	done
	PATH="${dir}:${dir}/gnu_tools:${PATH}"
}

cros_post_src_install_build_toolchain_catch() {
	# Some portage install hooks will run tools.  We probably want to change
	# those, but at least for now, we'll undo the wrappers.
	rm -rf "${T}/build-toolchain-wrappers"
}

# Set ASAN settings so they'll work for unittests. http://crbug.com/367879
# We run at src_unpack time so that the hooks have time to get registered
# and saved in the environment.  Portage has a bug where hooks registered
# in the same phase that fails are not run.  http://bugs.gentoo.org/509024
# We run at the _end_ of src_unpack time so that ebuilds which munge ${S}
# (packages which live in the platform2 repo) can do so before we do work.
cros_post_src_unpack_asan_init() {
	local log_path="${T}/asan_logs/asan"
	local coverage_path="${T}/coverage_logs"
	mkdir -p "${log_path%/*}"
	mkdir -p "${coverage_path%/*}"

	local strip_sysroot
	if [[ -n "${PLATFORM_BUILD}" ]] || [[ -n "${_ECLASS_CROS_RUST}" ]]; then
		# platform_test chroots into $SYSROOT before running the unit
		# tests, so we need to strip the $SYSROOT prefix from the
		# 'log_path' option specified in $ASAN_OPTIONS and the
		# 'suppressions' option specified in $LSAN_OPTIONS.
		strip_sysroot="${SYSROOT}"
	fi
	export ASAN_OPTIONS+=" log_path=${log_path#${strip_sysroot}}"
	export MSAN_OPTIONS+=" log_path=${log_path#${strip_sysroot}}"
	export TSAN_OPTIONS+=" log_path=${log_path#${strip_sysroot}}"
	export UBSAN_OPTIONS+=" log_path=${log_path#${strip_sysroot}}"
	# TODO(b/244629615): Disable detect_stack_use_after_return till we can
	# fix missing packages e.g. croslog/shill etc.
	export ASAN_OPTIONS+=" detect_stack_use_after_return=0"
	# symbolize ubsan crashes.
	export UBSAN_OPTIONS+=":symbolize=1:print_stacktrace=1"
	# Clang coverage file generation location, only for target builds.
	if [[ $(cros_target) == "board_sysroot" ]]; then
		export LLVM_PROFILE_FILE="${coverage_path#${strip_sysroot}}/${P}_%9m.profraw"
	fi

	local lsan_suppression="${S}/lsan_suppressions"
	local lsan_suppression_ebuild="${FILESDIR}/lsan_suppressions"
	export LSAN_OPTIONS+=" print_suppressions=0"
	if [[ -f ${lsan_suppression} ]]; then
		export LSAN_OPTIONS+=" suppressions=${lsan_suppression#${strip_sysroot}}"
	elif [[ -f ${lsan_suppression_ebuild} ]]; then
		export LSAN_OPTIONS+=" suppressions=${lsan_suppression_ebuild}"
	fi

	has asan_death_hook "${EBUILD_DEATH_HOOKS}" || EBUILD_DEATH_HOOKS+=" asan_death_hook"
}

# Check for & show ASAN failures when dying.
asan_death_hook() {
	# File(s) may not exist.
	compgen -G "${T}/asan_logs/asan*" >/dev/null || return 0

	# Find and fix permissions on the log files so that they can be read later.
	find "${T}"/asan_logs/asan* '!' -user "${PORTAGE_USERNAME}" -exec sudo chown "${PORTAGE_USERNAME}:${PORTAGE_GRPNAME}" {} +

	local l
	for l in "${T}"/asan_logs/asan*; do
		echo
		eerror "ASAN error detected:"
		eerror "$(asan_symbolize.py -d -s "${SYSROOT}" < "${l}")"
		echo
	done
	return 1
}

# Check for any ASAN failures that were missed while testing.
cros_post_src_test_asan_check() {
	# Remove the temporary directories created previously in asan_init.
	# Die if ASAN failures were reported.
	rmdir "${T}/asan_logs" 2>/dev/null || die "asan error not caught"
	# Recreate directories for incremental cros_workon-make --test usage.
	mkdir -p "${T}/asan_logs"
}

cros_post_src_install_coverage_logs() {
	# Generate coverage reports for board and host packages.
	local coverage_path="${T}/coverage_logs"
	if [ ! -d "${coverage_path}" ] || [ -z "$(ls -A "${coverage_path}")" ]; then
		return
	fi

	local report_path
	if [[ $(cros_target) == "cros_host" ]]; then
		local cov_dir="${CROS_ARTIFACTS_TMP_DIR}/coverage_data/"
		mkdir -p "${cov_dir}" || die
		local pkg_cover="${PN}_cover.out"
		local pkg_report="${PN}.html"
		mv "${coverage_path}/${pkg_cover}" "${coverage_path}/${pkg_report}" "${cov_dir}" || die "Cannot move artifacts to ${coverage_path}"
		report_path="${EXTERNAL_TRUNK_PATH}/chroot/${SYSROOT}/var/lib/chromeos/package-artifacts/${CATEGORY}/${PF}/coverage_data/${pkg_report}"
	elif [[ $(cros_target) == "board_sysroot" ]]; then
		local rel_cov_dir="build/coverage_data/${CATEGORY}/${PN}"
		[[ "${SLOT:-0}" != "0" ]] && rel_cov_dir+="-${SLOT}"
		local cov_dir="${D}/${rel_cov_dir}"
		mkdir -p "${cov_dir}/raw_profiles"
		cp "${coverage_path}"/*.profraw "${cov_dir}/raw_profiles" || die
		local cov_files=( "${coverage_path}"/*.profraw )

		# Create the indexed profile file from raw profiles.
		# TODO(b/215596245): Remove rust-specific cmd once clang and rust converge on same llvm version.
		local cov_fail=false
		local rust_fail=false
		llvm-profdata merge -sparse "${cov_files[@]}" \
			-output="${cov_dir}/${PN}.profdata" || cov_fail=true

		if [[ "${cov_fail}" == true ]]; then
			/usr/libexec/rust/llvm-profdata merge -sparse -failure-mode=all "${cov_files[@]}" \
				-output="${cov_dir}/${PN}.profdata" || die "Failed to merge profraw files."
		fi

		local cov_args
		# Find all elf binaries built in this package that have
		# coverage instrumentation enabled and add "-object option" to
		# be used later in llvm-cov.
		# TODO: Find more directories other than ${OUT} and ${WORKDIR}
		# that the package may use for producing binaries.
		readarray -t cov_args < <(scanelf -qRy -k__llvm_covmap \
			-F$'-object\n#k%F' "${OUT}" "${WORKDIR}" \
			"${CARGO_TARGET_DIR}/ecargo-test/${CHOST}")

		if [[ "${#cov_args[@]}" -eq 0 ]]; then
			elog "No object files found with coverage data."
			return
		fi

		# Generate json format coverage report.
		llvm-cov export "${cov_args[@]}" \
			-instr-profile="${cov_dir}/${PN}.profdata" \
			-skip-expansions \
			-skip-functions \
			> "${cov_dir}"/coverage.json || die

		# Generate html format coverage report.
		llvm-cov show "${cov_args[@]}" -format=html \
			-instr-profile="${cov_dir}/${PN}.profdata" \
			-output-dir="${cov_dir}" || die
		# Make coverage data readable for all users.
		chmod -R a+rX "${cov_dir}" || die "Could not make ${cov_dir} readable"
		report_path="${EXTERNAL_TRUNK_PATH}/chroot${SYSROOT}/${rel_cov_dir}/index.html"
	fi
	elog "Coverage report for ${PN} generated at file://${report_path}"
}

# Enables C++ exceptions. We normally disable these by default in
#   chromiumos-overlay/chromeos/config/make.conf.common-target
cros_enable_cxx_exceptions() {
	CXXFLAGS=${CXXFLAGS/ -fno-exceptions/ }
	CXXFLAGS=${CXXFLAGS/ -fno-unwind-tables/ }
	CXXFLAGS=${CXXFLAGS/ -fno-asynchronous-unwind-tables/ }
	CFLAGS=${CFLAGS/ -fno-exceptions/ }
	CFLAGS=${CFLAGS/ -fno-unwind-tables/ }
	CFLAGS=${CFLAGS/ -fno-asynchronous-unwind-tables/ }
	# Set the CXXEXCEPTIONS variable to 1 so packages based on common.mk or
	# platform2 gyp inherit this value by default.
	CXXEXCEPTIONS=1
}

# Allow usages of gcc/binutils tools.
cros_allow_gnu_build_tools() {
	rm -rf "${T}/build-toolchain-wrappers/gnu_tools"
}

# We still use gcc to build packages even the CC or CXX is set to
# something else.
cros_use_gcc() {
	if [[ $(basename ${CC:-gcc}) != *"gcc"* ]]; then
		export CC=${CHOST}-gcc
		export CXX=${CHOST}-g++
		export LD=${CHOST}-ld
	fi
	if [[ $(basename ${BUILD_CC:-gcc}) != *"gcc"* ]]; then
		export BUILD_CC=${CBUILD}-gcc
		export BUILD_CXX=${CBUILD}-g++
		export BUILD_LD=${CBUILD}-ld
	fi
	filter_unsupported_gcc_flags
	filter_sanitizers
	cros_allow_gnu_build_tools
}

# Use a frozen 4.9.2 GCC for packages that can't use latest GCC
# for compatibility reasons.
# Please do not use without contacting toolchain team.
cros_use_frozen_gcc() {
	local frozen_gcc_path="/opt/gcc-bin-4.9.2"

	ewarn "Building using old GCC from ${frozen_gcc_path}."
	ewarn "This GCC is frozen and no bug fixes are planned for it."
	ewarn "Any bugs should be handled by the package owners."

	local abis=(
		"aarch64-cros-linux-gnu"
		"armv7a-cros-linux-gnueabihf"
		"x86_64-cros-linux-gnu"
	)
	local abi
	for abi in "${abis[@]}"; do
		PATH="${frozen_gcc_path}/${abi}/bin:${PATH}"
	done
	cros_use_gcc
}

# Enforce use of libstdc++ instead of libc++ when building with clang.
cros_use_libstdcxx() {
	if [[ $(basename "${CC:-clang}") == *"clang"* ]]; then
		CXXFLAGS+=" -Xclang-only=-stdlib=libstdc++"
		LDFLAGS+=" -Xclang-only=-stdlib=libstdc++"
	fi
}

cros_log_failed_packages() {
	if [[ -n "${CROS_METRICS_DIR}" ]]; then
		mkdir -p "${CROS_METRICS_DIR}"
		echo "${CATEGORY}/${PF} ${EBUILD_PHASE:-"unknown"}" \
			 >> "${CROS_METRICS_DIR}/FAILED_PACKAGES"
	fi

	# Failures in these phases are often due to broken generation, so include
	# the logs if they exist.
	case ${EBUILD_PHASE} in
	unpack|prepare|configure)
		local f
		for f in libtoolize aclocal autoconf autoheader automake autopoint; do
			f="${T}/${f}.out"
			if [[ -e ${f} ]]; then
				echo "### START ${f} ###"
				cat "${f}"
				echo "### END ${f} ###"
			fi
		done
		;;
	esac
}

cros_optimize_package_for_speed() {
	# NOTE: Replacing this with -O3 probably isn't worth it. -O3 sometimes speeds
	# up code/sometimes doesn't, and the binaries where literally 94% of our
	# fleetwide cycles are spent (at the time of writing) reject our optimization
	# flags and substitute their own anyway.
	export CFLAGS+=" -O2"
	export CXXFLAGS+=" -O2"
	CROS_RUST_PACKAGE_IS_HOT=1
}

register_die_hook cros_log_failed_packages

filter_clang_syntax() {
	local var flag flags=()
	for var in CFLAGS CXXFLAGS; do
		for flag in ${!var}; do
			if [[ ${flag} != "-clang-syntax" ]]; then
				flags+=("${flag}")
			fi
		done
		export ${var}="${flags[*]}"
		flags=()
	done
}

filter_sanitizers() {
	local var flag flags=()
	for var in CFLAGS CXXFLAGS LDFLAGS; do
		for flag in ${!var}; do
			if [[ ${flag} != "-fsanitize"* && ${flag} != "-fno-sanitize"* ]]; then
				flags+=("${flag}")
			fi
		done
		export ${var}="${flags[*]}"
		flags=()
	done
}

filter_unsupported_gcc_flags() {
	local var flag flags=()
	for var in CFLAGS CXXFLAGS LDFLAGS; do
		for flag in ${!var}; do
			if [[ ${flag} != "-Xcompiler" && \
			      ${flag} != "-Wl,--icf=all" && \
			      ${flag} != "--unwindlib=libunwind" ]]; then
				flags+=("${flag}")
			fi
		done
		export ${var}="${flags[*]}"
		flags=()
	done
}
