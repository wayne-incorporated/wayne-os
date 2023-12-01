#!/bin/bash
#
# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# This script creates a tarball that contains toolchains for android
# tm-arc-dev. Before running it, please modify the following 4 variables
#   - ANDROID_TREE
#   - ARTIFACTS_DIR_ARM64
#   - ARTIFACTS_DIR_X86_64
#   - TO_DIR_BASE
#   - DEAPEXER
#   - DEBUGFS
# Then just run it from anywhere with no arguments.
# The constructed tarball will contain the sysroots under amd64 and arm.
#
# *** PREREQUISITES ***
# Before running the script, follow these steps:
#
# 1. Download prebuilts for ARM and x86_64
#
# Go to go/ab, select branch git_tm-arc-dev. Pick a -userdebug build for all
# architectures, then download bertha_${arch}-target_files-${build_id}.zip.
# Extract those files and point ARTIFACTS_DIR_${ARCH} to the respective
# directories.
# The prebuilts will provide most of the binaries.
#
# 2. Make sure you have the right version of the prebuilts
#
# $ grep "ro.build.version.release" ${ARTIFACTS_DIR_${ARCH}}/SYSTEM/build.prop
#
# The build artifacts will be created in subdirectories of out/ where the script
# will find them. Do not delete out/ or rebuild before running the script!
#
# 4. Download deapexer and debugfs binaries.
#
# Go to ab/ub-aapt2-release and choose the latest green static_apexer_tools
# build. Download the deapexer and debugfs_static artifacts from that build
# and make them executable. See
# https://g3doc.corp.google.com/third_party/android/apex/README.md for more
# info.
#
# Set DEAPEXER and DEBUGFS to the path to those artifacts.
#
# 5. Build bionic/libc
#
# Go to $ANDROID_TREE and run
#   . build/rbesetup.sh
#   lunch bertha_x86_64-userdebug
#   mmm bionic/libc
#
#   lunch bertha_arm64-userdebug
#   mmm bionic/libc
#
# Add a comment to save the sha of the bionic repo to the
# the ebuild so that we can reproduce this if necessary.
# You should be able to find it via git log in the bionic folder.
#
# 6. Run the script!
#
# $ ./gather.sh
#


set -e

# 1. Location of the android tm-arc-dev branch tree.
: "${ANDROID_TREE:="${HOME}/android"}"

# ARCH names used in sysroot.
ARC_ARCH=('amd64' 'arm64' 'amd64' 'arm64')

# LIBRARY paths for each ARCH
ARC_ARCH_LIB_DIR=('lib' 'lib' 'lib64' 'lib64')

# ARCH names used in android.
ARC_ARCH_ANDROID=('x86' 'arm' 'x86_64' 'arm64')

# ARCH CPU used in android.
ARC_ANDROID_CPU=('sandybridge' 'armv8-a_cortex-a72' 'sandybridge' \
  'armv8-a_cortex-a72')

# ARCH names used in kernel uapi.
ARC_ARCH_UAPI=('x86' 'arm' 'x86' 'arm64')

# 2. The dir to which the artifacts tarball (downloaded from go/ab) was
# extracted. Pick a -userdebug build.
# Now we support two platforms: 32/64-bit arm and 32/64-bit x86.
: "${ARTIFACTS_DIR_ARM64:="${ANDROID_TREE}/arm64_target_files/"}"
: "${ARTIFACTS_DIR_X86_64:="${ANDROID_TREE}/x86_64_target_files/"}"

ARTIFACTS_DIR_ARRAY=(
	"${ARTIFACTS_DIR_X86_64}"
	"${ARTIFACTS_DIR_ARM64}"
	"${ARTIFACTS_DIR_X86_64}"
	"${ARTIFACTS_DIR_ARM64}"
)

# 3. Destination directory.
TO_DIR_BASE="${TO_DIR_BASE:-"${ANDROID_TREE}/arc-toolchain-t-dir"}"

# 4. Path to deapexer and debugfs binaries.
: "${DEAPEXER:=""}"
: "${DEBUGFS:=""}"

if [[ ! -f "${DEAPEXER}" ]] || [[ ! -f "${DEBUGFS}" ]]; then
	echo "Please set \$DEAPEXER and \$DEBUGFS before running."
	exit 1
fi

### Do not change the following.

if [[ ! -d "${ANDROID_TREE}" ]] || \
	[[ ! -d "${ARTIFACTS_DIR_ARM64}" ]] || \
	[[ ! -d "${ARTIFACTS_DIR_X86_64}" ]] ; then
	echo "Please set ANDROID_TREE, ARTIFACTS_DIR_ARM64, and" \
		"ARTIFACTS_DIR_X86_64 before running."
	exit 1
fi

dryrun=
if [[ "$1" == "--dryrun" ]]; then
	dryrun=1
fi


### Run / dryrun a command.
function runcmd {
	cmdarray=("${@}")
	if [[ -z "${dryrun}" ]]; then
		echo "${cmdarray[@]}"
		"${cmdarray[@]}"
	else
		echo "dryrun: ${cmdarray[@]}"
	fi
}

# Clean any previous work.
if [ -d "${TO_DIR_BASE}" ]; then
	runcmd rm -rf "${TO_DIR_BASE}"
fi

# Number of supported sysroots
len=$((${#ARC_ARCH[@]}))

# Setup the sysroot for each architecture.
for (( a = 0; a < ${len}; ++a )); do
	arc_arch="${ARC_ARCH[${a}]}"
	arch="${ARC_ARCH_ANDROID[${a}]}"

	arch_to_dir="${TO_DIR_BASE}/${arc_arch}"
	runcmd mkdir -p "${arch_to_dir}/usr/include"
	runcmd mkdir -p "${arch_to_dir}/usr/include/asm"
	runcmd mkdir -p "${arch_to_dir}/usr/include/c++/4.9"
	runcmd mkdir -p "${arch_to_dir}/usr/include/linux/asm"

	### 1. Binaries.
	BINARY_FILES=(
		libbacktrace.so
		libbinder.so
		libc.so
		libc++.so
		libcutils.so
		libdl.so
		libexpat.so
		libhardware.so
		liblog.so
		libm.so
		libmediandk.so
		libnativewindow.so
		libstdc++.so
		libsync.so
		libui.so
		libutils.so
		libz.so
	)

	lib="${ARC_ARCH_LIB_DIR[${a}]}"
	artifacts_system_dir="${ARTIFACTS_DIR_ARRAY[${a}]}/SYSTEM"
	if [[ ! -d "${artifacts_system_dir}/${lib}" ]]; then
		echo "${artifacts_system_dir}/${lib} not found, continuing."
		continue
	fi
	runcmd mkdir -p "${arch_to_dir}/usr/${lib}/"

	# Special case: extract runtime apex if there is one (b/179070967).
	apex_path="${artifacts_system_dir}/apex/com.android.runtime.apex"
	apex_dir_path="${artifacts_system_dir}/apex/com.android.runtime"
	if [[ -f "${apex_path}" ]] &&
		[[ ! -d "${apex_dir_path}" ]]; then
		"${DEAPEXER}" --debugfs_path="${DEBUGFS}" extract \
			"${apex_path}" "${apex_dir_path}"
	fi

	for f in "${BINARY_FILES[@]}"; do
		# For some core libraries, e.g. libc and libm, there are two versions.
		# Filter out the "bootstrap" ones since those are supposed to be used by
		# apexd. Likewise for arm/arm64 folders found on x86/x86_64
                # prebuilds.

		file=$(find "${artifacts_system_dir}/${lib}" -name "${f}" 2>/dev/null \
			| grep -v /bootstrap/ | grep -v /arm/ | grep -v /arm64/)
		case $(echo "${file}" | wc -l) in
		0)
			echo "${f} not found, aborted."
			exit 1
			;;
                1) ;;
		*)
			echo "more than 1 ${f} found, aborted."
			echo "${file}"
			exit 1
			;;
		esac

		# Resolve symlink if not exists
		if [ -L "${file}" -a ! -f "${file}" ]; then
			file="${artifacts_system_dir}$(readlink $file)"
			# Special case: ART mainline module has different package name on
			# debuggable build.
			if [ ! -f "${file}" ]; then
				file="${file/com.android.runtime/com.android.runtime.debug}"
			fi
		fi
		runcmd cp -pv "${file}" "${arch_to_dir}/usr/${lib}/"
	done

	cpu="${ARC_ANDROID_CPU[${a}]}"
	for f in crtbegin_static.o crtbegin_dynamic.o crtend.o crtbegin_so.o crtend_so.o; do
		dir="${f%.o}"
		out_name="$f"
		# Special case for crtend which used to be named crtend_android.
		if [[ "${dir}" == "crtend" ]]; then
			dir="crtend_android"
			out_name="crtend_android.o"
		fi

		cpudir="${ANDROID_TREE}/out/soong/.intermediates/bionic/libc/${dir}/android_${arch}_${cpu}"
		absolute_f=$(find "${cpudir}" -name "${f}" | head -n 1)
		if [[ ! -e "${absolute_f}" ]]; then
			echo "${absolute_f} not found, did you make bionic/libc for bertha_x86_64-userdebug" \
                          "and bertha_arm64-userdebug? Aborted."
			exit 1
		fi
		runcmd cp -p "${absolute_f}" "${arch_to_dir}/usr/${lib}/${out_name}"
	done

	### 2. Bionic headers.
	for f in libc; do
		runcmd \
			cp -pPR \
			"${ANDROID_TREE}/bionic/${f}/include"/* \
			"${arch_to_dir}/usr/include/"
	done
	runcmd cp -pP \
		"${ANDROID_TREE}/bionic/libc/upstream-netbsd/android/include/sys/sha1.h" \
		"${arch_to_dir}/usr/include/"

	### 3. Libcxx and Libcxxabi headers.
	CXX_HEADERS_DIR="${arch_to_dir}/usr/include/c++/4.9"
	runcmd cp -pLR \
		"${ANDROID_TREE}/external/libcxx/include/"* \
		"${CXX_HEADERS_DIR}/"

	# This currently has a duplicate (__cxxabi_config.h) but the content is same.
	runcmd cp -pLR \
		"${ANDROID_TREE}/external/libcxxabi/include/"* \
		"${CXX_HEADERS_DIR}/"

	### 4.1 Linux headers.
	for f in linux asm-generic drm misc mtd rdma scsi sound video xen; do
		runcmd cp -pPR \
			"${ANDROID_TREE}/bionic/libc/kernel/uapi/${f}" \
			"${arch_to_dir}/usr/include/"
	done
	runcmd cp -pPR \
		"${ANDROID_TREE}/bionic/libc/kernel/android/uapi/linux" \
		"${arch_to_dir}/usr/include/"

	### 4.2 Linux kernel assembly.
	if [[ "${ARC_ARCH_UAPI[${a}]}" == "x86" ]]; then
		# x86 is able to use common asm headers
		asm_target="${arch_to_dir}/usr/include/asm/"
	else
		# arm and arm64 need different asm headers
		asm_target="${arch_to_dir}/usr/include/arch-${ARC_ARCH_UAPI[${a}]}/include/asm/"
	fi
	runcmd mkdir -p "${asm_target}"
	runcmd cp -pPR \
		"${ANDROID_TREE}/bionic/libc/kernel/uapi/asm-${ARC_ARCH_UAPI[${a}]}/asm"/* \
		"${asm_target}"

	### 4.3a Other include directories
	INCLUDE_DIRS=(
		"frameworks/av/media/ndk/include/media"
		"frameworks/native/include/android"
		"frameworks/native/include/ui"
		"frameworks/native/libs/arect/include/android"
		"frameworks/native/libs/nativebase/include/nativebase"
		"frameworks/native/libs/nativewindow/include/android"
		"frameworks/native/libs/nativewindow/include/apex"
		"frameworks/native/libs/nativewindow/include/system"
		"frameworks/native/libs/nativewindow/include/vndk"
		"frameworks/native/vulkan/include/hardware"
		"frameworks/native/vulkan/include/vulkan"
		"hardware/libhardware/include/hardware"
		"system/libbase/include/android-base"
		"system/unwinding/libbacktrace/include/backtrace"
		"system/core/include/cutils"
		"system/logging/liblog/include/log"
		"system/core/include/system"
		"system/core/include/utils"
		"system/logging/liblog/include/android"
		"system/core/libsync/include/android"
		"system/core/libsync/include/ndk"
		"system/core/libsync/include/sync"
	)

	for f in "${INCLUDE_DIRS[@]}"; do
		basename="$(basename "${f}")"
		todir="${arch_to_dir}/usr/include/${basename}"
		runcmd mkdir -p "${todir}"
		runcmd cp -pL "${ANDROID_TREE}/${f}"/*.h "${todir}/"
	done

	### 4.4 Expat includes

	runcmd cp -pP \
		"${ANDROID_TREE}/external/expat/lib"/expat*.h \
		"${arch_to_dir}/usr/include/"

	### 4.5 OpenGL includes

	for f in EGL KHR; do
		todir="${arch_to_dir}/usr/include/opengl/include/${f}/"
		runcmd mkdir -p "${todir}"
		runcmd cp -pP \
			"${ANDROID_TREE}/frameworks/native/opengl/include/${f}"/*.h \
			"${todir}"
	done

	### 4.6 zlib includes

	# Do not use -P (those are symlinks)
	runcmd cp -p \
		"${ANDROID_TREE}/external/zlib"/*.h \
		"${arch_to_dir}/usr/include/"

done

### 5. Copy clang.
# Set this version based on b/160386808#comment2
LLVM_VERSION='14.0.5'
runcmd mkdir -p "${TO_DIR_BASE}/arc-llvm/${LLVM_VERSION}"
runcmd cp -pPr \
	"${ANDROID_TREE}/prebuilts/clang/host/linux-x86/clang-r450784c"/* \
	"${TO_DIR_BASE}/arc-llvm/${LLVM_VERSION}" || echo "Please update clang version manually"

### 6. Do the pack

### 6.1. Ensure permissions are correct to avoid repeating crbug.com/811217
runcmd find "${TO_DIR_BASE}" -type d -exec chmod 755 {} \;
runcmd find "${TO_DIR_BASE}" -type f -executable -exec chmod 755 {} \;
runcmd find "${TO_DIR_BASE}" -type f ! -executable -exec chmod 644 {} \;

### 6.2. Create the tarball with files owned by root:root
PACKET_VERSION=$(date --rfc-3339=date | sed 's/-/./g')
TARBALL="${TO_DIR_BASE}/../arc-toolchain-t-${PACKET_VERSION}.tar.gz"
runcmd tar zcf "${TARBALL}" --owner=root --group=root -C "${TO_DIR_BASE}" .

### 7. Manually upload
echo "Done! Please upload ${TARBALL} manually to: " \
	"https://pantheon.corp.google.com/storage/browser/chromeos-localmirror-private/distfiles/?debugUI=DEVELOPERS"
echo "Or you try this command: gsutil cp -a project-private ${TARBALL} gs://chromeos-localmirror-private/distfiles/"
