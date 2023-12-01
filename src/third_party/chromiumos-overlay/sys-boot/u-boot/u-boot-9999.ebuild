# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_PROJECT=("chromiumos/third_party/u-boot" "chromiumos/platform/vboot_reference")
CROS_WORKON_LOCALNAME=("u-boot/files" "../platform/vboot_reference")
CROS_WORKON_EGIT_BRANCH=("chromeos-v2020.01" "master")
VBOOT_REFERENCE_DESTDIR="${S}/vboot_reference"
CROS_WORKON_DESTDIR=("${S}" "${VBOOT_REFERENCE_DESTDIR}")

inherit toolchain-funcs flag-o-matic cros-workon cros-unibuild cros-sanitizers

DESCRIPTION="Das U-Boot boot loader"
HOMEPAGE="http://www.denx.de/wiki/U-Boot"

LICENSE="GPL-2"
KEYWORDS="~*"
IUSE="dev sandbox vboot werror"

DEPEND="sandbox? ( media-libs/libsdl:= )"

RDEPEND="${DEPEND}
	chromeos-base/u-boot-scripts
	!!sys-boot/chromeos-u-boot
	"

UB_BUILD_DIR="build"

# To build for sandbox, check out the source:
#
#	cd src/third_party/u-boot/files
#	git remote add dm git://git.denx.de/u-boot-dm.git
#	git checkout dm/cros-working
#
# Then:
#	cros_workon --host start u-boot
#	USE="sandbox vboot" sudo -D emerge u-boot
#	sudo chmod a+rw /firmware/image-u-boot.bin
#	ln -s /firmware/image-u-boot.bin spi.bin
#	/firmware/u-boot-tpl -d /firmware/u-boot.dtb.out \
#		-L6 -c "host bind 0 $HOME/trunk/src/build/images/cheza/latest/chromiumos_image.bin; vboot go auto" -l
#
# See that it launches vboot (although without a functioning display) and
# Ctrl-D attempts to boot the kernel.
#
# From outside the chroot:
#
#	ln -s  ${CROS}/chroot/firmware/image-u-boot.bin spi.bin
#	${CROS}/chroot/firmware/u-boot-tpl -d \
#		${CROS}/chroot/firmware/u-boot.dtb.out -L6 \
#		-c "host bind 0 ${CROS}/src/build/images/cheza/latest/chromiumos_image.bin; vboot go auto" -l
#
# Outside the chroot the display and sound function correctly.

# @FUNCTION: get_current_u_boot_config
# @DESCRIPTION:
# Finds the config for the current board by checking the master configuration.
# The default is to use 'coreboot'.
get_current_u_boot_config() {
	local config

	if use sandbox; then
		config=chromeos_sandbox
	else
		config="$(cros_config_host get-firmware-build-targets u-boot)"
	fi
	echo "${config:-coreboot}"
}

umake() {
	# Add `ARCH=` to reset ARCH env and let U-Boot choose it.
	ARCH= emake "${COMMON_MAKE_FLAGS[@]}" "$@"
}

src_configure() {
	sanitizers-setup-env

	local config

	export LDFLAGS=$(raw-ldflags)
	tc-export BUILD_CC

	config="$(get_current_u_boot_config)"
	[[ -n "${config}" ]] || die "No U-Boot config selected"
	elog "Using U-Boot config: ${config}"

	# Firmware related binaries are compiled with 32-bit toolchain
	# on 64-bit platforms
	if ! use cros_host && [[ ${CHOST} == x86_64-* ]]; then
		CROSS_PREFIX="i686-cros-linux-gnu-"
	else
		CROSS_PREFIX="${CHOST}-"
	fi

	COMMON_MAKE_FLAGS=(
		"CROSS_COMPILE=${CROSS_PREFIX}"
		DEV_TREE_SEPARATE=1
		"HOSTCC=${BUILD_CC}"
		HOSTSTRIP=true
		QEMU_ARCH=
	)
	if use vboot; then
		COMMON_MAKE_FLAGS+=(
			"VBOOT_SOURCE=${VBOOT_REFERENCE_DESTDIR}"
			VBOOT_DEBUG=1
		)
	fi
	if use dev; then
		# Avoid hiding the errors and warnings
		COMMON_MAKE_FLAGS+=(
			-s
			QUIET=1
		)
	else
		COMMON_MAKE_FLAGS+=(
			-k
		)
	fi
	use werror && COMMON_MAKE_FLAGS+=( WERROR=y )

	BUILD_FLAGS=(
		"O=${UB_BUILD_DIR}"
	)

	umake "${BUILD_FLAGS[@]}" distclean
	umake "${BUILD_FLAGS[@]}" "${config}_defconfig"
}

src_compile() {
	umake "${BUILD_FLAGS[@]}" all
}

src_install() {
	local inst_dir="/firmware"
	local files_to_copy=(
		System.map
		u-boot.bin
		u-boot.dtb
		u-boot.dtb.out
		u-boot.img
	)
	local exec_to_copy=(
		u-boot
		spl/u-boot-spl
		tpl/u-boot-tpl
	)
	local f

	if ! use sandbox; then
		files_to_copy+=( "${exec_to_copy[@]}" )
		exec_to_copy=()
	fi

	insinto "${inst_dir}"
	exeinto "${inst_dir}"

	for f in "${files_to_copy[@]}"; do
		[[ -f "${UB_BUILD_DIR}/${f}" ]] &&
			doins "${f/#/${UB_BUILD_DIR}/}"
	done

	for f in "${exec_to_copy[@]}"; do
		[[ -f "${UB_BUILD_DIR}/${f}" ]] &&
			doexe "${f/#/${UB_BUILD_DIR}/}"
	done

	# Install the full image needed by sandbox.
	if use vboot; then
		newins "${UB_BUILD_DIR}/image.bin" image-u-boot.bin
	fi

	insinto "${inst_dir}/dtb"
	doins "${UB_BUILD_DIR}/dts/"*.dtb
}
