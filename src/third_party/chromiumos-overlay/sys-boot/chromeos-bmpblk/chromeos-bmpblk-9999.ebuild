# Copyright 2015 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_PROJECT="chromiumos/platform/bmpblk"
CROS_WORKON_LOCALNAME="../platform/bmpblk"
CROS_WORKON_OUTOFTREE_BUILD="1"

PYTHON_COMPAT=( python3_{6..9} )
inherit cros-workon python-r1

DESCRIPTION="Chrome OS Firmware Bitmap Block"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/bmpblk/"
SRC_URI=""
LICENSE="BSD-Google"
KEYWORDS="~*"
IUSE="physical_presence_power physical_presence_recovery unibuild"
REQUIRED_USE="unibuild"

BDEPEND="${PYTHON_DEPS}
	dev-python/pillow[${PYTHON_USEDEP}]"
DEPEND="chromeos-base/chromeos-config:="

BMPBLK_BUILD_NAMES=()
BMPBLK_BUILD_TARGETS=()

src_prepare() {
	local name
	local bmpblk_target

	while read -r name && read -r bmpblk_target; do
		if [[ -z "${bmpblk_target}" ]]; then
			# Use ${ARCH}-generic to get a fallback configuration.
			bmpblk_target="${ARCH}-generic"
		fi
		BMPBLK_BUILD_NAMES+=("${name}")
		BMPBLK_BUILD_TARGETS+=("${bmpblk_target}")
	done < <(cros_config_host get-firmware-build-combinations bmpblk)

	default

	# if fontconfig's cache is empty, prepare single use cache.
	# That's still faster than having each process (of which there
	# are many) re-scan the fonts
	if find /usr/share/cache/fontconfig -maxdepth 0 -type d -empty \
		-exec false {} +; then

		return
	fi

	local tmpcache=$(emktemp -d)
	cat > "${tmpcache}"/local-conf.xml <<-EOF
		<?xml version="1.0"?>
		<!DOCTYPE fontconfig SYSTEM "fonts.dtd">
		<fontconfig>
		<cachedir>${tmpcache}</cachedir>
		<include>/etc/fonts/fonts.conf</include>
		</fontconfig>
	EOF
	export FONTCONFIG_FILE=${tmpcache}/local-conf.xml
	fc-cache -v
}

# Compile bmpblk for a certain build target.
#   $1: bmpblk build target name
compile_bmpblk() {
	local build_target="$1"

	config_detachable="$(cros_config_host get-key-value \
		/firmware/build-targets bmpblk "${build_target}" \
		/firmware detachable-ui --ignore-unset)" || \
		die "Unable to determine detachable ui config for ${build_target}"
	if [[ "${config_detachable}" == "True" ]] ; then
		export DETACHABLE=1
	fi

	recovery_input="$(cros_config_host get-firmware-recovery-input bmpblk "${build_target}")" || \
		die "Unable to determine recovery input for ${build_target}"
	if [[ -n "${recovery_input}" ]] ; then
		einfo "Using cros_config_host to configure recovery"
		if [[ "${recovery_input}" == "POWER_BUTTON" ]] ; then
			export PHYSICAL_PRESENCE="power"
		elif [[ "${recovery_input}" == "RECOVERY_BUTTON" ]] ; then
			export PHYSICAL_PRESENCE="recovery"
		else
			export PHYSICAL_PRESENCE="keyboard"
		fi
	else
		# TODO(b/229906790) Remove this once USE flag support not longer needed
		einfo "Recovery input method not found in config. Reverting to deprecated use flags"
		if use physical_presence_power ; then
			export PHYSICAL_PRESENCE="power"
		elif use physical_presence_recovery ; then
			export PHYSICAL_PRESENCE="recovery"
		else
			export PHYSICAL_PRESENCE="keyboard"
		fi
	fi

	emake OUTPUT="${WORKDIR}" BOARD="${build_target}" || \
		die "Unable to compile bmpblk for ${build_target}."
	emake OUTPUT="${WORKDIR}/${build_target}" ARCHIVER="/usr/bin/archive" archive || \
		die "Unable to archive bmpblk for ${build_target}."
	if [[ "${build_target}" == "${ARCH}-generic" ]]; then
		printf "1" > "${WORKDIR}/${build_target}/vbgfx_not_scaled"
	fi
}

src_compile() {
	local build_target

	for build_target in "${BMPBLK_BUILD_TARGETS[@]}"; do
		# Check we haven't already compiled this target.
		if [[ -e "${WORKDIR}/${build_target}" ]]; then
			continue
		fi
		compile_bmpblk "${build_target}"
	done
}

doins_if_exist() {
	local f
	for f in "$@"; do
		if [[ -r "${f}" ]]; then
			doins "${f}"
		fi
	done
}

# Compile bmpblk for a certain build target.
#   $1: build combination name
#   $2: bmpblk build target name
install_bmpblk() {
	local build_combination="$1"
	local build_target="$2"

	# Most bitmaps need to reside in the RO CBFS only. Many boards do
	# not have enough space in the RW CBFS regions to contain all
	# image files.
	insinto "/firmware/cbfs-ro-compress/${build_combination}"
	# These files aren't necessary for debug builds. When these files
	# are missing, Depthcharge will render text-only screens. They look
	# obviously not ready for release.
	doins_if_exist "${WORKDIR}/${build_target}"/vbgfx.bin
	doins_if_exist "${WORKDIR}/${build_target}"/locales
	doins_if_exist "${WORKDIR}/${build_target}"/locale/ro/locale_*.bin
	doins_if_exist "${WORKDIR}/${build_target}"/font.bin
	# This flag tells the firmware_Bmpblk test to flag this build as
	# not ready for release.
	doins_if_exist "${WORKDIR}/${build_target}"/vbgfx_not_scaled

	# However, if specific bitmaps need to be updated via RW update,
	# we should also install here.
	insinto "/firmware/cbfs-rw-compress-override/${build_combination}"
	doins_if_exist "${WORKDIR}/${build_target}"/locale/rw/rw_locale_*.bin
}

src_install() {
	local i
	local name
	local target

	for i in "${!BMPBLK_BUILD_TARGETS[@]}"; do
		name="${BMPBLK_BUILD_NAMES[${i}]}"
		target="${BMPBLK_BUILD_TARGETS[${i}]}"

		install_bmpblk "${name}" "${target}"
	done
}
