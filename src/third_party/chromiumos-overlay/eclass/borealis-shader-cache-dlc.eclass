# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# @ECLASS: borealis-shader-cache-dlc.eclass
# @MAINTAINER:
# g/borealis-team, endlesspring@chromium.org, davidriley@chromium.org
# @BUGREPORTS:
# Please report bugs via
# https://issuetracker.google.com/issues/new?component=1149788
# and CC endlesspring@chromium.org
# @VCSURL: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/eclass/@ECLASS@
# @BLURB: helper eclass for building Borealis shader cache DLC
# @DESCRIPTION:
# Shader cache cannot be crowdsourced in ChromeOS in Steam due to privacy
# and security reasons. Hence, we build and distribute shader cache to users
# via DLC.

if [[ -z "${_ECLASS_BOREALIS_SHADER_CACHE_DLC}" ]]; then

# Multiple inclusion protection.
_ECLASS_BOREALIS_SHADER_CACHE_DLC=1

# We use ESYSROOT (EAPI 7 onwards) to get dependency artifacts.
case ${EAPI} in
[0-6]) die "${ECLASS}: EAPI ${EAPI} not supported" ;;
*) ;;
esac

# @ECLASS-VARIABLE: MESA_BUILD_ID
# @PRE_INHERIT
# @DESCRIPTION:
# Mesa GNU build ID to fetch precompiled cache for.

# @ECLASS-VARIABLE: DEVICE_ID
# @PRE_INHERIT
# @DESCRIPTION:
# GPU Device ID to fetch precompiled cache for.

if [[ -z "${MESA_BUILD_ID}" ]]; then
	die "MESA_BUILD_ID must be defined by dlc"
elif [[ -z "${DEVICE_ID}" ]]; then
	die "DEVICE_ID must be defined by dlc"
fi

# @ECLASS-VARIABLE: GS_BUCKET
# @DESCRIPTION:
# GS bucket path to fetch precompiled cache from.
: "${GS_BUCKET:=chromeos-localmirror/distfiles/borealis/shader-cache-dlc}"
# @ECLASS-VARIABLE: MESA_DIR
# @DESCRIPTION:
# Directory name created by Mesa for precompiled cache.
: "${MESA_DIR:=mesa_shader_cache_sf}"
# @ECLASS-VARIABLE: FILE_SUFFIX
# @DESCRIPTION:
# DLC file name suffix inside the bucket before '.tar.gz'. This allows us to
# add tags like '-V<number>' or '-T<timestamp>' that provides us flexibility.
# For example:
# - Timestamp our files so that we don't 'uprev' but create new DLCs instead,
#   preventing us from accidentialy breaking builds by mistakes.
# - Upload V2 of the file if they were incorrect and uprev.
: "${FILE_SUFFIX:=}"
# @ECLASS-VARIABLE: DLC_PREALLOC_GB
# @DESCRIPTION:
# Shader cache DLC's prealloc size in gigabytes. This is by default 2GB, but
# some games require higher value. This should be evaluated per-game basis
# and set when first the shader cache DLC is first created for the game (and
# never change).
: "${DLC_PREALLOC_GB:=2}"
# @ECLASS-VARIABLE: BOREALIS_SHADER_CACHE_USED_IN_TESTS
# @DESCRIPTION:
# If set to "true", this shader cache DLC is preloaded for test images:
#   DLC_PRELOAD=true
: "${BOREALIS_SHADER_CACHE_USED_IN_TESTS:="false"}"

inherit dlc

# Expected DLC name format:
#  borealis-shader-cache-<GAME_ID>-dlc-<VARIANT>-id-<SHADER_IDENTITY>
if [[ ! "${PN}" =~ ^borealis-shader-cache-[0-9]+-dlc-[a-z]+-id-[a-z]+$ ]]; then
	eerror "${PN} does not match expected name format:"
	eerror "  borealis-shader-cache-<GAME_ID>-dlc-<VARIANT>-id-<SHADER_IDENTITY>"
	die "Unexpected DLC package name format"
fi
GAME_ID="$(ver_cut 4 "${PN}")"
VARIANT="$(ver_cut 6 "${PN}")"
SHADER_IDENTITY="$(ver_cut 8 "${PN}")"

# DLC_ID should be identity-less, so that shadercached does not have to figure
# out the identity (ebuild deps should distribute the right ones).
DLC_ID="${PN%-id*}"

DESCRIPTION="Borealis shader cache for game ${GAME_ID}, variant ${SHADER_IDENTITY}-${VARIANT}"
HOMEPAGE="https://www.chromium.org/chromium-os/steam-on-chromeos/"

RESTRICT="mirror"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

# It is expected that borealis_host and dlc are set as global use flags.
IUSE="borealis_host dlc"
REQUIRED_USE="borealis_host dlc"

DEPEND="virtual/vulkan-icd"

RDEPEND="${DEPEND}"

# Default 2GB = 2 x 512 x 512 x 4KB blocks.
DLC_PREALLOC_BLOCKS="$((DLC_PREALLOC_GB * 512 * 512))"

DLC_PRELOAD="${BOREALIS_SHADER_CACHE_USED_IN_TESTS}"

# We plan have O(1000) production DLCs.
DLC_SCALED=true

SRC_URI="gs://${GS_BUCKET}/${GAME_ID}/${GAME_ID}-${SHADER_IDENTITY}-${DEVICE_ID}-${MESA_BUILD_ID}${FILE_SUFFIX}.tar.gz"
S="${WORKDIR}"

src_install() {
	# cwd is "${S}", default src_unpack unpacked the tarball at cwd.

	# We don't need further paths inside the DLC, kabuto has packaged up
	# the right path for us.
	local dlc_path="$(dlc_add_path /)"
	into "${dlc_path}"
	insinto "${dlc_path}"
	exeinto "${dlc_path}"

	# If the mesa hash mismatch, there is no point building the DLC since
	# end-users won't be able to use them. Fail gracefully by creating an 'empty'
	# dlc with dlc_build_error file.
	local lib_dir="${ESYSROOT}/usr/$(get_libdir)"
	# TODO(b/278626818): Reliably detect which mesa variant was built during
	# borealis shader cache dlc builds.
	local lib_file_name="libvulkan_radeon.so"
	if [[ -f "${lib_dir}/libvulkan_intel.so" ]]; then
		lib_file_name="libvulkan_intel.so"
	fi
	# The package's Mesa build id hash is the pinned value.
	local pkg_mesa_build_id="${MESA_BUILD_ID}"
	local local_mesa_build_id="$(readelf -n "${lib_dir}/${lib_file_name}" 2>/dev/null | awk '/Build ID:/{ print $NF; exit }')"
	if [[ "${pkg_mesa_build_id}" != "${local_mesa_build_id}" ]]; then
		# If Kabuto automation failed to build the correct shader cache, still allow
		# the image to be built but do not include the DLC.
		eerror "${PN} (${DEVICE_ID}) DLC Mesa hash mismatch, empty DLC created"
		eerror "  local:    ${local_mesa_build_id}"
		eerror "  packaged: ${pkg_mesa_build_id}"
	else
		doins -r "${MESA_DIR}"
	fi

	dlc_src_install
}

fi
