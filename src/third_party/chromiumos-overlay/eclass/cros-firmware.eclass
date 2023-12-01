# Copyright 2013 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Original Author: The ChromiumOS Authors <chromium-os-dev@chromium.org>
# Purpose: Generate shell script containing firmware update bundle.
#

if [[ -z "${EBUILD}" ]]; then
	die "This eclass needs EBUILD environment variable."
fi

PYTHON_COMPAT=( python3_{8..9} )
unset PYTHON_COMPAT_OVERRIDE

inherit cros-workon cros-unibuild cros-constants python-any-r1

# @ECLASS-VARIABLE: CROS_FIRMWARE_BCS_OVERLAY
# @DESCRIPTION: (Optional) Name of board overlay on Binary Component Server
: "${CROS_FIRMWARE_BCS_OVERLAY:=$(
	# EBUILD will be the full path to the ebuild file.
	IFS="/"
	# shellcheck disable=SC2046,SC2086
	set -- ${EBUILD}
	# Chop off the ebuild, the $PN dir, and the $CATEGORY dir.
	n=$(( $# - 3 ))
	echo "${!n}"
)}"

# @ECLASS-VARIABLE: CROS_FIRMWARE_MAIN_IMAGE
# @DESCRIPTION: (Optional) Location of system firmware (BIOS) image
: "${CROS_FIRMWARE_MAIN_IMAGE:=}"

# @ECLASS-VARIABLE: CROS_FIRMWARE_MAIN_RW_IMAGE
# @DESCRIPTION: (Optional) Location of RW system firmware image
: "${CROS_FIRMWARE_MAIN_RW_IMAGE:=}"

# @ECLASS-VARIABLE: CROS_FIRMWARE_EC_IMAGE
# @DESCRIPTION: (Optional) Location of EC firmware image
: "${CROS_FIRMWARE_EC_IMAGE:=}"

# Check for EAPI 2+
case "${EAPI:-0}" in
0|1) die "unsupported EAPI (${EAPI}) in eclass (${ECLASS})" ;;
*) ;;
esac

# $board-overlay/make.conf may contain these flags to always create "firmware
# from source".
IUSE="bootimage cros_ec cros_ish tot_firmware unibuild zephyr_ec"

# "futility update" is needed when building and running updater package.
COMMON_DEPEND="
	chromeos-base/vboot_reference
	unibuild? (
		chromeos-base/chromeos-config
	)
"

# Apply common dependency.
DEPEND="${COMMON_DEPEND}"
RDEPEND="${COMMON_DEPEND}"

# Dependency for run time only (invoked by `futility update`).
RDEPEND+="
	chromeos-base/vpd
	sys-apps/flashrom
	cros_ish? ( chromeos-base/chromeos-ish )
	"
# Maintenance note:  The factory install shim downloads and executes
# the firmware updater.  Consequently, run time dependencies for the
# updater are also run time dependencies for the install shim.
#
# The contents of RDEPEND must also be present in the
# chromeos-base/factory_installer ebuild in PROVIDED_DEPEND.  If you make any
# change to the list above, you may need to make a matching change in the
# factory_installer ebuild.

# Dependency to build firmware from source (build phase only).
DEPEND+="
	bootimage? ( sys-boot/chromeos-bootimage )
	cros_ec? ( chromeos-base/chromeos-ec )
	zephyr_ec? ( chromeos-base/chromeos-zephyr )
	"

RESTRICT="mirror"

# Local variables.

UPDATE_SCRIPT="chromeos-firmwareupdate"
FW_IMAGE_LOCATION=""
FW_RW_IMAGE_LOCATION=""
EC_IMAGE_LOCATION=""

# Output the URI associated with a file to download. This can be added to the
# SRC_URI variable.
# Portage will then take care of downloading these files before the src_unpack
# phase starts.
# Args
#   $1: Input file to read, with prefix (e.g. "bcs://Reef.9042.72.0.tbz2")
#   $2: Overlay name (e.g. "reef-private")
#   $3: Board directory containing file (e.g. "chromeos-firmware-reef")
_add_uri() {
	local input="$1"
	local overlay="$2"
	local board="$3"
	local protocol="${input%%://*}"
	local uri="${input#*://}"
	local user="bcs-${overlay#variant-*-}"
	local bcs_url="gs://chromeos-binaries/HOME/${user}/overlay-${overlay}"

	# Input without ${protocol} are local files (ex, ${FILESDIR}/file).
	case "${protocol}" in
		bcs)
			echo "${bcs_url}/${CATEGORY}/${board}/${uri}"
			;;
		http|https|gs)
			echo "${input}"
			;;
	esac
}

# Output a URL for the given firmware variable.
# This calls _add_uri() after setting up the required parameters.
#  $1: Variable containing the required filename (e.g. "FW_IMAGE_LOCATION")
#  $2: src uri (unused)
_add_source() {
	local var="$1"
	local overlay="${CROS_FIRMWARE_BCS_OVERLAY#overlay-}"
	local input="${!var}"

	_add_uri "${input}" "${overlay}" "${PN}"
}

_unpack_archive() {
	local var="$1"
	local input="${!var}"
	local archive="${input##*/}"
	local folder="${S}/.dist/${archive}"

	# Remote source files (bcs://, http://, ...) are downloaded into
	# ${DISTDIR}, which is the default location for command 'unpack'.
	# For any other files (ex, ${FILESDIR}/file), use complete file path.
	local unpack_name="${input}"
	if [[ "${unpack_name}" =~ "://" ]]; then
		input="${DISTDIR}/${archive}"
		unpack_name="${archive}"
	fi

	case "${input##*.}" in
		tar|tbz2|tbz|bz|gz|tgz|zip|xz) ;;
		*)
			eval "${var}='${input}'"
			return
			;;
	esac

	mkdir -p "${folder}" || die "Not able to create ${folder}"
	(cd "${folder}" && unpack "${unpack_name}") ||
		die "Failed to unpack ${unpack_name}."
	local contents=()
	mapfile -d '' contents < <(find "${folder}" -mindepth 1 -maxdepth 1 -print0)
	if [[ ${#contents[@]} -gt 1 ]]; then
		# Currently we can only serve one file (or directory).
		ewarn "WARNING: package ${input} contains multiple files."
	fi
	eval "${var}='${contents[0]}'"
}

cros-firmware_src_unpack() {
	case "${EAPI:-0}" in
	1|2|3|4)
		use unibuild &&
			die "Update your EAPI version to 5 to use unibuild"
		;;
	esac

	cros-workon_src_unpack
	local i

	if ! use unibuild; then
		for i in {FW,FW_RW,EC,PD}_IMAGE_LOCATION; do
			_unpack_archive ${i}
		done
	fi
}

# Add members to an array.
#  $1: Array variable to append to.
#  $2..: Arguments to append, each to be put in its own array element.
_append_var() {
	local var="$1"
	shift
	eval "${var}+=( \"\$@\" )"
}

# Add a string command-line flag with its value to an array.
# If the value is empty then this function does nothing.
#  $1: Array variable to append to.
#  $2: Flag (e.g. "-b").
#  $3: Value (e.g. "bios.bin").
_add_param() {
	local var="$1"
	local flag="$2"
	local value="$3"

	[[ -n "${value}" ]] && _append_var "${var}" "${flag}" "${value}"
}

# Add a string command-line flag with its file argument to an array.
# If the file does not exists then this function does nothing.
#  $1: Array variable to append to.
#  $2: Flag (e.g. "-b").
#  $3: File path (e.g. "bios.bin").
_add_file_param() {
	local var="$1"
	local flag="$2"
	local value="$3"

	[[ -e "${value}" ]] && _append_var "${var}" "${flag}" "${value}"
}

# Add a boolean command-line flag to an array.
# If the value is empty then this function does nothing, otherwise it
# appends the flag.
#  $1: Array variable to append to.
#  $2: Flag (e.g. "--create_bios_rw_image").
#  $3: Value (e.g. "${IMAGE}"), only used to determine flag presence.
_add_bool_param() {
	local var="$1"
	local flag="$2"
	local value="$3"

	[[ -n "${value}" ]] && _append_var "${var}" "${flag}"
}

cros-firmware_src_compile() {
	local root="${SYSROOT%/}"
	local local_root="${root}/firmware"

	# We need lddtree from chromite.
	export PATH="${CHROMITE_BIN_DIR}:${PATH}"

	# For the official BCS firmware updater.
	local image_cmd=()
	local ext_cmd=()
	if use unibuild; then
		_add_param ext_cmd -i "${DISTDIR}"
		_add_param ext_cmd -c "${root}${UNIBOARD_YAML_CONFIG}"
	else
		ext_cmd+=(--legacy)
		_add_param image_cmd -b "${FW_IMAGE_LOCATION}"
		_add_param image_cmd -e "${EC_IMAGE_LOCATION}"
		_add_param image_cmd -w "${FW_RW_IMAGE_LOCATION}"
	fi

	# For the local firmware updater.
	local local_image_cmd=()
	local local_ext_cmd=("${ext_cmd[@]}")
	if use unibuild; then
		local_ext_cmd+=(--local)
		# Tell pack_firmware.py where to find the files.
		# 'BUILD_TARGET' will be replaced with the build-targets config
		# from the unified build config file. Since these path do not
		# exist, we can't use _add_file_param.
		_add_param local_image_cmd \
			-b "${local_root}/image-BUILD_TARGET.bin"
		local local_dir="${local_root}/BUILD_TARGET"
		if use zephyr_ec; then
			_add_param local_image_cmd -e "${local_dir}/ec.bin"
		elif use cros_ec; then
			_add_param local_image_cmd -e "${local_dir}/ec.bin"
		fi
	else
		_add_param local_image_cmd -b "${local_root}/image.bin"
		_add_file_param local_image_cmd -e "${local_root}/ec.bin"
	fi

	if use tot_firmware; then
		einfo "tot_firmware is enabled, skipping BCS firmware updater"
	elif [ ${#image_cmd[@]} -eq 0 ] && ! use unibuild; then
		# Create an empty update script for the generic case
		# (no need to update)
		einfo "Building empty firmware update script"
		echo -n >"${UPDATE_SCRIPT}"
	else
		einfo "Build ${BOARD_USE} BCS firmware updater to ${UPDATE_SCRIPT}:" \
			"${image_cmd[*]} ${ext_cmd[*]}"
		"${EPYTHON}" ./pack_firmware.py -o "${UPDATE_SCRIPT}" \
			"${image_cmd[@]}" "${ext_cmd[@]}" ||
			die "Cannot pack firmware updater."
	fi

	# To create local updater, bootimage must be enabled.
	if ! use bootimage; then
		if use cros_ec; then
			# TODO(hungte) Deal with a platform that has
			# only EC and no BIOS, which is usually
			# incorrect configuration.  We only warn here to
			# allow for BCS based firmware to still generate
			# a proper chromeos-firmwareupdate update
			# script.
			ewarn "WARNING: platform has no local BIOS."
			ewarn "EC-only is not supported."
			ewarn "Not generating a local updater script."
		fi
		return
	fi

	# If the updater does not exist, fall back to local updater.
	if [[ ! -f "${UPDATE_SCRIPT}" ]]; then
		einfo "Build ${BOARD_USE} local updater to ${UPDATE_SCRIPT}:" \
			"${local_image_cmd[*]} ${local_ext_cmd[*]}"
		"${EPYTHON}" ./pack_firmware.py -o "${UPDATE_SCRIPT}" \
			"${local_image_cmd[@]}" "${local_ext_cmd[@]}" ||
			die "Cannot pack local firmware updater."
		if ! use tot_firmware; then
			ewarn "No BCS updater created; using local updater"
		fi
	fi

	# Create local signer config
	if use unibuild && use bootimage; then
		./local_signer.py -c "${root}${UNIBOARD_YAML_CONFIG}" \
			-r "${root}" || die "Cannot create local signer config."
	fi
}

cros-firmware_src_install() {
	# install updaters for firmware-from-source archive.
	if use tot_firmware && use bootimage; then
		exeinto /firmware
		newexe "${UPDATE_SCRIPT}" updater.sh
	fi

	# install local signer config
	if use unibuild && use bootimage; then
		insinto /firmware
		doins signer_config.csv
	fi

	# skip anything else if no main updater program.
	if [[ ! -s "${UPDATE_SCRIPT}" ]]; then
		return
	fi

	# install the main updater program if available.
	dosbin "${UPDATE_SCRIPT}"

	dosbin "${S}"/sbin/*
	# install ${FILESDIR}/sbin/* (usually board-setgoodfirmware).
	if [[ -d "${FILESDIR}"/sbin ]]; then
		dosbin "${FILESDIR}"/sbin/*
	fi
}

# Trigger tests on each firmware build. While there is a chromeos-firmware-1
# ebuild which could be used to run these tests on the host, it doesn't do
# anything at present, and the usual workflow is to build firmware for a
# particular board. This way it is more likely that people will see any
# failures in their normal workflow.
cros-firmware_src_test() {
	local fname

	# We need lddtree from chromite.
	export PATH="${CHROMITE_BIN_DIR}:${PATH}"

	for fname in *test.py; do
		einfo "Running tests in ${fname}"
		"${EPYTHON}" "./${fname}" || die "Tests failed at ${fname} (py3)"
	done
}

# @FUNCTION: _expand_list
# @USAGE <var> <ifs> <string>
# @DESCRIPTION:
# Internal function to expand a string (separated by ifs) into bash array.
_expand_list() {
	local var="$1" ifs="$2"
	IFS="${ifs}" read -r -a "${var?}" <<<"${*:3}"
}

# @FUNCTION: cros-firmware_setup_source
# @DESCRIPTION:
# Configures all firmware binary source files to SRC_URI, and updates local
# destination mapping (*_LOCATION). Must be invoked after CROS_FIRMWARE_*_IMAGE
# are set. This also reads the master configuration if available and adds files
# from there for unified builds. The result is something like:
#
# SRC_URI="!unibuild? ( file1 file2 ) unibuild? ( file3 file3 )"
#
# With this we will end up downloading either the unibuild files or the
# !unibuild files, depending on the 'unibuild' USE flag.
cros-firmware_setup_source() {
	# This function is called before FILESDIR is set so figure it out from
	# the ebuild filename.
	local basedir="${EBUILD%/*}"
	local files="${basedir}/files"
	local i srcf

	# Get list of all srcuri files (if any).
	# The filenames must include 'srcuris'.
	# Builtin compgen is used since it returns an empty
	# list (instead of the regexp) if there are no matches.
	mapfile -t srcf <<< "$(compgen -G "${files}/*srcuris*")"
	if [[ -n "${srcf[0]}" ]]; then
		local uris=()
		local u
		# We can't use any external commands, so de-dup by
		# checking for an entry before adding to the list.
		for i in "${srcf[@]}"; do
			mapfile -t onefile < "${i}"
			for u in "${onefile[@]}"; do
				# The extra quoting is to avoid the shellcheck warning.
				if [[ ! " ${uris[*]} " =~ " ""${u}"" " ]]; then
					uris+=("${u}")
				fi
			done
		done
		SRC_URI+=" ${uris[*]}"
	else
		local uris
		FW_IMAGE_LOCATION="${CROS_FIRMWARE_MAIN_IMAGE}"
		FW_RW_IMAGE_LOCATION="${CROS_FIRMWARE_MAIN_RW_IMAGE}"
		EC_IMAGE_LOCATION="${CROS_FIRMWARE_EC_IMAGE}"

		# Add these files for use if unibuild is not set.
		for i in {FW,FW_RW,EC,PD}_IMAGE_LOCATION; do
			uris+=" $(_add_source ${i})"
		done

		if [[ -n "${uris// }" ]]; then
			SRC_URI+="!unibuild? ( ${uris} ) "
		fi
	fi

	# No sources required if only building firmware from ToT.
	if [[ -n "${SRC_URI}" ]]; then
		SRC_URI="!tot_firmware? ( ${SRC_URI} )"
	fi
}

# If "inherit cros-firmware" appears at end of ebuild file, build source URI
# automatically. Otherwise, you have to put an explicit call to
# "cros-firmware_setup_source" at end of ebuild file.
[[ -n "${CROS_FIRMWARE_MAIN_IMAGE}" ]] && cros-firmware_setup_source

EXPORT_FUNCTIONS src_unpack src_compile src_install src_test
