# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# Check for EAPI 5+
case "${EAPI:-0}" in
5|6|7) ;;
*) die "unsupported EAPI (${EAPI}) in eclass (${ECLASS})" ;;
esac

# In order to rebuild packages when config changes happen, we need a
# subslot dependency on on the bsp packages that provide the actual
# configs.  We do this here instead of in the ebuilds so that we don't
# pollute the tree with this complex dependency syntax.
case "${CATEGORY}/${PN}" in
	# Can't depend on ourselves, special case this away.
	chromeos-base/chromeos-config-bsp* ) ;;
	* )
		IUSE="
			has_chromeos_config_bsp
			has_chromeos_config_bsp_private
			has_chromeos_config_bsp_baseboard
			has_chromeos_config_bsp_baseboard_private
		"
		DEPEND="
			has_chromeos_config_bsp? ( chromeos-base/chromeos-config-bsp:= )
			has_chromeos_config_bsp_private? (
				chromeos-base/chromeos-config-bsp-private:=
			)
			has_chromeos_config_bsp_baseboard? (
				chromeos-base/chromeos-config-bsp-baseboard:=
			)
			has_chromeos_config_bsp_baseboard_private? (
				chromeos-base/chromeos-config-bsp-baseboard-private:=
			)
		"
		# Again, can't depend on ourselves.
		if [[ "${CATEGORY}/${PN}" != "chromeos-base/chromeos-config" ]]; then
			IUSE+=" unibuild "
			DEPEND+="
				unibuild? ( chromeos-base/chromeos-config:= )
			"
		fi
		RDEPEND="${DEPEND}"

		# Let's also provide an environment variable that
		# cros_config_host can use, that way it can validate we got
		# the proper dependencies to use it.
		export CROS_UNIBUILD_ECLASS=1
esac

# Additionally, if we support EAPI=7, let's be proper and add a
# BDEPEND.
case "${EAPI}" in
	7 )
		BDEPEND="chromeos-base/chromeos-config-host:="
		;;
esac

# @ECLASS-VARIABLE: UNIBOARD_CROS_CONFIG_DIR
# @DESCRIPTION:
#  This is the installation directory of cros-config data.
UNIBOARD_CROS_CONFIG_DIR="/usr/share/chromeos-config"

# @ECLASS-VARIABLE: UNIBOARD_JSON_INSTALL_PATH
# @DESCRIPTION:
#  This is the filename of the master configuration for use with doins.
UNIBOARD_JSON_INSTALL_PATH="${UNIBOARD_CROS_CONFIG_DIR}/config.json"

# @ECLASS-VARIABLE: UNIBOARD_YAML_DIR
# @DESCRIPTION:
#  This is the installation directory of the yaml source files.
UNIBOARD_YAML_DIR="${UNIBOARD_CROS_CONFIG_DIR}/yaml"

# @ECLASS-VARIABLE: UNIBOARD_YAML_CONFIG
# @DESCRIPTION:
#  This is the installation path to the YAML source file.
UNIBOARD_YAML_CONFIG="${UNIBOARD_YAML_DIR}/config.yaml"

# @FUNCTION: _find_configs
# @USAGE: <directory> <extension>
# @INTERNAL
# @DESCRIPTION:
# Find .json/.yaml files in a given directory tree.
# Args:
#   $1: Directory to search.
#   $2: Extension to search for (.json or .yaml).
# Returns:
#   Exports a 'files' variable containing the array of files found.
# TODO(gmeinke): rename this to something more generic.
_find_configs() {
	local file

	while read -d $'\0' -r file; do
		files+=( "${file}" )
	done < <(find -H "$1" -name "*$2" -print0)
}

# @FUNCTION: _insert_config_files
# @USAGE: <files array> <output directory>
# @INTERNAL
# @DESCRIPTION:
# Do a newins to the output directory for each file in the input array.
# Args:
#   $1: Files array to insert.
#   $2: Output directory to newins into.
#   $3: prefix to prepend to filename.
# Returns:
#   None.
_insert_config_files() {
	[[ $# -eq 3 ]] || die "${FUNCNAME}: takes three arguments"
	local ins_files=($1)
	local output_dir="$2"
	local prefix="$3"
	if [[ "${#ins_files[@]}" -gt 0 ]]; then
		einfo "Installing ${#ins_files[@]} files to ${output_dir}"
		# Avoid polluting callers with our newins.
		(
			insinto "${output_dir}"
			for f in "${ins_files[@]}"; do
				local dest="${prefix}${f##*/}"
				einfo "Copying ${f} -> ${dest}"
				newins "${f}" "${dest}"
			done
		)
	fi
}

# @FUNCTION: _install_model_files
# @USAGE: [prefix]
# @INTERNAL
# @DESCRIPTION:
# Find .yaml files in a given directory tree.
# Install model files with a given prefix:
# Args:
#   $1: Prefix to use (either "" or "private-")
_install_model_files() {
	[[ $# -eq 1 ]] || die "${FUNCNAME}: takes one arguments"

	local prefix="$1"
	local files

	files=()
	_find_configs "${FILESDIR}" ".yaml"
	_insert_config_files "${files[*]}" "${UNIBOARD_YAML_DIR}" "${prefix}"
}

# @FUNCTION: install_private_model_files
# @USAGE:
# @DESCRIPTION:
# Installs all .yaml files for the current board. This is intended to be called
# from the chromeos-config-<board> private ebuild. The files are named
# "private-<fname>.yaml".
install_private_model_files() {
	[[ $# -eq 0 ]] || die "${FUNCNAME}: takes no arguments"

	_install_model_files "private-"
}

# @FUNCTION: install_model_files
# @USAGE:
# @DESCRIPTION:
# Installs all .yaml files for the current board. This is intended to be called
# from the chromeos-config-<board> public ebuild. The files are named
# "<fname>.yaml".
install_model_files() {
	[[ $# -eq 0 ]] || die "${FUNCNAME}: takes no arguments"

	_install_model_files ""
}

# @FUNCTION: install_generated_config_files
# @USAGE:
# @DESCRIPTION:
# Installs generated JSON payloads and C files for the current board. This is
# intended to be called from the chromeos-config-<board> public and private
# ebuilds.
install_generated_config_files() {
	[[ $# -eq 0 ]] || die "${FUNCNAME[0]}: takes no arguments"

	# Install build config as "config.yaml".
	# Consumers of the payloads expect these names and locations.

	insinto "${UNIBOARD_YAML_DIR}"
	newins "${FILESDIR}/generated/build_config.json" "config.yaml"

	doins "${FILESDIR}/generated/config.c"
}

# @FUNCTION: verify_file_match
# @USAGE: [expected_file] [actual_file]
# @DESCRIPTION:
# Verifies the expected file matches the actual file.
#   $1: Filename of expected file contents
#   $2: Filename of actual file contents
verify_file_match() {
	local expected_file="$1"
	local actual_file="$2"

	einfo "Verifying ${expected_file} matches ${actual_file}"
	local expected_cksum="$(cksum "${expected_file}" | cut -d ' ' -f 1)"
	local actual_cksum="$(cksum "${actual_file}" | cut -d ' ' -f 1)"
	if [[ "${expected_cksum}" -ne "${actual_cksum}" ]]; then
		eerror "Generated file doesn't match expected file. \n" \
			"Generated file is available at: ${actual_file}\n" \
			"If this is an expected change, copy this change to the expected" \
			"$(basename "${expected_file}") file and commit with your CL.\n"
		die
	fi
	einfo "Successfully verified ${expected_file} matches ${actual_file}"
}

# @FUNCTION: _unibuild_common_install
# @USAGE: command [config_file]
# @INTERNAL
# @DESCRIPTION:
# Common installation function.
# Install files from a relative path in FILESDIR to an absolute path in the
# root.
# Args:
#   $1: Command to pass to cros_config_host to get the files
#   $2: (optional) Config file used by cros_config_host
_unibuild_common_install() {
	[[ $# -gt 0 ]] || die "${FUNCNAME}: cros_config_host command required"
	[[ $# -lt 3 ]] || die "${FUNCNAME}: Only optional config file arg allowed"

	local cmd="$1"
	local config_files_path="${FILESDIR}"
	local config="${SYSROOT}${UNIBOARD_YAML_DIR}/config.yaml"
	if [[ $# -gt 1 ]]; then
		config_files_path="."
		config="$2"
	fi
	einfo "unibuild: Installing ${cmd} based on ${config}"
	local source dest origfile
	(cros_config_host -c "${config}" "${cmd}" || die) |
	while read -r source; do
		read -r dest
		einfo "   - ${config_files_path}/${source}"
		insinto "$(dirname "${dest}")"
		# From EAPI4+ symbolic links are not dereferenced when
		# installing, but we want to dereference our links when
		# installing config files. Common config files may be linked
		# in the source directory, but the installed file should not be
		# a link especially since the installed folder structure is
		# different.
		origfile="$(readlink -f "${config_files_path}/${source}")" ||
			die "readlink -f ${config_files_path}/${source} failed"
		newins "${origfile}" "$(basename "${dest}")"
	done
}

# @FUNCTION: _unibuild_install_fw
# @USAGE: [source] [dest] [symlink path]
# @INTERNAL
# @DESCRIPTION:
# Install the firmware and create a symlink for 'request firmware' hotplug.
#   $1: Source filename
#   $2: Destination filename (in /opt/google)
#   $3: Full path to symlink in /lib/firmware
_unibuild_install_fw() {
	local source="$1"
	local dest="$2"
	local symlink="$3"

	elog "   - ${source} with symlink from ${symlink}"
	insinto "$(dirname "${dest}")"
	newins "${source}" "$(basename "${dest}")"
	dosym "${dest}" "${symlink}"
}

# @FUNCTION: _unibuild_install_fw_common
# @USAGE: [cmd] [config_file]
# @INTERNAL
# @DESCRIPTION:
# Install the firmware and create a symlink for the files which query from
# the cros_config_host.
# Args:
#   $1: Command to pass to cros_config_host to get the files
#   $2: (optional) Config file used by cros_config_host
_unibuild_install_fw_common() {
	[[ $# -gt 0 ]] || die "${FUNCNAME}: cros_config_host command required"
	[[ $# -lt 3 ]] || die "${FUNCNAME}: Only optional config file arg allowed"

	local cmd="$1"
	local files_path="${FILESDIR}"
	local config="${SYSROOT}${UNIBOARD_YAML_DIR}/config.yaml"

	if [[ $# -gt 1 ]]; then
		files_path="."
		config="$2"
	fi

	# Determine if using files or workdir for the path.
	if [[ "${cmd}" == *"-workdir" ]]; then
		cmd="${cmd%-workdir}"
		files_path="${WORKDIR}"
	fi

	einfo "unibuild: Installing ${cmd} based on ${config}"
	set -o pipefail
	cros_config_host -c "${config}" "${cmd}" |
	( while read -r source; do
		read -r dest
		read -r symlink
		_unibuild_install_fw "${files_path}/${source}" "${dest}" "${symlink}"
	done ) || die "Failed to read config"
}

# @FUNCTION: unibuild_install_touch_files
# @USAGE: [config_file]
# @DESCRIPTION:
# Install files related to touch firmware. This includes firmware for the
# touchscreen, touchpad and stylus.  These files are expected in files dir.
# Args:
#   $1: (optional) Config file used by cros_config_host
unibuild_install_touch_files() {
	[[ $# -lt 2 ]] || die "${FUNCNAME}: Only optional config file arg allowed"
	_unibuild_install_fw_common "get-touch-firmware-files" "$@"
}

# @FUNCTION: unibuild_install_touch_workdir
# @USAGE: [config_file]
# @DESCRIPTION:
# Install files related to touch firmware. This includes firmware for the
# touchscreen, touchpad and stylus. These files are expected in workdir.
# Args:
#   $1: (optional) Config file used by cros_config_host
unibuild_install_touch_workdir() {
	[[ $# -lt 2 ]] || die "${FUNCNAME}: Only optional config file arg allowed"
	_unibuild_install_fw_common "get-touch-firmware-files-workdir" "$@"
}

# @FUNCTION: unibuild_install_detachable_base_files
# @USAGE: [config_file]
# @DESCRIPTION:
# Install files related to detachable base firmware. This includes firmware
# for the detachable base ec and touchpad binary
# Args:
#   $1: (optional) Config file used by cros_config_host
unibuild_install_detachable_base_files() {
	[[ $# -lt 2 ]] || die "${FUNCNAME}: Only optional config file arg allowed"
	_unibuild_install_fw_common "get-detachable-base-firmware-files" "$@"
}

# @FUNCTION: unibuild_install_detachable_base_files_workdir
# @USAGE: [config_file]
# @DESCRIPTION:
# Install files related to detachable base firmware. This includes firmware
# for the detachable base ec and touchpad binary.
# These files are expected in workdir.
# Args:
#   $1: (optional) Config file used by cros_config_host
unibuild_install_detachable_base_files_workdir() {
	[[ $# -lt 2 ]] || die "${FUNCNAME}: Only optional config file arg allowed"
	_unibuild_install_fw_common "get-detachable-base-firmware-files-workdir" "$@"
}

# @FUNCTION: unibuild_build_configfs_file
# @USAGE:
# @DESCRIPTION:
# Build configfs img file.
unibuild_build_configfs_file() {
	[[ $# -eq 0 ]] || die "${FUNCNAME}: takes no arguments"

	einfo "unibuild: Build configfs img file"

	local yaml="${FILESDIR}/generated/build_config.json"
	local configfs_image="${WORKDIR}/configfs.img"

	cros_config_schema -c "${yaml}" \
		--configfs-output "${configfs_image}" -g "${WORKDIR}" -f "True" \
		|| die "cros_config_schema failed for configfs."
}

# @FUNCTION: unibuild_install_configfs_file
# @USAGE:
# @DESCRIPTION:
# Install configfs img file.
unibuild_install_configfs_file() {
	[[ $# -eq 0 ]] || die "${FUNCNAME}: takes no arguments"

	einfo "unibuild: Install configfs img file"

	insinto "${UNIBOARD_CROS_CONFIG_DIR}"
	doins "${WORKDIR}/configfs.img"
}

# @FUNCTION: platform_json_compile
# @USAGE:
# @DESCRIPTION:
# Compile platform json file project-config.json. This is done by finding all
# project-config.json within $S and using cros_config_schema to combine them
# into a single project-config.json.
platform_json_compile() {
	[[ $# -eq 0 ]] || die "${FUNCNAME}: takes no arguments"

	einfo "Compiling platform json file project-config.json."

	local files
	files=()
	_find_configs "${S}" "project-config.json"

	cros_config_schema \
		-o "${WORKDIR}/project-config.json" \
		-m "${files[@]}" \
		|| die "cros_config_schema failed for build config."
}

# @FUNCTION: platform_json_install
# @USAGE:
# @DESCRIPTION:
# Install platform json file project-config.json.
platform_json_install() {
	[[ $# -eq 0 ]] || die "${FUNCNAME}: takes no arguments"

	einfo "Installing platform json file project-config.json."

	insinto "${UNIBOARD_YAML_DIR}"
	doins "${WORKDIR}/project-config.json"
}

# @FUNCTION: platform_merged_install
# @USAGE:
# @DESCRIPTION:
# Install project-specific joined.jsonproto files into tmp dir.
# These files will be available to the Build API as artifacts.
# Args:
#   $1: Name of the project being installed
platform_merged_install() {
	[[ $# -eq 1 ]] || die "${FUNCNAME}: takes a single argument"
		einfo "Installing project-specific joined.jsonproto file."

	insinto "/build/share/cros-unibuild/$1/generated"
	doins "${S}/$1/generated/joined.jsonproto"
}


# @FUNCTION: unibuild_install_files
# @USAGE: [config_file]
# @DESCRIPTION:
# Install files as specified in project config.
# Args:
#   $1: Which files to install, translates to a command to pass to
#       cros_config_host to get the files
#   $2: (optional) Config file used by cros_config_host
unibuild_install_files() {
	[[ $# -gt 0 ]] || die "${FUNCNAME}: files to install arg required"
	[[ $# -lt 3 ]] || die "${FUNCNAME}: Only optional config file arg allowed"

	local file_set="$1"
	shift

	_unibuild_common_install "get-${file_set}" "$@"
}
