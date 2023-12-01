# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_SUBTREE="chromeos-config/cros_config_host"

PYTHON_COMPAT=( python3_{8..9} )
unset PYTHON_COMPAT_OVERRIDE

inherit cros-unibuild cros-workon python-any-r1

DESCRIPTION="Chromium OS-specific configuration"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/config/"
SRC_URI=""
LICENSE="BSD-Google"
KEYWORDS="~*"
IUSE="zephyr_poc"

RDEPEND="chromeos-base/crosid"

# This ebuild creates the Chrome OS master configuration file stored in
# ${UNIBOARD_JSON_INSTALL_PATH}. See go/cros-unified-builds-design for
# more information.

# Run a Python utility from the cros_config_host directory.
#
# Doing this instead of calling the installed copy has multiple
# benefits:
# - Users who are making a schema change do not need to cros workon
#   chromeos-base/chromeos-config-host, emerge that, and cros workon
#   chromeos-base/chromeos-config for their board, and finally emerge
#   that.  Historically, this was a common confusion point for
#   developers.
# - Schema permissions don't end up messed up if a user does a repo
#   sync with a weird umask.
# - Schema changes force the chromeos-base/chromeos-config package to
#   get revbumped.
#
# Args:
#    $1: The tool name to run (either cros_config_host or
#        cros_config_schema).
#    $@: The remaining arguments are passed directly to the tool.
run_cros_config_tool() {
	local tool="${1}"
	shift

	PYTHONPATH="${S}/chromeos-config/cros_config_host" \
		"${EPYTHON}" -m "${tool}" "$@"
}

# Merges all of the source YAML config files and generates the
# corresponding build config and platform config files.
src_compile() {
	local yaml_files=( "${SYSROOT}${UNIBOARD_YAML_DIR}/"*.yaml )
	local input_yaml_files=()
	local schema_flags=()
	local yaml="${WORKDIR}/config.yaml"
	local configfs_image="${WORKDIR}/configfs.img"
	local gen_yaml="${SYSROOT}${UNIBOARD_YAML_DIR}/config.yaml"

	# Protobuf based configs generate JSON directly with no YAML.
	if [[ -f "${SYSROOT}${UNIBOARD_YAML_DIR}/project-config.json" ]]; then
		yaml_files=( "${SYSROOT}${UNIBOARD_YAML_DIR}/project-config.json" )
	fi

	for source_yaml in "${yaml_files[@]}"; do
		if [[ -f "${source_yaml}" && "${source_yaml}" != "${gen_yaml}" ]]; then
			einfo "Adding source YAML file ${source_yaml}"
			# Order matters here.  This will control how YAML files
			# are merged.  To control the order, change the name
			# of the input files to be in the order desired.
			input_yaml_files+=("${source_yaml}")
		fi
	done

	if use zephyr_poc; then
		schema_flags+=( --zephyr-ec-configs-only )
	fi

	if [[ "${#input_yaml_files[@]}" -ne 0 ]]; then
		run_cros_config_tool cros_config_schema "${schema_flags[@]}" \
			-o "${yaml}" \
			-m "${input_yaml_files[@]}" \
			|| die "cros_config_schema failed for build config."

		run_cros_config_tool cros_config_schema -c "${yaml}" \
			--configfs-output "${configfs_image}" -f "True" \
			--identity-table-out "${WORKDIR}/identity.bin" \
			|| die "cros_config_schema failed for platform config."
	fi
}

src_install() {
	# Get the directory name only, and use that as the install directory.
	insinto "${UNIBOARD_JSON_INSTALL_PATH%/*}"
	if [[ -e "${WORKDIR}/configfs.img" ]]; then
		doins "${WORKDIR}/configfs.img"
	fi
	if [[ -e "${WORKDIR}/identity.bin" ]]; then
		doins "${WORKDIR}/identity.bin"
	fi

	insinto "${UNIBOARD_YAML_DIR}"
	if [[ -e "${WORKDIR}/config.yaml" ]]; then
		doins "${WORKDIR}/config.yaml"
	fi
}

# @FUNCTION: _verify_config_dump
# @USAGE: [source-yaml] [expected-json]
# @INTERNAL
# @DESCRIPTION:
# Dumps the cros_config_host contents and verifies expected file match.
#   $1: Source YAML config file used to generate JSON dump.
#   $2: Expected JSON output file that is verified against.
_verify_config_dump() {
	local source_yaml="$1"
	local expected_json="$2"

	local expected_path="${SYSROOT}${CROS_CONFIG_TEST_DIR}/${expected_json}"
	local source_path="${SYSROOT}${UNIBOARD_YAML_DIR}/${source_yaml}"
	local actual_path="${WORKDIR}/${expected_json}"
	local merged_path="${WORKDIR}/${source_yaml}"
	if [[ -e "${expected_path}" ]]; then
		if [[ -e "${source_path}" ]]; then
			run_cros_config_tool cros_config_schema -o "${merged_path}" \
				-m "${source_path}" \
				|| die "cros_config_schema failed for build config."
			run_cros_config_tool cros_config_host \
				-c "${merged_path}" dump-config > "${actual_path}"
			verify_file_match "${expected_path}" "${actual_path}"
		else
			eerror "Source YAML ${source_path} doesn't exist for checking" \
				"against expected JSON dump ${expected_path}"
			die
		fi
	fi
}

src_test() {
	_verify_config_dump model.yaml config_dump.json
	_verify_config_dump private-model.yaml config_dump-private.json
}
