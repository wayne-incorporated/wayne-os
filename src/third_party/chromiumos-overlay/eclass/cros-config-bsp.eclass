# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2
#
# Standardizes the setup for chromeos-config-bsp ebuilds across
# all overlays based on config managed in the project specific
# repos (located under src/project).
# Note: this eclass does not support cros_workon_make as it
# updates the source tree (where config files are generated)

# Check for EAPI 7+
case "${EAPI:-0}" in
7) ;;
*) die "unsupported EAPI (${EAPI}) in eclass (${ECLASS})" ;;
esac


# @ECLASS-VARIABLE: PROGRAM
# @PRE_INHERIT
# @REQUIRED
# @DESCRIPTION:
# Name of the program under src/program
: "${PROGRAM:=alpha}"


# @ECLASS-VARIABLE: PROJECTS
# @PRE_INHERIT
# @REQUIRED
# @DESCRIPTION:
# Names of the projects under src/project/$PROGRAM/ that will be
# included in this build.
: "${PROJECTS:=(one two three)}"

PROJECT_PREFIX="project_"
PROJECT_ALL="${PROJECT_PREFIX}all"
IUSE="${PROJECT_ALL} ${PROJECTS[*]/#/${PROJECT_PREFIX}}"

# Watch for any change anywhere in the projects or program
export CONFIG_ROOT=""

inherit cros-unibuild cros-constants

SRC_URI=""

LICENSE="BSD-Google"
SLOT="0/${PF}"

BDEPEND="
	dev-go/lucicfg
"

EXPORT_FUNCTIONS src_compile src_install

# @FUNCTION: cros-config-bsp_build_config
# @USAGE: cros-config-bsp_build_config <generate_dir> <starlark_file>
# @DESCRIPTION:
# Generates a payload (ConfigBundle) config file based on Starlark config.
cros-config-bsp_build_config() {
	local config_dir=$1
	local starlark_file=$2
	lucicfg generate --config-dir "${config_dir}" "${starlark_file}" \
		|| die "Failed to generate config under $(pwd)."
}

# @FUNCTION: cros-config-bsp_proto_converter
# @USAGE:
# cros-config-bsp_proto_converter <program_name> <project_name> <output_dir>
# @DESCRIPTION:
# Transforms a ConfigBundle file to platform JSON.
cros-config-bsp_proto_converter() {
	local program_config=$1
	local project_config=$2
	local output_dir=$3

	if [[ ! -e "${program_config}" || ! -e "${project_config}" ]]; then
		die "'${program_config}' and '${project_config}' must exist."
	fi

	rm -rf "${output_dir}"
	mkdir -p "${output_dir}"
	cros_config_proto_converter \
		--output "${output_dir}/project-config.json" \
		--program-config "${program_config}" \
		--project-configs "${project_config}" \
		--dtd-path config/payload_utils/media_profiles.dtd \
		|| die "Failed to run cros_config_proto_converter."
}

# @FUNCTION: cros-config-bsp_merge_payloads
# @USAGE:
# cros-config-bsp_merge_payloads <imported_config> <config_bundle> <output_file>
# @DESCRIPTION:
# Merges a backfilled ConfigBundle file with the ConfigBundle produced by Starlark.
cros-config-bsp_merge_payloads() {
	local imported_config=$1
	local config_bundle=$2
	local output_file=$3

	cros_config_merge_backfilled_config \
		--backfilled-config-bundle "${imported_config}" \
		--config-bundle "${config_bundle}" \
		--output "${output_file}" \
		|| die "Failed to merge backfilled config and config payload"
}

# @FUNCTION: cros-config-bsp_gen_config
# @USAGE: cros-config-bsp_gen_config
# @DESCRIPTION:
# Generates platform configuration files for the program and associated projects.
cros-config-bsp_gen_config() {
	# Re-establish the symlinks as they exist in the source tree.
	ln -sfT "${S}/config" "${S}/program/${PROGRAM}/config" \
		|| die "Failed to create '${PROGRAM}' link."
	(
		cd "${S}/program/${PROGRAM}" || die "Unable to cd into ${PROGRAM}."
		cros-config-bsp_build_config generated config.star
	)
	local project
	for project in "${PROJECTS[@]}"; do
		# Clean any generated config dirs
		rm -rf "${S}/${project}/sw_build_config/platform/chromeos-config/generated" \
			|| die "Unable to remove sw_build_config generated dir"
		rm -rf "${S}/${project}/public_sw_build_config/platform/chromeos-config/generated" \
			|| die "Unable to remove public_sw_build_config generated dir"
		ln -sfT "${S}/config" "${S}/${project}/config" \
			|| die "Failed to create '${project}/config' link."
		ln -sfT "${S}/program/${PROGRAM}" "${S}/${project}/program" \
			|| die "Failed to create '${project}/program' link."
		local output_dir="sw_build_config/platform/chromeos-config/generated"
		(
			cd "${S}/${project}" || die "Unable to cd into ${project}."
			cros-config-bsp_build_config generated config.star
			cros-config-bsp_proto_converter "program/generated/config.jsonproto" \
				"generated/config.jsonproto" "${output_dir}"
			cros-config-bsp_merge_payloads "generated/imported.jsonproto" \
				"generated/config.jsonproto" "generated/joined.jsonproto"
		)
	done
}

cros-config-bsp_src_compile() {
	cros-config-bsp_gen_config
	platform_json_compile
}

cros-config-bsp_src_install() {
	platform_json_install
	local project
	for project in "${PROJECTS[@]}"; do
		platform_merged_install "${project}"
	done

	unibuild_install_files arc-files "${WORKDIR}/project-config.json"
	unibuild_install_files thermal-files "${WORKDIR}/project-config.json"
	unibuild_install_touch_files "${WORKDIR}/project-config.json"
	unibuild_install_files intel-wifi-sar-files "${WORKDIR}/project-config.json"
	unibuild_install_files proximity-sensor-files "${WORKDIR}/project-config.json"
}
