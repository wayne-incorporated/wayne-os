# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2
#
#
# Purpose: Eclass for handling gtest functional test packages

inherit cros-constants

# @ECLASS-VARIABLE: GTEST_METADATA_INSTALL_DIR
# @DESCRIPTION:
# Location of the appropriate metadata install directory
: "${GTEST_METADATA_INSTALL_DIR:=/usr/local/build/gtest}"

install_gtest_metadata() {
	local gtest_dir="${WORKDIR}/${P}/platform/dev/test/gtest"
	local metadata_files=()

	for f in "$@"
	do
 		local meta_file=$(basename "${f}" .yaml).pb
 		python3 "${gtest_dir}"/generate_gtest_metadata.py   --output_file "${meta_file}" \
															--yaml_schema "${gtest_dir}"/gtest_schema.yaml \
															"${f}" \
															|| die "Failed to generate metadata for '${f}'!"

		metadata_files+=("${meta_file}")
	done

	insinto "${GTEST_METADATA_INSTALL_DIR}"
	doins "${metadata_files[@]}"
}

export install_gtest_metadata
