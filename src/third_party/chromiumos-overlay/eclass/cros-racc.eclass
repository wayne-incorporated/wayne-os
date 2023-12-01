# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# @ECLASS: cros-racc.eclass
# @BLURB: helper eclass for building Chromium packages of RACC
# @DESCRIPTION:
# Packages src/platform2/{hardware_verifier,runtime_probe} are in active
# development.  We have to add board-specific rules manually.

EXPORT_FUNCTIONS src_compile src_install

# @FUNCTION: cros-racc_src_compile
# @DESCRIPTION:
# Remove all indents, line breaks and spaces in json file to reduce disk usage.
cros-racc_src_compile() {
	einfo "cros-racc src_compile"

	local CMD_MINIFY_JSON=("jq" "-c" ".")
	local BUILD_ROOT="${WORKDIR}/build"
	local config
	if [[ -d "${FILESDIR}/runtime_probe/" ]]; then
		# shellcheck disable=SC2015
		while read -r -d $'\0' config; do
			mkdir -p "$(dirname "${BUILD_ROOT}/${config}")"
			"${CMD_MINIFY_JSON[@]}" \
				< "${FILESDIR}/${config}" > "${BUILD_ROOT}/${config}" ||
				die "Failed to minify json file: ${config}"
		done < <(cd "${FILESDIR}" && find "runtime_probe/" -maxdepth 2 -name "*.json" -type f -print0 || die)
	fi
}

# @FUNCTION: cros-racc_src_install
# @DESCRIPTION:
# Install AVL runtime verification config files.
# https://bugs.chromium.org/p/chromium/issues/detail?id=959178 for more details.
cros-racc_src_install() {
	einfo "cros-racc src_install"

	if [[ -d "${WORKDIR}/build/runtime_probe/" ]]; then
		insinto /etc/runtime_probe
		doins -r "${WORKDIR}/build/runtime_probe/"*
	fi

	if [[ -e "${FILESDIR}/hw_verification_spec.prototxt" ]]; then
		insinto /etc/hardware_verifier
		doins "${FILESDIR}/hw_verification_spec.prototxt"
	fi
}
