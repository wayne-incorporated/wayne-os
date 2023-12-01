# Copyright 2012 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

#
# Original Author: The ChromiumOS Authors <chromium-os-dev@chromium.org>
# Purpose: Install Tegra BCT files for firmware construction.
#

# @ECLASS-VARIABLE: TEGRA_BCT_SDRAM_CONFIG
# @DESCRIPTION:
# SDRAM memory timing configuration file to install
: ${TEGRA_BCT_SDRAM_CONFIG:=}

# @ECLASS-VARIABLE: TEGRA_BCT_FLASH_CONFIG
# @DESCRIPTION:
# Flash memory configuration file to install
: ${TEGRA_BCT_FLASH_CONFIG:=}

# @ECLASS-VARIABLE: TEGRA_BCT_ODM_DATA_CONFIG
# @DESCRIPTION:
# (Optional) ODM DATA value for specified board. ODM DATA specifies
# different configurations like memory and debug UART.
: ${TEGRA_BCT_ODM_DATA_CONFIG:=}

# @ECLASS-VARIABLE: TEGRA_BCT_CHIP_FAMILY
# @DESCRIPTION:
# Family of Tegra chip (determines BCT configuration)
: ${TEGRA_BCT_CHIP_FAMILY:=t25}

# Check for EAPI 2+
case "${EAPI:-0}" in
2|3|4|5|6) ;;
*) die "unsupported EAPI (${EAPI}) in eclass (${ECLASS})" ;;
esac

tegra-bct_src_configure() {
	local sdram_file=${FILESDIR}/${TEGRA_BCT_SDRAM_CONFIG}
	local flash_file=${FILESDIR}/${TEGRA_BCT_FLASH_CONFIG}
	local odmdata_file=${FILESDIR}/${TEGRA_BCT_ODM_DATA_CONFIG}

	if [ -z "${TEGRA_BCT_SDRAM_CONFIG}" ]; then
		die "No SDRAM configuration file selected."
	fi

	if [ -z "${TEGRA_BCT_FLASH_CONFIG}" ]; then
		die "No flash configuration file selected."
	fi

	if [ -z "${TEGRA_BCT_CHIP_FAMILY}" ]; then
		die "No chip family selected."
	fi

	einfo "Using sdram config file: ${sdram_file}"
	einfo "Using flash config file: ${flash_file}"
	einfo "Using chip family      : ${TEGRA_BCT_CHIP_FAMILY}"

	cat ${flash_file} > board.cfg ||
		die "Failed to read flash config file."

	cat ${sdram_file} >> board.cfg ||
		die "Failed to read SDRAM config file."

	# TEGRA_BCT_ODM_DATA_CONFIG is optional, Only use it if set.
	if [ ! -z "${TEGRA_BCT_ODM_DATA_CONFIG}" ]; then
		einfo "Using odmdata          : ${TEGRA_BCT_ODM_DATA_CONFIG}"
		cat ${odmdata_file} >> board.cfg ||
			die "Failed to read ODMDATA config file."
	fi
}

tegra-bct_src_compile() {
	local chip_family="-${TEGRA_BCT_CHIP_FAMILY}"
	cbootimage -gbct $chip_family board.cfg board.bct ||
		die "Failed to generate BCT."
}

tegra-bct_src_install() {
	local sdram_file=${FILESDIR}/${TEGRA_BCT_SDRAM_CONFIG}
	local flash_file=${FILESDIR}/${TEGRA_BCT_FLASH_CONFIG}
	local odmdata_file=${FILESDIR}/${TEGRA_BCT_ODM_DATA_CONFIG}

	insinto /firmware/bct

	doins "${sdram_file}"
	doins "${flash_file}"

	# TEGRA_BCT_ODM_DATA_CONFIG is optional, Only use it if set.
	if [ ! -z "${TEGRA_BCT_ODM_DATA_CONFIG}" ]; then
		doins "${odmdata_file}"
	fi

	if [ "$(basename ${sdram_file})" != "sdram.cfg" ]; then
		dosym "$(basename ${sdram_file})" /firmware/bct/sdram.cfg
	fi

	if [ "$(basename ${flash_file})" != "flash.cfg" ]; then
		dosym "$(basename ${flash_file})" /firmware/bct/flash.cfg
	fi

	doins board.cfg
	doins board.bct
}

EXPORT_FUNCTIONS src_configure src_compile src_install
