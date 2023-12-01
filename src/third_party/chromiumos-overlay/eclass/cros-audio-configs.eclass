# Copyright 2015 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

#
# Original Author: The ChromiumOS Authors <chromium-os-dev@chromium.org>
# Purpose: Library for handling installation of audio config files.
#
#
#  This class provides an easy way to install audio config files.
#  It is intended to be used by chromeos-bsp-<BOARD> ebuilds.

install_audio_configs()
{
	[[ $# -ne 2 ]] && die "Usage: ${FUNCNAME} <board> <audio_config_directory>"

	# Install alsa config files.
	local board=$1
	local audio_config_dir=$2

	insinto /etc/modprobe.d
	local alsa_conf="${audio_config_dir}/alsa-module-config/alsa-${board}.conf"
	if [[ -f "${alsa_conf}" ]] ; then
		doins "${alsa_conf}"
	fi

	# Install alsa patch files.
	insinto /lib/firmware
	local alsa_patch="${audio_config_dir}/alsa-module-config/${board}_alsa.fw"
	if [[ -f "${alsa_patch}" ]] ; then
		doins "${alsa_patch}"
	fi

	# Install ucm config files.
	insinto /usr/share/alsa/ucm
	local ucm_config="${audio_config_dir}/ucm-config"
	if [[ -d "${ucm_config}" ]] ; then
		doins -r "${ucm_config}"/*
	fi

	# Install cras config files.
	insinto /etc/cras
	local cras_config="${audio_config_dir}/cras-config"
	if [[ -d "${cras_config}" ]] ; then
		doins -r "${cras_config}"/*
	fi
}
