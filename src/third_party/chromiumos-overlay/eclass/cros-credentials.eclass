# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# @ECLASS: cros-credentials.eclass
# @MAINTAINER:
# ChromiumOS Build Team
# @BUGREPORTS:
# Please report bugs via http://crbug.com/new (with label Build)
# @VCSURL: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/eclass/@ECLASS@
# @BLURB: Set credentials properly to access private git repo.
# @DESCRIPTION:
# Copy in credentials to fake home directory so that build process can
# access vcs and ssh if needed.
# Add a call to cros-credentials_setup before accessing a private repo.

cros-credentials_setup() {
	einfo "Setting up CrOS credentials"
	mkdir -vp "${HOME}"
	local whoami=$(whoami)
	local ssh_config_dir="/home/${whoami}/.ssh"
	if [[ -d "${ssh_config_dir}" ]]; then
		cp -vrfp "${ssh_config_dir}" "${HOME}" || die
	fi
	local net_config="/home/${whoami}/.netrc"
	if [[ -f "${net_config}" ]]; then
		einfo "Copying ${net_config} to ${HOME}"
		cp -vfp "${net_config}" "${HOME}" || die
	fi
	local gitcookies_src="/home/${whoami}/.gitcookies"
	local gitcookies_dst="${HOME}/.gitcookies"
	if [[ -f "${gitcookies_src}" ]]; then
		cp -vfp "${gitcookies_src}" "${gitcookies_dst}" || die
		echo 'gitcookies accounts:'
		awk 'NF && $1 !~ /^#/ {print $1}' "${gitcookies_dst}"
		git config --global http.cookiefile "${gitcookies_dst}"
	fi
	local luci_creds_src="/home/${whoami}/.config/chrome_infra/auth/creds.json"
	local luci_creds_dest="${HOME}/.config/chrome_infra/auth/"
	if [[ -f "${luci_creds_src}" ]]; then
		einfo "Copying ${luci_creds_src} to ${HOME}"
		mkdir -p "${luci_creds_dest}"
		cp -vfp "${luci_creds_src}" "${luci_creds_dest}" || die
	fi

	# Force disable user/pass prompting to avoid hanging builds.
	git config --global core.askPass true
}

# @FUNCTION: cros-fetch_google_app_credentials
# @USAGE:
# @RETURN: "true" if able to get local dev's app credentials. "false" otherwise.
# @INTERNAL
# @DESCRIPTION:
# Copy over app credentials from chroot -> sysroot for local developers only (this is not needed for build bots)
# gcloud default credentials are located in chroot user's:
# ~/.config/gcloud directory (eg. /home/<user>/.config/gcloud)
# However, the build executes relative to sysroot, where the homedir is something like:
# (eg. /build/hatch/tmp/portage/chromeos-base/chromeos-chrome-9999/homedir)
# So when we run reproxy process, we need to provide it with the gcloud credentials under the
# sysroot home path, which are the actions done below.
# Do so only for local development (no need for buildbots)
cros-fetch_google_app_credentials() {
	HAS_APP_CREDENTIALS="true"

	if [[ -z ${CHROMEOS_CI_USERNAME} ]]; then
		die "FATAL - CHROMEOS_CI_USERNAME is undefined. Should be defined in make.common"
	fi

	# Check that this is not running on a buildbot (username: chrome-bot)
	if [[ "$(whoami)" != "${CHROMEOS_CI_USERNAME}" ]]; then
		# Get here for local devs
		CHROOT_APP_CREDENTIALS="/home/$(whoami)/.config/gcloud"

		if [[ ! -d "${CHROOT_APP_CREDENTIALS}" ]]; then
			einfo "*************************************************************************************"
			einfo "*** Defaulting to slower local build due to missing gcloud app credentials, instead of faster distributed builds on reclient."
			einfo "*** Unable to find gcloud credentials under: ${CHROOT_APP_CREDENTIALS}"
			einfo "*** For googlers, run 'gcloud auth application-default login' outside of chroot, then retry. go/cloud-cli-tpc to get the CLI"
			einfo "*************************************************************************************"
			HAS_APP_CREDENTIALS="false"
		else
			# The env variable below is also used by reproxy to find where the credentials is located in sysroot.
			export GOOGLE_APPLICATION_CREDENTIALS="${HOME}/.config/gcloud/application_default_credentials.json"

			# Only update if credential file doesn't already exist
			if [[ ! -f "${GOOGLE_APPLICATION_CREDENTIALS}" ]]; then
				# The env variable below is also used by reproxy to find where the credentials is located
				einfo "Copying over google app credentials from chroot -> sysroot. [${CHROOT_APP_CREDENTIALS} -> ${GOOGLE_APPLICATION_CREDENTIALS}]"
				mkdir -p "${HOME}/.config"
				cp -R "${CHROOT_APP_CREDENTIALS}" "${HOME}/.config/"
			fi
		fi
	else
		einfo "Executing on buildbot - no need to copy over gcloud application default credentials."
	fi

	echo ${HAS_APP_CREDENTIALS}
}
