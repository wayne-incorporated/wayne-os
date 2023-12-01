# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# @ECLASS: tast-bundle.eclass
# @MAINTAINER:
# The ChromiumOS Authors <chromium-os-dev@chromium.org>
# @BUGREPORTS:
# Please report bugs via https://issuetracker.google.com/ (with component
# "ChromeOS > Test > Harness > Tast > Framework").
# @VCSURL: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/eclass/@ECLASS@
# @BLURB: Eclass for installing Tast test bundles data.
# @DESCRIPTION:
# Installs Tast test bundles data.
# See https://chromium.googlesource.com/chromiumos/platform/tast/ for details.
# The bundle type ("local" or "remote") are derived from the package name, which
# should end with "-<type>-data".

# @ECLASS-VARIABLE: TAST_BUNDLE_ROOT
# @DESCRIPTION:
# It is the root of the full path of the Tast bundle to be installed.
: "${TAST_BUNDLE_ROOT:="go.chromium.org/tast-tests/cros"}"


if ! [[ "${PN}" =~ .*-(local|remote)-data$ ]]; then
	die "Package \"${PN}\" should end with \"-<type>-data\""
fi

# @FUNCTION: tast-bundle-data_pkg_setup
# @DESCRIPTION:
# Parses package name to extract bundle info and sets binary target.
tast-bundle-data_pkg_setup() {
	# Strip off the "*-" prefix and "-data" suffix to get the type
	# ("local" or "remote").
	local tmp=${PN%-data}
	TAST_BUNDLE_DATA_TYPE=${tmp##*-}
	if ! [[ "${TAST_BUNDLE_DATA_TYPE}" =~ ^(local|remote)$ ]]; then
		die "BUG: unexpected type \"${TAST_BUNDLE_DATA_TYPE}\""
	fi
}

# @FUNCTION: tast-bundle-data_src_install
# @DESCRIPTION:
# Installs data files.
tast-bundle-data_src_install() {
	# The base directory where test data files are installed.
	local -r basedatadir="/usr/share/tast/data"

	# Install each test category's data dir.
	pushd src >/dev/null || die "failed to pushd src"
	local datadir dest

	find "${TAST_BUNDLE_ROOT}/${TAST_BUNDLE_DATA_TYPE}" -type d,l -name 'data' | while read -r datadir; do
		[[ -e "${datadir}" ]] || die
		[[ -d "${datadir}" ]] || continue

		# Dereference symlinks to support shared files: https://crbug.com/927424
		dest=${ED%/}/${basedatadir#/}/${datadir%/*}
		mkdir -p "${dest}" || die "Failed to create ${dest}"
		cp --preserve=mode --dereference -R "${datadir}" "${dest}" || \
			die "Failed to copy ${datadir} to ${dest}"
		chmod -R u=rwX,go=rX "${dest}" || die "Failed to chmod ${dest}"
	done
	popd >/dev/null || die
}

EXPORT_FUNCTIONS pkg_setup src_install
