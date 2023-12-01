# Copyright 2016 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# @ECLASS: autotest-external-dep.eclass
# @MAINTAINER:
# ChromiumOS Build Team
# @AUTHOR:
# The ChromiumOS Authors <chromium-os-dev@chromium.org>
# @BUGREPORTS:
# Please report bugs via http://crbug.com/new (with label Build)
# @VCSURL: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/eclass/@ECLASS@
# @BLURB: Eclass for handling minimal external autotest-dep packages
# @DESCRIPTION:
# Since all autotest dep package requires basic fake test during compile stage,
# each package needs a ${PACKAGE}.py for setup. However, we have many dep
# packages that simply fetches src from external packages and thus don't need
# additional setup. This eclass handles the common jobs that has to be done by
# these autotest-dep ebuilds.

inherit autotest-deponly cros-constants

# @ECLASS-VARIABLE: PACKAGE
# @DESCRIPTION:
# The name of the autotest-dep package being build. MUST be set by the
# inheriting ebuild. If empty, build fails.

autotest-external-dep_src_prepare() {
	# Check if PACKAGE is set, abort if not set.
	[[ -z "${PACKAGE}" ]] && die "PACKAGE is not set"
	# Use customized ${PACKAGE}.py if available, use default otherwise.
	if [[ -e "${FILESDIR}/${PACKAGE}.py" ]]; then
		cp "${FILESDIR}/${PACKAGE}.py" "${WORKDIR}/${PACKAGE}.py" || die
	else
		cat << EOF > "${WORKDIR}/${PACKAGE}.py"
import logging
import os

# Setup autotest_lib path by importing common.
import common
from autotest_lib.client.bin import utils

version = 1

def setup(setup_dir):
    """ An empty setup function
    @param setup_dir: the target directory
    """
    logging.info('setup(%s)', setup_dir)

pwd = os.getcwd()
utils.update_version(pwd, True, version, setup, pwd)
EOF
		chmod a+x "${WORKDIR}/${PACKAGE}.py"
	fi
}

autotest-external-dep_src_compile() {
	if [[ ! -e "${AUTOTEST_WORKDIR}/client/deps/${PACKAGE}" ]]; then
		mkdir -p "${AUTOTEST_WORKDIR}/client/deps"
		ln -s "${WORKDIR}" "${AUTOTEST_WORKDIR}/client/deps/${PACKAGE}" || die
	fi
	autotest_src_compile
	if [[ -e "${ROOT}/${AUTOTEST_BASE}/client/deps/${PACKAGE}/.version" ]]; then
		cp "${ROOT}/${AUTOTEST_BASE}/client/deps/${PACKAGE}/.version" "${WORKDIR}/" || die
	fi
	# Clean up autotest workdir which we don't need in final package.
	rm -rf "${AUTOTEST_WORKDIR}"
}

autotest-external-dep_src_install() {
	insinto "${AUTOTEST_BASE}"/client/deps/${PACKAGE}
	doins -r .
}

EXPORT_FUNCTIONS src_prepare src_compile src_install
