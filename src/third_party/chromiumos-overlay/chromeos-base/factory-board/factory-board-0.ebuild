# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# This is a template for chromeos-base/factory-board package.
# Read go/cros-factory-make if you need further information.

EAPI=7

# If you need to share files across different overlays from BCS, uncomment the
# definition below with right overlay name.
# CROS_CPFE_BOARD_OVERLAY="overlay-${YOUR_OVERLAY_HERE}-private"
inherit cros-cpfe cros-factory

DESCRIPTION="Board-specific file for factory software (chromeos-base/factory)."
HOMEPAGE="http://src.chromium.org"
SRC_URI=""
LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

RESTRICT="mirror strip"
S="${WORKDIR}"

# All files in ${FILESDIR} (files/) directory will be merged by
# chromeos-base/factory. If you don't need additional downloaded files (either
# from CPFE or localmirror), you can stop now and delete all lines below.

# CPFE Binary Configuration
# -------------------------
# To upload a new archive, browse http://www.google.com/chromeos/partner/fe/ ,
# click "Uploads - Private", select correct board overlay and enter
# "chromeos-base/factory-board" in "Relative path to file".
# Then run "ebuild-$BOARD <ebuild-name> manifest" to update Manifest file.
# If you have per-board binary files, the archive should better have
# ${CROS_CPFE_BOARD_NAME} in its downloaded file name to prevent file collision.
#
# Example 1 (assume you want to install 'xxx' for board 'samus'):
#  SAMUS_XXX_PACKAGE="samus-xxx-1.0-r1.tar.bz2"
#  SAMUS_XXX_URI="${CROS_CPFE_URL}/${SAMUS_XXX_PACKAGE}"
#  SRC_URI+=" ${SAMUS_XXX_URI}"
#
# Example 2 (files uploaded to BCS does not have board name prefix):
#  SAMUS_XXX_BCS_NAME="xxx-1.0-r1.tar.bz2"
#  SAMUS_XXX_PACKAGE="${CROS_CPFE_BOARD_NAME}-${SAMUS_XXX_BCS_NAME}"
#  SAMUS_XXX_URI="${CROS_CPFE_URL}/${SAMUS_XXX_BCS_NAME}"
#  SRC_URI+=" ${SAMUS_XXX_URI} -> ${SAMUS_XXX_PACKAGE}"
#
# And in the end, you have to specify where to install your package, using
# function factory_install_resource. Usage:
#   factory_install_resource name local newpath files...
#
# Example 1:
#  Assume the downloaded 'xxx' package has a directory 'xxx-dir' and one file
#  'xxx-file' that you want to install into /usr/local/factory/third_party:
#
#  src_install() {
#    # Usage: factory_install_resource name local newpath files...
#    factory_create_resource "" "" "third_party" \
#      xxx-dir xxx-file
#  }
#
# Example 2:
#  Assume you have two packages, 'xxx' and 'yyy'. 'xxx' package has a top
#  level 'xxx-1.0' with one directory 'xxx-dir' and file 'xxx-file' inside.
#  'yyy' has 'yyy-2.0/yyy-dir' and 'yyy-2.0/yyy-file'. You want to strip the top
#  level folder 'xxx-1.0' and 'yyy-2.0', then install xxx into
#  /usr/local/factory/third_party, and yyy into /usr/local/factory/bin:
#
#  src_install() {
#    # Usage: factory_install_resource name local newpath files...
#    factory_create_resource "factory-xxx" "xxx-1.0" "third_party" \
#      xxx-dir xxx-file
#    factory_create_resource "factory-yyy" "yyy-2.0" "bin" \
#      yyy-dir yyy-file
#  }
