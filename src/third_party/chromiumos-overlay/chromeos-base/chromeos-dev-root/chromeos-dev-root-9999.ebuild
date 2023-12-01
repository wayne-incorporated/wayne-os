# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# NB: This package should be kept to an absolute minimum.  We do not want the
# dev image to deviate from the base rootfs that is released to the world.
# If you really need rootfs modifications, use chromeos-test-root and a test
# image instead.

EAPI="7"

# This ebuild only cares about its own FILESDIR and ebuild file, so it tracks
# the canonical empty project.
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

inherit cros-workon

DESCRIPTION="Install packages that must live in the rootfs in dev images."
HOMEPAGE="https://dev.chromium.org/"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="~*"
IUSE="printscanmgr pvs-disable-ssh"

# TODO(b/257070388): Remove the printscanmgr package and its IUSE flag once it
# is being installed in the base image.
RDEPEND="
	!pvs-disable-ssh? ( chromeos-base/openssh-server-init )
	printscanmgr? ( chromeos-base/printscanmgr )
	chromeos-base/virtual-usb-printer
	virtual/chromeos-bsp-dev-root
"
