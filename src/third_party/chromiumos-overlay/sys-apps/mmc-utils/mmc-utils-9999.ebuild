# Copyright 2013 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_PROJECT="chromiumos/third_party/mmc-utils"

inherit cros-workon toolchain-funcs cros-sanitizers

# original Announcement of project:
#	http://permalink.gmane.org/gmane.linux.kernel.mmc/12766
#
# Upstream GIT:
#   https://git.kernel.org/cgit/linux/kernel/git/cjb/mmc-utils.git/
#
# To grab a local copy of the mmc-utils source tree:
#   git clone git://git.kernel.org/pub/scm/linux/kernel/git/cjb/mmc-utils.git
#
# or to reference upstream in local mmc-utils tree:
#   git remote add upstream git://git.kernel.org/pub/scm/linux/kernel/git/cjb/mmc-utils.git
#   git remote update

DESCRIPTION="Userspace tools for MMC/SD devices"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/third_party/mmc-utils"

LICENSE="GPL-2"
SLOT="0/0"
KEYWORDS="~*"
IUSE="static"

src_configure() {
	sanitizers-setup-env
	use static && append-ldflags -static
	tc-export CC
	export prefix=/usr
	default
}
