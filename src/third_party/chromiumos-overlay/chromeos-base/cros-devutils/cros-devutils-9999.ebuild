# Copyright 2012 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

# This ebuild only cares about its own FILESDIR and ebuild file, so it tracks
# the canonical empty project.
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"
CROS_WORKON_OUTOFTREE_BUILD=1

inherit cros-workon

DESCRIPTION="Development utilities for ChromiumOS"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/dev-util/+/HEAD/host/"

LICENSE="BSD-Google"
KEYWORDS="~*"
IUSE=""

RDEPEND="app-portage/gentoolkit
	>=chromeos-base/devserver-0.0.2
	dev-util/shflags
	dev-util/toolchain-utils
	"
# These are all either bash / python scripts.  No actual builds DEPS.
DEPEND=""
