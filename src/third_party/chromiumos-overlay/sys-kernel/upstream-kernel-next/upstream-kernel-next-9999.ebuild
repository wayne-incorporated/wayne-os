# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_PROJECT="linux-next"
CROS_WORKON_REPO="https://kernel.googlesource.com/pub/scm/linux/kernel/git/next"
CROS_WORKON_MANUAL_UPREV="1"
CROS_WORKON_EGIT_BRANCH="master"
CROS_WORKON_ALWAYS_LIVE="1"

# This must be inherited *after* EGIT/CROS_WORKON variables defined
inherit cros-workon cros-kernel2

HOMEPAGE="https://www.chromium.org/chromium-os/chromiumos-design-docs/chromium-os-kernel"
DESCRIPTION="Linux Kernel Upstream (next)"
KEYWORDS="*"
