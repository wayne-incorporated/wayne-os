# Copyright 2010 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

# CROS_WORKON_REPO=FILL_YOUR_REPO_URL_HERE
# inherit toolchain-funcs flag-o-matic cros-workon autotest

DESCRIPTION="All private autotest tests"
HOMEPAGE="https://dev.chromium.org/chromium-os"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"

# This ebuild file is reserved for adding new private tests in your factory
# process. You can change the CROS_WORKON_REPO to your own server, and uncomment
# the following CROS_WORKON_* variables to have your own tests merged when
# building factory test run-in images.

# CROS_WORKON_PROJECT=autotest-private
# CROS_WORKON_LOCALNAME=../third_party/autotest-private
