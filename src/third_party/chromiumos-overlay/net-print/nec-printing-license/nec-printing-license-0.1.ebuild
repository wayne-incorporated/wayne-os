# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# This ebuild is used to install the NEC PPD license into ChromeOS. PPDs are
# served separately from the operating system through a static content server,
# but in order for their associated licenses to appear in the os-credits page a
# license must be generated from an ebuild.

EAPI=7

DESCRIPTION="Licenses for NEC PPD files"
HOMEPAGE="https://jpn.nec.com/printer/laser/index.html"

LICENSE="LICENSE.nec-ppds"
SLOT="0"
KEYWORDS="*"
