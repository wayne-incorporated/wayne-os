# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

CROS_WORKON_COMMIT=("e687d49261f807d96ce5b9d8f1bfa8f184aa5bbd" "c5028d11ccb7799ec16a1aea08f55e1a27bea33c")
CROS_WORKON_TREE=("5f52f55a4678653b15e0126bf489a8e105f32768" "b62ae50ed547d76feb94710f8c187f5a3f52bc84" "f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6" "0a61f084217b6f375b571defe2093d98a0b66e46")
CROS_WORKON_PROJECT=(
	"chromiumos/platform2"
	"chromiumos/platform/redaction_tool"
)

CROS_WORKON_LOCALNAME=(
	"platform2"
	"platform/redaction_tool"
)

CROS_WORKON_DESTDIR=(
	"${S}/platform2"
	# This needs to be platform2/redaction_tool instead of
	# platform/redaction_tool because we are using the
	# platform2 build system.
	"${S}/platform2/redaction_tool"
)

CROS_WORKON_SUBTREE=("common-mk metrics .gn" "")

PLATFORM_SUBDIR="redaction_tool"

inherit cros-workon platform

DESCRIPTION="Redaction tool library for Chromium OS"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/redaction_tool"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE="+cpp20"

COMMON_DEPEND="
	chromeos-base/metrics:=
	dev-libs/re2:=
"

RDEPEND="${COMMON_DEPEND}"
DEPEND="${COMMON_DEPEND}"

platform_pkg_test() {
	platform test_all
}
