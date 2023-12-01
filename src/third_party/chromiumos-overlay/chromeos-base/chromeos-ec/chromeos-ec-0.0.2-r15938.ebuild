# Copyright 2012 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE.makefile file.

# A note about this ebuild: this ebuild is Unified Build enabled but
# not in the way in which most other ebuilds with Unified Build
# knowledge are: the primary use for this ebuild is for engineer-local
# work or firmware builder work. In both cases, the build might be
# happening on a branch in which only one of many of the models are
# available to build. The logic in this ebuild succeeds so long as one
# of the many models successfully builds.

# Increment the "eclass bug workaround count" below when you change
# "cros-ec.eclass" to work around https://issuetracker.google.com/201299127.
#
# eclass bug workaround count: 8

EAPI=7

CROS_WORKON_COMMIT=("3ab9f11c5b5078ab87a910547ff9c0a77d2f86e7" "0dd679081b9c8bfa2583d74e3a17a413709ea362" "c18f94e3b017104284cd541e553472e62e85e526" "e0d601a57fde7d67a1c771e7d87468faf1f8fe55")
CROS_WORKON_TREE=("9d91c80eda27615faf2b252a03db4b4f1f4830b5" "d99abee3f825248f344c0638d5f9fcdce114b744" "17878f433c782b4f34ec7180490cdfb371a0fee7" "307ef78893e2eb0851e7d09bb2fd535748bbccf7")
CROS_WORKON_PROJECT=(
	"chromiumos/platform/ec"
	"chromiumos/third_party/cryptoc"
	"external/gitlab.com/libeigen/eigen"
	"external/gob/boringssl/boringssl"
)
CROS_WORKON_LOCALNAME=(
	"platform/ec"
	"third_party/cryptoc"
	"third_party/eigen3"
	"third_party/boringssl"
)
CROS_WORKON_DESTDIR=(
	"${S}/platform/ec"
	"${S}/third_party/cryptoc"
	"${S}/third_party/eigen3"
	"${S}/third_party/boringssl"
)

inherit cros-ec cros-workon

# Make sure config tools use the latest schema.
BDEPEND=">=chromeos-base/chromeos-config-host-0.0.2"

MIRROR_PATH="gs://chromeos-localmirror/distfiles/"
DESCRIPTION="Embedded Controller firmware code"
KEYWORDS="*"

# Restrict strip because chromeos-ec package installs unstrippable firmware.
RESTRICT="strip"
