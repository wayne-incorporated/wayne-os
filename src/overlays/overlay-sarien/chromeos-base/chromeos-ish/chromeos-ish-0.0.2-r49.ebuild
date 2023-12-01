# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE.makefile file.

EAPI=7

CROS_WORKON_COMMIT=("3c1a1c1ae009aac90e1234c2d73675aae39fe86d" "1e2e9d7183f545eefd1a86a07b0ab6f91d837a6c")
CROS_WORKON_TREE=("f090636098b404fa31ade3300ee419f6e5b36676" "fdbc51bbd5a7ee9d532ea1aa30cf21e57ca199db")
CROS_WORKON_PROJECT=(
	"chromiumos/platform/ec"
	"chromiumos/third_party/cryptoc"
)
CROS_WORKON_LOCALNAME=(
	"platform/ec"
	"third_party/cryptoc"
)
CROS_WORKON_DESTDIR=(
	"${S}/platform/ec"
	"${S}/third_party/cryptoc"
)

# Prevent automatic uprevs of this package since sarien/arcada FW for ISH
# is stable, and we don't want to introduce risk by taking the latest ToT
# image with every Chrome OS release.
CROS_WORKON_MANUAL_UPREV="1"

inherit cros-workon cros-ish

DESCRIPTION="ECOS ISH image"
HOMEPAGE="https://www.chromium.org/chromium-os/ec-development"

LICENSE="BSD-Google"
KEYWORDS="*"

# Remove the patches once chromeos-ish uses newer EC sources.
PATCHES=(
	"${FILESDIR}/chromeos-ish-ec-warning-06a82155ef.patch"
	"${FILESDIR}/chromeos-ish-ec-glibc-strsignal.patch"
	"${FILESDIR}/chromeos-ish-ec-gcc11.patch"
)
