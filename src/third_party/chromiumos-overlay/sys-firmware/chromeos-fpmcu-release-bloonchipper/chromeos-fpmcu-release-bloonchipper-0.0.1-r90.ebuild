# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# Increment the "eclass bug workaround count" below when you change
# "cros-ec-release.eclass" to work around https://issuetracker.google.com/201299127.
#
# eclass bug workaround count: 8

EAPI=7

CROS_WORKON_COMMIT=("2bcf863b492fe7ed8105c853814dba6ed32ba719" "1e26cef0adb1dd12638787147427c49ebf68b556" "0dd679081b9c8bfa2583d74e3a17a413709ea362")
CROS_WORKON_TREE=("fcf6ce5810f9ff9e3c8cce434812dd75492269ed" "2c77954aa1b501a92387e6456b6f5176be0e86a5" "d99abee3f825248f344c0638d5f9fcdce114b744")
FIRMWARE_EC_BOARD="bloonchipper"
FIRMWARE_EC_RELEASE_REPLACE_RO="yes"

CROS_WORKON_PROJECT=(
	"chromiumos/platform/ec"
	"chromiumos/third_party/tpm2"
	"chromiumos/third_party/cryptoc"
)

CROS_WORKON_LOCALNAME=(
	"../platform/release-firmware/fpmcu-bloonchipper"
	"tpm2"
	"cryptoc"
)

CROS_WORKON_DESTDIR=(
	"${S}/platform/ec"
	"${S}/third_party/tpm2"
	"${S}/third_party/cryptoc"
)

CROS_WORKON_EGIT_BRANCH=(
	"firmware-fpmcu-bloonchipper-release"
	"master"
	"master"
)

inherit cros-workon cros-ec-release cros-sanitizers

HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/ec/+/master/README.md"
LICENSE="BSD-Google"
KEYWORDS="*"

src_configure() {
	sanitizers-setup-env
	default
}
