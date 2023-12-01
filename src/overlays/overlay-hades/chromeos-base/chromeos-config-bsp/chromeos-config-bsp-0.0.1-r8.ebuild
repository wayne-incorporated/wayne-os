# Copyright 2023 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="b055a12c5cdedac4e8e29559297b2c5dcf5a111b"
CROS_WORKON_TREE=("bc4fb970880c36cc0e92c1b71019592e0f4de45e" "4cf547be7af44082e2fd5d12d76a8a4f1b625bd8" "2d8e3c2c08148272b455e9e3b0461dd5859794e5")
inherit cros-constants
CROS_WORKON_REPO="${CROS_GIT_HOST_URL}"

PROJECTS=(
	"cora"
	"hades"
	"zeus"
)

CONFIG_PATH="sw_build_config/platform/chromeos-config"

CROS_WORKON_PROJECT=( "chromiumos/project" )
CROS_WORKON_LOCALNAME=( "project_public" )
CROS_WORKON_SUBTREE=( "$(printf "hades/%s/${CONFIG_PATH} " "${PROJECTS[@]}")" )
CROS_WORKON_DESTDIR=( "${PROJECTS[@]/#/${S}/}" )
CROS_BOARDS=( hades )

inherit cros-unibuild cros-workon

DESCRIPTION="Chrome OS Model configuration package for hades"
HOMEPAGE="https://www.chromium.org/chromium-os"
SRC_URI=""

LICENSE="BSD-Google"
SLOT="0/${PF}"
KEYWORDS="* amd64 x86"
RDEPEND="!chromeos-base/chromeos-config-bsp-hades"


src_compile() {
	platform_json_compile
}


src_install() {
	platform_json_install
}
