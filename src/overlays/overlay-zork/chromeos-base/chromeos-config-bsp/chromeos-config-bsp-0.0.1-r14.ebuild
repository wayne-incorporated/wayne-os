# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=6

CROS_WORKON_COMMIT="b055a12c5cdedac4e8e29559297b2c5dcf5a111b"
CROS_WORKON_TREE=("0d2d9be2eb2060a28464f1e546d37c5a94477ed6" "db7d8edc812e453bebe9eef15c5732d81208cab6" "6fed9b554db588a320deffc8627f8fe3b2e341b7" "492f6fdc5e1832dc70f7e5afda49ec76408ed34d" "1efaa46474c2a6599a3d9cf0bc024f7bb1e21ba5" "1e5ccc1f34e1368802a6933d724cbb9c9db64baa" "badef1b7126563a1c8a500aaeaf12ecb6b86dcb3" "bddc501244cfd88ad405175155ac697c6a4d639a")
inherit cros-constants
CROS_WORKON_REPO="${CROS_GIT_HOST_URL}"

PROJECTS=(
    "berknip"
    "dalboz"
    "dirinboz"
    "ezkinil"
    "morphius"
    "trembyle"
    "vilboz"
    "woomax"
)

CONFIG_PATH="sw_build_config/platform/chromeos-config"

CROS_WORKON_PROJECT=( "chromiumos/project" )
CROS_WORKON_LOCALNAME=( "project_public" )
CROS_WORKON_SUBTREE=( "$(printf "zork/%s/${CONFIG_PATH} " "${PROJECTS[@]}")" )
CROS_WORKON_DESTDIR=( "${PROJECTS[@]/#/${S}/}" )
CROS_BOARDS=( zork )

inherit cros-unibuild cros-workon

DESCRIPTION="Chrome OS Model configuration package for zork"
HOMEPAGE="https://www.chromium.org/chromium-os"
SRC_URI=""

LICENSE="BSD-Google"
SLOT="0/${PF}"
KEYWORDS="* amd64 x86"
RDEPEND="!chromeos-base/chromeos-config-bsp-zork"


src_compile() {
	platform_json_compile
}


src_install() {
	platform_json_install
}
