# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=6

CROS_WORKON_COMMIT="b055a12c5cdedac4e8e29559297b2c5dcf5a111b"
CROS_WORKON_TREE=("2170490e00c4882c1ebef70275ae93e463d99be7" "ec62ffa86ffa55279341f2a58ed16b0fa76b2646" "91e9c1ff412b0fbd124a2e5e7ec5e61b9f1ce645" "40c8024e931f2ad32735c5863b4335edc9a7382a" "b8d5e1771666eb7f99b9dee205a5b00b71136fdb" "e5c6cca8788e6b1a4847c7d6892e7ae80af9e1ee" "5b3662133cc88ddf9433c73399f5bad98cfee35f")
inherit cros-constants
CROS_WORKON_REPO="${CROS_GIT_HOST_URL}"

PROJECTS=(
	"dooly"
    "duffy"
    "faffy"
    "kaisa"
    "noibat"
    "puff"
    "wyvern"
)

CONFIG_PATH="sw_build_config/platform/chromeos-config"

CROS_WORKON_PROJECT=( "chromiumos/project" )
CROS_WORKON_LOCALNAME=( "project_public" )
CROS_WORKON_SUBTREE=( "$(printf "puff/%s/${CONFIG_PATH} " "${PROJECTS[@]}")" )
CROS_WORKON_DESTDIR=( "${PROJECTS[@]/#/${S}/}" )
CROS_BOARDS=( puff )

inherit cros-unibuild cros-workon

DESCRIPTION="Chrome OS Model configuration package for puff"
HOMEPAGE="https://www.chromium.org/chromium-os"
SRC_URI=""

LICENSE="BSD-Google"
SLOT="0/${PF}"
KEYWORDS="* amd64 x86"
RDEPEND="!chromeos-base/chromeos-config-bsp-puff"


src_compile() {
	platform_json_compile
}


src_install() {
	platform_json_install
}
