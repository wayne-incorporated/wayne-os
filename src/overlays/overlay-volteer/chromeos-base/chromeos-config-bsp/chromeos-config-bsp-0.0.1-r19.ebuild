# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=6

CROS_WORKON_COMMIT="b055a12c5cdedac4e8e29559297b2c5dcf5a111b"
CROS_WORKON_TREE=("5c8b935639394fe90401127d5d15fdebab0fe953" "c4fa094fb3f496c846de81a05c9ab99e7f85c56c" "bd6dcc4807e9daa9b0caf68eb51111598a8c8c7d" "aab305d71cb057717c1aefc540d972d778a208f3" "493d13ffa0d4311db7172e43da8b2f32c081fe56" "bb337cab4eff521610f340950b62e9a826fb6565" "72229de1d3b83d298460637a16e95d1edaa9e00d" "c9a8cf19c07da09081ef600288b1e1b9fc9541dc" "12b813045e5ad50ea64b4f3f5d667d9b49370f4c" "07397bbbb7b533380a848edfcaec847edfbb18c6" "1f6e20f7acd80dce1a9b69bb20c623e219ed219f" "f161715b365c702d4eb5fa8d9fce15acf7277b7a" "ac930915c574d2863d29e6e748d1699fe224339b")
inherit cros-constants
CROS_WORKON_REPO="${CROS_GIT_HOST_URL}"

PROJECTS=(
	"chronicler"
	"collis"
	"copano"
	"delbin"
	"drobit"
	"eldrid"
	"elemi"
	"lindar"
	"terrador"
	"voema"
	"volet"
	"volteer"
	"voxel"
)

CONFIG_PATH="sw_build_config/platform/chromeos-config"

CROS_WORKON_PROJECT=( "chromiumos/project" )
CROS_WORKON_LOCALNAME=( "project_public" )
CROS_WORKON_SUBTREE=( "$(printf "volteer/%s/${CONFIG_PATH} " "${PROJECTS[@]}")" )
CROS_WORKON_DESTDIR=( "${PROJECTS[@]/#/${S}/}" )
CROS_BOARDS=( volteer )

inherit cros-unibuild cros-workon

DESCRIPTION="Chrome OS Model configuration package for volteer"
HOMEPAGE="https://www.chromium.org/chromium-os"
SRC_URI=""

LICENSE="BSD-Google"
SLOT="0/${PF}"
KEYWORDS="* amd64 x86"
RDEPEND="!chromeos-base/chromeos-config-bsp-volteer"


src_compile() {
	platform_json_compile
}


src_install() {
	platform_json_install
}
