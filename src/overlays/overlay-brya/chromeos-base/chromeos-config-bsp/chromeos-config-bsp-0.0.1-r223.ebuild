# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="2812fcb7b626a17e76b4e55ffaf6bafa7afefe7b"
CROS_WORKON_TREE=("6792c52a60af5d007d5bcd03bcca99dc04a2bb57" "68d6cd3bf8406f87354aba810dcc06485679c08a" "bc756bfa1e1338a2806842ce02f039381b5d0c51" "3871e7f66c62a0b08ec70c4da76474bc20c9fb62" "c540b2f11bc4a003d0fb3e8eb5cd80320d9893fc" "98fd74578511a43345c117e4c45aaabb88d8fdb5" "b6dbd3372edbab317eb8fc47c975822a77b01d2a" "ee0672ff369646a2401f5dcd4777dad07684843c" "0af42a5b9e4fb3c4a173cb854c3bc537b7b62dc5" "7fe84bce29bf90ae979eca67b4e08bec33de28bc" "5de15aaff845e11f66a732606ff7232d53346e2b" "fa3e4c13d4d13c1e7dc37a47d22f29b9be29c2af" "f96201bb2a1e0756af5780d9cf68e8ad90d25711" "a1e2de5d8a4989db30800cd4424e191487a87989" "5a88e185fbab4f866a6bbd99bd6964062f6fddec" "47054b27c241ff7d5249cc5a12bc247810bea83c" "f5190e9ab9bc34fdbdf672a1cdd0f196509141c6" "ad3d5ffd1220da2e75cb496f800bda524a12fad5" "3c694c653a1adcbd81e2a9e0d0369cd35b4640fc" "6a33129fdeb3434c60350fe92fb12350ae6c1363")
inherit cros-constants
CROS_WORKON_REPO="${CROS_GIT_HOST_URL}"

PROJECTS=(
	"adlrvp"
	"anahera"
	"banshee"
	"brya"
	"crota"
	"felwinter"
	"gimble"
	"kano"
	"marasov"
	"mithrax"
	"omnigul"
	"osiris"
	"primus"
	"redrix"
	"skolas"
	"taeko"
	"taniks"
	"vell"
	"volmar"
	"vyhar"
)

CONFIG_PATH="sw_build_config/platform/chromeos-config"

CROS_WORKON_PROJECT=( "chromiumos/project" )
CROS_WORKON_LOCALNAME=( "project_public" )
CROS_WORKON_SUBTREE=( "$(printf "brya/%s/${CONFIG_PATH} " "${PROJECTS[@]}")" )
CROS_WORKON_DESTDIR=( "${PROJECTS[@]/#/${S}/}" )
CROS_BOARDS=( brya )

inherit cros-unibuild cros-workon

DESCRIPTION="Chrome OS Model configuration package for brya"
HOMEPAGE="https://www.chromium.org/chromium-os"
SRC_URI=""

LICENSE="BSD-Google"
SLOT="0/${PF}"
KEYWORDS="* amd64 x86"

RDEPEND="!chromeos-base/chromeos-config-bsp-brya"

src_compile() {
	platform_json_compile
}


src_install() {
	platform_json_install
}
