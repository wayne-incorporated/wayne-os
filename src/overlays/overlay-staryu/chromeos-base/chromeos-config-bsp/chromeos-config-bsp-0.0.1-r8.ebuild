# Copyright 2023 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="4e96af261c9bd1a2b9ae4f6b14bd3501ae0b8631"
CROS_WORKON_TREE=("7c6c7b2fd071ea1045c5bcbc352e0e327adea481" "6a09290d8d3bb651e9bee291e1d1c67db93a9146")
inherit cros-constants
CROS_WORKON_REPO="${CROS_GIT_HOST_URL}"

PROJECTS=(
	"starmie"
	"staryu"
)

CONFIG_PATH="sw_build_config/platform/chromeos-config"

CROS_WORKON_PROJECT=( "chromiumos/project" )
CROS_WORKON_LOCALNAME=( "project_public" )
CROS_WORKON_SUBTREE=( "$(printf "staryu/%s/${CONFIG_PATH} " "${PROJECTS[@]}")" )
CROS_WORKON_DESTDIR=( "${PROJECTS[@]/#/${S}/}" )
CROS_BOARDS=( staryu )

inherit cros-unibuild cros-workon

DESCRIPTION="Chrome OS Model configuration package for staryu"
HOMEPAGE="https://www.chromium.org/chromium-os"
SRC_URI=""

LICENSE="BSD-Google"
SLOT="0/${PF}"
KEYWORDS="*"

RDEPEND="!chromeos-base/chromeos-config-bsp-staryu"

src_compile() {
	platform_json_compile
}


src_install() {
	platform_json_install
}
