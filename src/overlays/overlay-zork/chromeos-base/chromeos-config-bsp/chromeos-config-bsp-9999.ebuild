# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=6

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
KEYWORDS="~* ~amd64 ~x86"
RDEPEND="!chromeos-base/chromeos-config-bsp-zork"


src_compile() {
	platform_json_compile
}


src_install() {
	platform_json_install
}
