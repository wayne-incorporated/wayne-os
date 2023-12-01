# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="b055a12c5cdedac4e8e29559297b2c5dcf5a111b"
CROS_WORKON_TREE=("3355800303e61a967e049db2355d46ebc1620e53" "a43d692c2c840441583b8074fd6a9b46837b2238" "6085df404843bb7bca9360e31c6835cac3b66b3e" "d4546f7b9c14f008a8678913a4bd3b5538061608" "7a97b0191067dfaddee8da6bb094c490f2b5c0e1" "e1fda3408acbba233775401fe1bec3853688c6d2" "7c99bc8b2dd736ee0e2fe04908535b931a3b9707")
inherit cros-constants
CROS_WORKON_REPO="${CROS_GIT_HOST_URL}"

PROJECTS=(
	"evoker"
	"herobrine"
	"hoglin"
	"piglin"
	"villager"
	"zoglin"
	"zombie"
)

CONFIG_PATH="sw_build_config/platform/chromeos-config"

CROS_WORKON_PROJECT=( "chromiumos/project" )
CROS_WORKON_LOCALNAME=( "project_public" )
CROS_WORKON_SUBTREE=( "$(printf "herobrine/%s/${CONFIG_PATH} " "${PROJECTS[@]}")" )
CROS_WORKON_DESTDIR=( "${PROJECTS[@]/#/${S}/}" )
CROS_BOARDS=( herobrine )

inherit cros-unibuild cros-workon

DESCRIPTION="Chrome OS Model configuration package for herobrine"
HOMEPAGE="https://www.chromium.org/chromium-os"
SRC_URI=""

LICENSE="BSD-Google"
SLOT="0/${PF}"
KEYWORDS="*"
RDEPEND="!chromeos-base/chromeos-config-bsp-herobrine"


src_compile() {
	platform_json_compile
}


src_install() {
	platform_json_install
}
