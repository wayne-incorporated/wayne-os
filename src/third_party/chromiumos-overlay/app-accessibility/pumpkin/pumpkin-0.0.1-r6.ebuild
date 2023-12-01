# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v3
#
# JavaScript/Web assembly port of the Pumpkin semantic parser.

EAPI=7

CROS_WORKON_COMMIT="d2d95e8af89939f893b1443135497c1f5572aebc"
CROS_WORKON_TREE="776139a53bc86333de8672a51ed7879e75909ac9"
inherit cros-workon dlc

DESCRIPTION='Pumpkin is a semantic parser built using web assembly and a
JavaScript API. This DLC downloads the web assembly, JavaScript wrapper, and
locale-specific binary files, which are all built in google3. Pumpkin is
currently used by accessibility services on Chrome OS.'
HOMEPAGE=""
SRC_URI="gs://chromeos-localmirror/distfiles/${PN}-3.0.tar.xz"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE="dlc"
REQUIRED_USE="dlc"

# "cros_workon info" expects these variables to be set, so use the standard
# empty project.
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="../platform/empty-project"

# DLC variables.
# The total size of the Pumpkin DLC is 5.9MB.
# DLC_PREALLOC_BLOCKS = (DLC_SIZE * 1.3) / 4000 = 1917.5.
DLC_PREALLOC_BLOCKS="1918"

S="${WORKDIR}"
src_unpack() {
	local archive="${SRC_URI##*/}"
	unpack "${archive}"
}

src_install() {
	# Install main Pumpkin WASM and PumpkinTagger JS wrapper files.
	into "$(dlc_add_path /)"
	insinto "$(dlc_add_path /)"
	exeinto "$(dlc_add_path /)"
	doins js_pumpkin_tagger_bin.js tagger_wasm_main.js tagger_wasm_main.wasm

	# Install binary Pumpkin configs for each supported locale.
	local locales=("en_us" "fr_fr" "es_es" "de_de" "it_it")
	for locale in "${locales[@]}"; do
		doins -r "${locale}"
	done

	dlc_src_install
}
