# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit toolchain-funcs

DESCRIPTION="Plugins for Yosys developed as part of the F4PGA project"
HOMEPAGE="https://github.com/chipsalliance/yosys-f4pga-plugins"

GIT_REV="52cdcc42db527087fb342b4dabdb1a79878266cb"

SRC_URI="
	https://github.com/chipsalliance/yosys-f4pga-plugins/archive/${GIT_REV}.tar.gz -> ${PN}-${GIT_REV}.tar.gz
"

S="${WORKDIR}/${PN}-${GIT_REV}"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"

DEPEND="sci-electronics/yosys"
RDEPEND="sci-electronics/yosys:="

src_compile() {
	# For now, we just build and install this one plugin, because that's all
	# that HPS uses. Some of the other plugins have extra dependencies which
	# aren't packaged in ChromiumOS. We could expand this to build more plugins
	# in future if needed.
	emake -C dsp-ff-plugin all
}

src_test() {
	# Can't run the tests because there's no way to make yosys find a plugin
	# before it's been installed into /usr/share/yosys/plugins. :-(
	#emake -C dsp-ff-plugin/tests
	:
}

src_install() {
	emake -C dsp-ff-plugin install DESTDIR="${D}"
}
