# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Package responsible for setting up the sane test backend"
HOMEPAGE="http://www.sane-project.org/"

LICENSE="BSD-Google"
KEYWORDS="*"
SLOT="0/0"
S="${WORKDIR}"

RDEPEND="
	>=media-gfx/sane-backends-1.0.31-r2
	<media-gfx/sane-backends-2
"

src_install() {
	local sane_libdir="/usr/$(get_libdir)/sane"
	dodir "${sane_libdir}"
	local local_libdir="${ED}/usr/local/$(get_libdir)"
	local lib_names="
		libsane-test.so
		libsane-test.so.1
	"
	for lib in ${lib_names}; do
		# Don't use dosym since we'd need to explicitly specify the
		# relative symlink
		# (i.e. 'dosym "../../local/$(get_libdir)/${lib}" [...]').
		ln -rs "${local_libdir}/${lib}" "${ED}/${sane_libdir}" || die
	done
}
