# Copyright 2015 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"
PYTHON_COMPAT=( python3_{6..11} )

inherit python-single-r1

# To roll grit to a new version:
#  1. Determine the commit to roll to and update GIT_SHA1 below.
#  2. Obtain a tarball corresponding to ${GIT_SHA1} from
#     https://chromium.googlesource.com/chromium/src/tools/grit/+archive/${GIT_SHA1}.tar.gz
#  3. Upload the tarball as ${PN}-${GIT_SHA1}.tar.gz to
#     chromeos-localmirror/distfiles
#  4. Rename the ebuild, using the date corresponding to ${GIT_SHA1}'s commit
#     time stamp as the new version.
GIT_SHA1="73253b76da834152a7cfa76f6b4208694febf4d5"
SRC_URI="gs://chromeos-localmirror/distfiles/${PN}-${GIT_SHA1}.tar.gz"

DESCRIPTION="GRIT - Google Resource and Internationalization Tool"
HOMEPAGE="https://chromium.googlesource.com/chromium/src/tools/grit/"

LICENSE="BSD-2"
SLOT="0"
KEYWORDS="*"
REQUIRED_USE="${PYTHON_REQUIRED_USE}"

DEPEND="${PYTHON_DEPS}"
RDEPEND="${DEPEND}"

S="${WORKDIR}"

PATCHES=(
	"${FILESDIR}"/${PN}-revert-diags.patch
)

src_install() {
	python_domodule grit
	python_newscript grit.py grit

	# Delete unneeded stuff pulled in from the source tree.
	local grit_module_dir="${ED}/$(python_get_sitedir)/grit"
	rm -rf "${grit_module_dir}"/{testdata,grit-todo.xml}
	find "${grit_module_dir}" \
		-regex '.*/\(.*_unittest.*\|PRESUBMIT\)\.py[co]?$' \
		-delete
}
