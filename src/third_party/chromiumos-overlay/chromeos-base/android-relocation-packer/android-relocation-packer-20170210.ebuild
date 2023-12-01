# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="5"

inherit cros-debug toolchain-funcs

DESCRIPTION="Tool for packed relocations in Android."
HOMEPAGE="https://android.googlesource.com/platform/bionic/"

# Snapshot as of 2017-02-10.
BIONIC_GIT_SHA1="43801a50b071279c58d8d3b4d06ce26b39e57a4e"
CORE_GIT_SHA1="f2e615c7b88d5558deadab7b093f9e82cb3c1bba"
SRC_URI="https://android.googlesource.com/platform/bionic/+archive/${BIONIC_GIT_SHA1}/tools/relocation_packer.tar.gz -> ${P}.tar.gz
	https://android.googlesource.com/platform/system/core/+archive/${CORE_GIT_SHA1}/base/include.tar.gz -> android-system-core-base-${PV}.tar.gz
"

LICENSE="Apache-2.0 BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""

RDEPEND="dev-libs/elfutils"
DEPEND="${RDEPEND}"

S="${WORKDIR}"

e() {
	echo "$@"
	"$@"
}

src_compile() {
	e $(tc-getCXX) ${CXXFLAGS} ${CPPFLAGS} ${LDFLAGS} -o relocation_packer \
		-I. -std=c++11 \
		src/debug.cc src/delta_encoder.cc src/elf_file.cc src/main.cc \
		src/packer.cc src/sleb128.cc -lelf || die
}

src_install() {
	dobin relocation_packer
}
