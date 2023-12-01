# Copyright 2023 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

# This ebuild only cares about its own FILESDIR and ebuild file, so it tracks
# the canonical empty project.
CROS_WORKON_COMMIT="d2d95e8af89939f893b1443135497c1f5572aebc"
CROS_WORKON_TREE="776139a53bc86333de8672a51ed7879e75909ac9"
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="../platform/empty-project"

inherit cros-workon

DESCRIPTION="List of packages needed to generate a Stage 2 and Stage 3 SDK
tarball. This set of packages should be as small as possible. All the packages
listed here will be implicit dependencies to ALL packages built by bazel. This
means that if any of these dependencies change, all packages will be rebuilt.
If a package needs a host tool that is not listed here it should be listed in
the package's BDEPEND. The USE flags for these packages should also be adjusted
to limit the number of runtime dependencies that are pulled in."
HOMEPAGE="https://chromium.googlesource.com/chromiumos/bazel/+/refs/heads/main/README.md"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"

# Primordial packages.
RDEPEND="
	virtual/libc
	virtual/os-headers
	sys-libs/libcxx
	sys-libs/llvm-libunwind
"

RDEPEND+="
	sys-apps/baselayout
"

# Implicit system
RDEPEND+="
	app-arch/lbzip2
	app-arch/pigz
	app-arch/pixz
	app-misc/pax-utils
	app-shells/bash
	sys-apps/coreutils
	sys-apps/diffutils
	sys-apps/findutils
	sys-apps/gawk
	sys-apps/gentoo-functions
	sys-apps/grep
	sys-apps/sed
	sys-devel/patch
	sys-process/procps
	virtual/package-manager
"

# Build tools for C languages.
#
# We only include LLVM and exclude GCC. If any packages need GCC they should
# list it in their BDEPEND.
RDEPEND+="
	dev-util/pkgconfig
	sys-devel/binutils
	sys-devel/llvm
	sys-devel/make
"

# Needed for toolchain wrapper error messages
RDEPEND+="
	sys-process/psmisc
"

# We pick the smallest editor possible.
RDEPEND+="
	app-editors/nano
"

# We need a go compiler to compile go.
RDEPEND+="
	dev-lang/go
"
