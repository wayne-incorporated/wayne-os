# Copyright 2013 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

DESCRIPTION="Metapackage that provides the implicit system
dependencies of anything CrOS-ish. These are things like 'mv', 'ls',
'mkfs', 'a shell', 'c libraries', users and groups, SSL certs, etc. If
every package had to specify them, it'd be onerous and also difficult
to replace them with other functional equivalents.

Developers should assume that this metapackage supplies functionality
roughly equivalent to a POSIX-compliant system. Each package we include here
has justification provided inline. For further reference, see
POSIX (1003.1-2008): http://pubs.opengroup.org/onlinepubs/9699919799/idx/utilities.html
FHS: http://www.pathname.com/fhs/pub/fhs-2.3.html

Other than the standard C and C++ libraries (libc, libpthreads, libstdc++, etc),
if you're linking against a library that happens to be installed by a package
listed here, you MUST also depend on the appropriate package.


Exclusions:
compression utils, e.g. tar/bzip2/gzip: at this time, we don't store data
compressed on the rootfs, and don't expect users to be interacting on the
command line. If your daemon needs functionality like this, ideally you'd
use a library that implements this functionality and not command-line tools.

iputils: ping et al are helpful diagnostic tools, but not required for normal
system function."

HOMEPAGE="http://src.chromium.org"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"
IUSE=""

RDEPEND=""

# We need a /bin/sh shell.
RDEPEND+=" app-shells/dash"

# We need our custom /etc/passwd and friends, as well as some symlinks:
#  /bin/sh
#  /usr/bin/awk
RDEPEND+=" chromeos-base/chromeos-base"

# Many packages need a blessed list of SSL certificates. For non Google
# distributed Chromium OS systems, that's the Mozilla NSS set, which is
# installed by app-misc/ca-certificates from portable-stable. The old
# chromiumos-overlay for - chromeos-base/root-certificates has been deleted. See
# https://chromium.googlesource.com/chromiumos/docs/+/master/ca_certs.md for
# more details.
RDEPEND+="
	app-misc/ca-certificates
	!chromeos-base/root-certificates
"

# Basic FHS setup.
RDEPEND+=" sys-apps/baselayout"

# We use a fair amount of shell script, and need common tools:
#  general tools: echo, env, expr, false, printf, pwd, sleep, test, true
#  stream tools: cat, head, sort, tail
#  filesystem tools: cp, dd, ln, ls, mkdir, mkfifo, mknod, mv, readlink, rm,
#                    rmdir, sync, touch
#  permission tools: chgrp, chmod, chown, id
#  process tools: chroot, nice, nohup
RDEPEND+=" sys-apps/coreutils"

# Those scripts also need some non-core utils:
#  awk -- symlink to mawk is created in chromeos-base
#  find
#  grep
#  sed
#  which -- frequently used to check for installed software.
RDEPEND+="
	sys-apps/findutils
	sys-apps/grep
	sys-apps/mawk
	sys-apps/sed
	sys-apps/which
"

# Scripts often manage process lifetime with tools like:
#  kill
#  ps
#  sysctl
# Some user utils are installed here as well (top, free, uptime) but
# there's no guarantee that will always be so.
RDEPEND+=" sys-process/procps"

# Required:
#  hostname.
# ipconfig et al are useful, but should be provided by your build
# profile if you need them.
RDEPEND+=" sys-apps/net-tools"

# Required:
#  su
# NB: Password management tools ({group,user}{add,del,mod}) are part of the
# build system.
RDEPEND+=" sys-apps/shadow"

# Required:
#  dmesg, flock, ionice, logger, mount, umount.
# Provided currently, but not guaranteed:
#  agetty, getopt, hexdump, fsck
RDEPEND+=" sys-apps/util-linux"

# Provides gcc runtime libs.
RDEPEND+=" sys-libs/gcc-libs"

# Provides libc++ libs.
RDEPEND+="
	sys-libs/llvm-libunwind
	sys-libs/libcxx
"

# This should be dropped once we have converted to 'virtual/libc'.
RDEPEND+=" sys-libs/timezone-data"

DEPEND="${RDEPEND}"
