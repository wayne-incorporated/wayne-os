# Copyright 2012 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="c0b4726937bec74b465396f700614e75cd0c8a9a"
CROS_WORKON_TREE="a702e15e0ddd15efe8421377b87fafe7309bb025"
CROS_WORKON_PROJECT="chromiumos/platform/libevdev"
CROS_WORKON_USE_VCSID=1
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_LOCALNAME="platform/libevdev"

inherit cros-debug cros-sanitizers cros-workon cros-common.mk

DESCRIPTION="evdev userspace library"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/libevdev"

LICENSE="BSD-Google"
KEYWORDS="*"
IUSE="-asan"
SLOT="0/1"

src_configure() {
	sanitizers-setup-env
	cros-common.mk_src_configure
}

src_install() {
	emake DESTDIR="${ED}" LIBDIR="/usr/$(get_libdir)" install
}
