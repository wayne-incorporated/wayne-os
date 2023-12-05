#!/usr/bin/env python3
# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Make sure packages don't create random paths outside of existing norms."""

import argparse
import fnmatch
import logging
import os
import sys


# NB: Do not add any new entries here without wider discussion.


# Paths that are allowed in the / dir.
#
# NB: We don't allow packages to install into some subdirs because they are
# always bind mounted with the host distro, and we don't want to pollute them.
# Those are: /dev
VALID_ROOT = {
    "bin",
    "etc",
    "home",
    "lib",
    "lib32",
    "lib64",
    "media",
    "mnt",
    "opt",
    "proc",
    "root",
    "run",
    "sbin",
    "sys",
    "usr",
    "var",
}

# Paths that are allowed in the / dir for boards.
VALID_BOARD_ROOT = {
    "boot",
    "build",
    "dev",
    "efi",
    "firmware",
    # TODO(): We should clean this up.
    "postinst",
}

# Paths that are allowed in the / dir for the SDK chroot.
VALID_HOST_ROOT = set()

# Paths under / that should not have any subdirs.
NOSUBDIRS_ROOT = {
    "bin",
    "dev",
    "proc",
    "sbin",
    "sys",
}

# Paths that are allowed in the /usr dir.
VALID_USR = {
    "bin",
    "include",
    "lib",
    "lib32",
    "lib64",
    "libexec",
    "sbin",
    "share",
    "src",
}

# Paths that are allowed in the /usr dir for boards.
VALID_BOARD_USR = {
    # Boards install into /usr/local for test images.
    "local",
}

# Paths that are allowed in the /usr dir for the SDK chroot.
VALID_HOST_USR = set()

# Paths under /usr that should not have any subdirs.
NOSUBDIRS_USR = {
    "bin",
    "sbin",
}

# Valid toolchain targets.  We don't want to add any more non-standard ones.
# targets that use *-cros-* as the vendor are OK to add more.
KNOWN_TARGETS = {
    # These are historical names that we want to change to *-cros-* someday.
    "arm-none-eabi",
    # This is the host SDK name.
    "x86_64-pc-linux-gnu",
    "*-cros-eabi",
    "*-cros-elf",
    "*-cros-linux-gnu*",
}

# These SDK packages need cleanup.
# NB: Do *not* add more packages here.
BAD_HOST_USR_LOCAL_PACKAGES = {
    "app-crypt/nss",
}

# Ignore some packages installing into /var for now.
# NB: Do *not* add more packages here.
BAD_VAR_PACKAGES = {
    "app-accessibility/brltty",
    "app-admin/eselect",
    "app-admin/rsyslog",
    "app-admin/sudo",
    "app-admin/sysstat",
    "app-admin/webapp-config",
    "app-crypt/mit-krb5",
    "app-crypt/trousers",
    "app-emulation/containerd",
    "app-emulation/lxc",
    "chromeos-base/chromeos-initramfs",
    "dev-python/django",
    "media-gfx/sane-backends",  # nocheck
    "media-sound/alsa-utils",
    "net-analyzer/netperf",
    "net-dns/dnsmasq",
    "net-firewall/iptables",
    "net-firewall/nftables",
    "net-fs/samba",
    "net-misc/chrony",
    "net-misc/dhcpcd",
    "net-misc/openssh",
    "net-print/cups",
    "sys-apps/dbus",
    "sys-apps/iproute2",
    "sys-apps/portage",
    "sys-apps/sandbox",
    "sys-apps/systemd",
    "sys-apps/usbguard",
    "sys-kernel/loonix-initramfs",
    "sys-libs/glibc",
    "sys-process/audit",
    "www-servers/nginx",
    "x11-base/xwayland",
}

# Ignore some packages installing into /run for now.
# NB: Do *not* add more packages here.
BAD_RUN_PACKAGES = {
    "app-accessibility/brltty",
    "net-fs/samba",
}


def has_subdirs(path):
    """See if |path| has any subdirs."""
    # These checks are helpful for manually running the script when debugging.
    if os.path.ismount(path):
        logging.warning("Ignoring mounted dir for subdir check: %s", path)
        return False

    if os.path.join(os.getenv("SYSROOT", "/"), "tmp") == path:
        logging.warning("Ignoring live dir: %s", path)
        return False

    for _, dirs, _ in os.walk(path):
        if dirs:
            logging.error(
                "Subdirs found in a dir that should be empty:\n  %s\n"
                "  |-- %s",
                path,
                "\n  |-- ".join(sorted(dirs)),
            )
            return True
        break

    return False


def check_usr(usr, host=False):
    """Check the /usr filesystem at |usr|."""
    ret = True

    # Not all packages install into /usr.
    if not os.path.exists(usr):
        return ret

    atom = get_current_package()
    paths = set(os.listdir(usr))
    unknown = paths - VALID_USR
    for target in KNOWN_TARGETS:
        unknown = set(x for x in unknown if not fnmatch.fnmatch(x, target))
    if host:
        unknown -= VALID_HOST_USR

        if atom in BAD_HOST_USR_LOCAL_PACKAGES:
            logging.warning("Ignoring known bad /usr/local install for now")
            unknown -= {"local"}
    else:
        unknown -= VALID_BOARD_USR

        if atom in {"chromeos-base/ap-daemons"}:
            logging.warning("Ignoring known bad /usr install for now")
            unknown -= {"www"}

    if unknown:
        logging.error(
            "Paths are not allowed in the /usr dir: %s", sorted(unknown)
        )
        ret = False

    for path in NOSUBDIRS_USR:
        if has_subdirs(os.path.join(usr, path)):
            logging.error(
                "%s: Path is not allowed to have subdirectories", path
            )
            ret = False

    return ret


def check_root(root, host=False):
    """Check the filesystem |root|."""
    ret = True

    atom = get_current_package()
    paths = set(os.listdir(root))
    unknown = paths - VALID_ROOT
    if host:
        unknown -= VALID_HOST_ROOT
    else:
        unknown -= VALID_BOARD_ROOT

    if unknown:
        logging.error(
            "Paths are not allowed in the root dir:\n  %s\n  |-- %s",
            root,
            "\n  |-- ".join(sorted(unknown)),
        )
        ret = False

    # Some of these may have subdirs at runtime, but not from package installs.
    for path in NOSUBDIRS_ROOT:
        if has_subdirs(os.path.join(root, path)):
            ret = False

    # Special case /var due to so many misuses currently.
    if os.path.exists(os.path.join(root, "var")):
        if atom in BAD_VAR_PACKAGES:
            logging.warning("Ignoring known bad /var install for now")
        elif os.environ.get("PORTAGE_REPO_NAME") == "portage-stable":
            logging.warning(
                "Ignoring bad /var install with portage-stable package "
                "for now"
            )
        else:
            logging.error(
                "Installing files or directories in /var is not allowed; "
                "these must be created at runtime only (e.g. via tmpfiles.d)"
            )
            ret = False
    else:
        if atom in BAD_VAR_PACKAGES:
            logging.warning(
                "Package has improved; please update BAD_VAR_PACKAGES"
            )

    # Special case /run due to so many misuses currently.
    if os.path.exists(os.path.join(root, "run")):
        if atom in BAD_RUN_PACKAGES:
            logging.warning("Ignoring known bad /run install for now")
        elif os.environ.get("PORTAGE_REPO_NAME") == "portage-stable":
            logging.warning(
                "Ignoring bad /run install with portage-stable package "
                "for now"
            )
        else:
            logging.error(
                "Installing files or directories in /run is not allowed; "
                "these must be created at runtime only (e.g. via tmpfiles.d)"
            )
            ret = False
    else:
        if atom in BAD_RUN_PACKAGES:
            logging.warning(
                "Package has improved; please update BAD_RUN_PACKAGES"
            )

    if not check_usr(os.path.join(root, "usr"), host):
        ret = False

    return ret


def get_current_package():
    """Figure out what package is being built currently."""
    if "CATEGORY" in os.environ and "PN" in os.environ:
        return f'{os.environ.get("CATEGORY")}/{os.environ.get("PN")}'
    else:
        return None


def get_parser():
    """Get a CLI parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--host",
        default=None,
        action="store_true",
        help="the filesystem is the host SDK, not board sysroot",
    )
    parser.add_argument(
        "--board",
        dest="host",
        action="store_false",
        help="the filesystem is a board sysroot",
    )
    parser.add_argument("root", nargs="?", help="the rootfs to scan")
    return parser


def main(argv):
    """The main func!"""
    parser = get_parser()
    opts = parser.parse_args(argv)

    # Default to common portage env vars.
    if opts.root is None:
        for var in ("ED", "D", "ROOT"):
            if var in os.environ:
                logging.debug("Scanning filesystem root via $%s", var)
                opts.root = os.environ[var]
                break
    if not opts.root:
        parser.error("Need a valid rootfs to scan, but unable to detect one")

    if opts.host is None:
        if os.getenv("BOARD") == "amd64-host":
            opts.host = True
        else:
            opts.host = not bool(os.getenv("SYSROOT"))

    if not check_root(opts.root, opts.host):
        logging.critical(
            "Package '%s' does not conform to CrOS's filesystem conventions. "
            "Please review the paths flagged above and adjust its layout.",
            get_current_package(),
        )
        return 1
    else:
        return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
