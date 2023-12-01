#!/usr/bin/env python3
# Copyright 2013 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Wrapper for running platform2 tests.

This handles the fun details like running against the right sysroot, via
qemu, bind mounts, etc...
"""

import argparse
import contextlib
import ctypes
import ctypes.util
import errno
import os
from pathlib import Path
import pwd
import re
import signal
import stat
import sys
import tempfile

import psutil  # pylint: disable=import-error

from chromite.lib import build_target_lib
from chromite.lib import commandline
from chromite.lib import namespaces
from chromite.lib import osutils
from chromite.lib import process_util
from chromite.lib import proctitle
from chromite.lib import qemu
from chromite.lib import retry_util
from chromite.lib import signals


PR_SET_CHILD_SUBREAPER = 0x24
libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)


def _MakeProcessSubreaper():
    """Marks the current process as a subreaper.

    This causes all orphaned processes to be reparented to this process instead
    of the init process.
    """
    if libc.prctl(ctypes.c_int(PR_SET_CHILD_SUBREAPER), ctypes.c_int(1)) != 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))


def _ReapUntilProcessExits(monitored_pid):
    """Reap processes until |monitored_pid| exits, then return its exit status.

    This will also reap any other processes ready to be reaped immediately after
    |monitored_pid| is reaped.
    """
    pid_status = None
    options = 0
    while True:
        try:
            (pid, status, _) = os.wait3(options)

            # Capture status of monitored_pid so we can return it.
            if pid == monitored_pid:
                pid_status = status
                # Switch to nohang so we can churn through the zombies
                # w/out getting stuck on live orphaned processes.
                options = os.WNOHANG

            # There may be some more child processes still running,
            # but none of them have exited/finished.  Don't wait for
            # those as we'll throw an error in the caller.
            if pid_status is not None and pid == 0 and status == 0:
                break
        except OSError as e:
            if e.errno == errno.ECHILD:
                break
            elif e.errno != errno.EINTR:
                raise
    return pid_status


SAN_OPTIONS = re.compile(r"[A-Z]{1,3}SAN_OPTIONS$")

# Compiled regular expressions for determining what environment variables to
# let through to the test env when we do sudo. If any character at the
# beginning of an environment variable matches one of the regular expression
# patterns (i.e. matching via re.match), the environment variable is let
# through.
ENV_PASSTHRU_REGEX_LIST = list(
    re.compile(x)
    for x in (
        # Used by various sanitizers.
        SAN_OPTIONS,
        # Used by QEMU.
        r"QEMU_",
        # Used to select profiling output location for gcov.
        r"GCOV_",
        # Used to select profiling output location for llvm instrumented
        # binaries.
        r"^LLVM_PROFILE_FILE$",
        # Used by unit tests to access test binaries.
        r"^OUT$",
        # Used by unit tests to access source data files.
        r"^SRC$",
        # Used by unit tests to access data files outside of the source tree.
        r"^T$",
        # Used by unit tests to increase test reproducibility.
        r"^MALLOC_PERTURB_$",
    )
)


class Platform2Test(object):
    """Framework for running platform2 tests"""

    _BIND_RW_MOUNT_PATHS = (
        "dev/pts",
        "dev/shm",
    )
    _BIND_RO_MOUNT_PATHS = (
        "sys",
        "mnt/host/source",
    )

    def __init__(
        self,
        test_bin,
        board,
        host,
        framework,
        user,
        gtest_filter,
        user_gtest_filter,
        sysroot,
        bind_mount_dev,
        env_vars,
        test_bin_args,
    ):
        if not test_bin_args:
            test_bin_args = [test_bin]
        if not test_bin:
            test_bin = test_bin_args[0]
        self.bin = test_bin
        self.env_vars = env_vars
        self.args = test_bin_args
        self.board = board
        self.host = host
        self.user = user
        self.bind_mount_dev = bind_mount_dev
        (self.gtest_filter, self.user_gtest_filter) = self.generateGtestFilter(
            gtest_filter, user_gtest_filter
        )

        if sysroot:
            self.sysroot = sysroot
        else:
            self.sysroot = build_target_lib.get_default_sysroot_path(self.board)

        self.framework = framework
        if self.framework == "auto":
            qemu_arch = qemu.Qemu.DetectArch(self.bin, self.sysroot)
            if qemu_arch is None:
                self.framework = "ldso"
            else:
                self.framework = "qemu"
        elif self.framework == "qemu":
            qemu_arch = qemu.Qemu.DetectArch(self.bin, self.sysroot)
        if self.framework == "qemu":
            assert qemu_arch, (
                "failed to detect qemu arch: "
                "confirm that qemu is supported on your system"
            )
            self.qemu = qemu.Qemu(self.sysroot, arch=qemu_arch)

    @classmethod
    def generateGtestSubfilter(cls, gtest_filter):
        """Split a gtest_filter down into positive and negative filters.

        Args:
            gtest_filter: A filter string as normally passed to --gtest_filter.

        Returns:
            A tuple of format (positive_filters, negative_filters).
        """

        filters = gtest_filter.split("-", 1)
        positive_filters = [x for x in filters[0].split(":") if x]
        if len(filters) > 1:
            negative_filters = [x for x in filters[1].split(":") if x]
        else:
            negative_filters = []

        return (positive_filters, negative_filters)

    @classmethod
    def generateGtestFilter(cls, filters, user_filters):
        """Merge internal gtest filters and user-supplied gtest filters.

        Returns:
            A string that can be passed to --gtest_filter.
        """

        gtest_filter = cls.generateGtestSubfilter(filters)
        user_gtest_filter = []

        if user_filters:
            filters = user_filters.split("::")[-1]
            user_gtest_filter = cls.generateGtestSubfilter(filters)

        return (gtest_filter, user_gtest_filter)

    def removeSysrootPrefix(self, path):
        """Returns the given path with any sysroot prefix removed."""
        # If the sysroot is /, then the paths are already normalized.
        if self.sysroot != "/" and path.startswith(self.sysroot):
            path = path.replace(self.sysroot, "", 1)

        return path

    @staticmethod
    def GetNonRootAccount(user):
        """Return details about the non-root account we want to use.

        Args:
            user: User to lookup.  If None, try the active user, then 'nobody'.

        Returns:
            A tuple of (username, uid, gid, home).
        """
        if user is not None:
            # Assume the account is a UID first.
            try:
                acct = pwd.getpwuid(int(user))
            except (KeyError, ValueError):
                # Assume it's a name then.
                try:
                    acct = pwd.getpwnam(user)
                except ValueError as e:
                    print("error: %s: %s" % (user, e), file=sys.stderr)
                    sys.exit(1)

                return (acct.pw_name, acct.pw_uid, acct.pw_gid, acct.pw_dir)

        return (
            os.environ.get("SUDO_USER", "nobody"),
            int(os.environ.get("SUDO_UID", "65534")),
            int(os.environ.get("SUDO_GID", "65534")),
            # Should we find a better home?
            "/tmp/portage",
        )

    @staticmethod
    @contextlib.contextmanager
    def LockDb(db):
        """Lock an account database.

        We use the same algorithm as shadow/user.eclass.  This way we don't race
        and corrupt things in parallel.
        """
        lock = "%s.lock" % db
        _, tmplock = tempfile.mkstemp(prefix="%s.platform." % lock)

        # First try forever to grab the lock.
        retry = lambda e: e.errno == errno.EEXIST
        # Retry quickly at first, but slow down over time.
        try:
            retry_util.GenericRetry(
                retry, 60, os.link, tmplock, lock, sleep=0.1
            )
        except Exception:
            print(
                "error: timeout: could not grab lock %s" % lock, file=sys.stderr
            )
            raise

        # Yield while holding the lock, but try to clean it no matter what.
        try:
            os.unlink(tmplock)
            yield lock
        finally:
            os.unlink(lock)

    def SetupUser(self):
        """Propogate the user name<->id mapping from outside the chroot.

        Some unittests use getpwnam($USER), as does bash.  If the account
        is not registered in the sysroot, they get back errors.
        """
        MAGIC_GECOS = (
            "Added by your friendly platform test helper; do not modify"
        )
        # This is kept in sync with what sdk_lib/make_chroot.sh generates.
        SDK_GECOS = "ChromeOS Developer"

        # We assume the nobody group always exists.  This is reasonable.
        user, uid, gid, home = self.GetNonRootAccount(self.user)
        if user == "nobody":
            return

        passwd_db = os.path.join(self.sysroot, "etc", "passwd")

        def _user_exists():
            """See if the user has already been registered in the db."""

            try:
                data = osutils.ReadFile(passwd_db)
            except FileNotFoundError:
                return False

            accts = data.splitlines()
            for acct in accts:
                passwd = acct.split(":")
                if passwd[0] == user:
                    # Did the sdk make this account?
                    if passwd[4] == SDK_GECOS:
                        # Don't modify it (see below) since we didn't create it.
                        return True

                    # Did we make this account?
                    if passwd[4] != MAGIC_GECOS:
                        raise RuntimeError(
                            "your passwd db (%s) has unmanaged acct %s"
                            % (passwd_db, user)
                        )

                    # Maybe we should see if it needs to be updated?
                    # Like if they changed UIDs?  But we don't really
                    # check that elsewhere ...
                    return True

        # Fast path: see if the user exists already w/out grabbing a global
        # lock. This should be the most common flow.
        if _user_exists():
            return

        with self.LockDb(passwd_db):
            # Recheck the db w/the lock in case the user was added in parallel.
            if _user_exists():
                return

            acct = (
                "%(name)s:x:%(uid)s:%(gid)s:%(gecos)s:%(homedir)s:%(shell)s"
                % {
                    "name": user,
                    "uid": uid,
                    "gid": gid,
                    "gecos": MAGIC_GECOS,
                    "homedir": home,
                    "shell": "/bin/bash",
                }
            )

            # Create /etc/passwd if it does not already exist
            mode = "r+" if os.path.exists(passwd_db) else "x+"
            with open(passwd_db, mode) as f:
                data = f.read()
                if data and data[-1] != "\n":
                    f.write("\n")
                f.write("%s\n" % acct)

    def pre_test(self):
        """Runs pre-test environment setup.

        Sets up any required mounts and copying any required files to run tests
        (not those specific to tests) into the sysroot.
        """
        if self.user is None:
            self.SetupUser()
        else:
            # Force the C library to load any modules it might use to access
            # user databases.  For example, glibc will dlopen nss modules.
            pwd.getpwall()

        if self.framework == "qemu":
            self.qemu.Install()
            self.qemu.RegisterBinfmt()

    def post_test(self):
        """Runs post-test teardown.

        Removes mounts/files copied during pre-test.
        """

    def _remount_ro(self, path: str) -> None:
        """Helper to remount a path as read-only.

        The kernel doesn't allow specifying ro when creating the bind mount, so
        add a helper to remount it with the ro flag.
        """
        osutils.Mount(
            None,
            path,
            None,
            osutils.MS_REMOUNT | osutils.MS_BIND | osutils.MS_RDONLY,
        )

    def SetupDev(self):
        """Initialize a pseudo /dev directory.

        Unittests shouldn't need access to the real host /dev, especially since it
        won't be the same as exists on builders.
        """
        NODES = {
            "full": (1, 7, 0o666),
            "null": (1, 3, 0o666),
            "tty": (5, 0, 0o666),
            "urandom": (1, 9, 0o444),
            "zero": (1, 5, 0o666),
        }

        SYMLINKS = {
            "ptmx": "pts/ptmx",
            "fd": "/proc/self/fd",
            "stdin": "fd/0",
            "stdout": "fd/1",
            "stderr": "fd/2",
        }

        # Create an empty scratch space for /dev.
        path = os.path.join(self.sysroot, "dev")
        osutils.SafeMakedirs(path)
        osutils.Mount(
            "/dev",
            path,
            "tmpfs",
            osutils.MS_NOSUID | osutils.MS_NOEXEC,
            "size=10M,mode=0755",
        )

        # Disable umask while we create paths.
        with osutils.UmaskContext(0):
            # Populate the few nodes we care about.
            for node, (major, minor, perm) in NODES.items():
                perm |= stat.S_IFCHR
                os.mknod(
                    os.path.join(path, node), perm, os.makedev(major, minor)
                )

            # Setup some symlinks for common paths.
            for source, target in SYMLINKS.items():
                os.symlink(target, os.path.join(path, source))

            # Mount subpaths.
            os.mkdir(os.path.join(path, "shm"), 0o1777)

    def SetupProc(self, tempdir: Path) -> None:
        """Initialize a reduced /proc directory.

        We want to expose process info, but not host config settings.
        """
        # Mount the new proc to a tempdir before we move it to the final place.
        # This allows us to bind mount paths from the real /proc when we're
        # using --sysroot=/.
        osutils.Mount(
            "/proc",
            tempdir,
            None,
            osutils.MS_BIND,
        )
        DISABLE_SUBDIRS = (
            "acpi",
            "asound",
            "bus",
            "driver",
            "dynamic_debug",
            "fs",
        )
        empty_dir = os.path.join(self.sysroot, "mnt", "empty")
        for d in DISABLE_SUBDIRS:
            d = tempdir / d
            if d.is_dir():
                osutils.Mount(
                    empty_dir, d, None, osutils.MS_BIND | osutils.MS_RDONLY
                )

        # Setup some sysctl paths.  Have to be careful to only expose stable
        # entries that are long term stable ABI, and only read-only.
        sysctl = tempdir / "sys"
        osutils.Mount(
            "sysctl",
            sysctl,
            "tmpfs",
            osutils.MS_NOSUID | osutils.MS_NODEV | osutils.MS_NOEXEC,
            "mode=0755,size=1M",
        )
        d = sysctl / "kernel" / "random"
        osutils.SafeMakedirs(d)
        osutils.Mount("/proc/sys/kernel/random", d, None, osutils.MS_BIND)
        self._remount_ro(d)
        self._remount_ro(sysctl)

        d = os.path.join(self.sysroot, "proc")
        osutils.SafeMakedirs(d)
        osutils.Mount(
            tempdir,
            d,
            None,
            osutils.MS_MOVE,
        )

    def SetupSys(self) -> None:
        """Initialize a reduced /sys directory.

        We want to expose generic config, but not host config settings.
        """
        DISABLE_SUBDIRS = (
            "firmware",
            "hypervisor",
            "module",
            "power",
        )
        empty_dir = os.path.join(self.sysroot, "mnt/empty")
        for d in DISABLE_SUBDIRS:
            d = os.path.join(self.sysroot, "sys", d)
            if os.path.isdir(d):
                osutils.Mount(
                    empty_dir, d, "none", osutils.MS_BIND | osutils.MS_RDONLY
                )

    def run(self):
        """Runs the test in a proper environment (e.g. qemu)."""

        # We know these pre-tests are fast (especially if they've
        # already been run once), so run them automatically for the
        # user if they test by hand.
        self.pre_test()

        # Set up /dev first.
        bind_mount_paths = []
        if self.bind_mount_dev:
            bind_mount_paths += ["dev"]
        else:
            self.SetupDev()
        bind_mount_paths += (
            self._BIND_RW_MOUNT_PATHS + self._BIND_RO_MOUNT_PATHS
        )

        # Make sure /mnt/empty is always empty, and remains empty.
        mnt_empty = os.path.join(self.sysroot, "mnt/empty")
        osutils.SafeMakedirs(mnt_empty)
        osutils.Mount(
            "empty-dir",
            mnt_empty,
            "tmpfs",
            osutils.MS_RDONLY,
            "mode=0755,size=1K",
        )

        for mount in bind_mount_paths:
            path = os.path.join(self.sysroot, mount)
            osutils.SafeMakedirs(path)
            osutils.Mount("/" + mount, path, "none", osutils.MS_BIND)
            if mount in self._BIND_RO_MOUNT_PATHS:
                self._remount_ro(path)

        with tempfile.TemporaryDirectory() as tempdir_obj:
            tempdir = Path(tempdir_obj)
            self.SetupProc(tempdir)

        self.SetupSys()

        # Make sure /run/lock is usable.  But not the real lock path since tests
        # shouldn't be touching real state.
        path = os.path.join(self.sysroot, "run")
        # Ensure that ${SYSROOT}/run exists before we try to mount to it.
        osutils.SafeMakedirs(path, mode=0o755, sudo=True)
        osutils.Mount(
            "run",
            path,
            "tmpfs",
            osutils.MS_NOSUID | osutils.MS_NODEV | osutils.MS_NOEXEC,
            "mode=755",
        )
        path = os.path.join(path, "lock")
        osutils.SafeMakedirs(path, mode=0o1777)

        positive_filters = self.gtest_filter[0]
        negative_filters = self.gtest_filter[1]

        if self.user_gtest_filter:
            positive_filters += self.user_gtest_filter[0]
            negative_filters += self.user_gtest_filter[1]

        filters = (":".join(positive_filters), ":".join(negative_filters))
        gtest_filter = "%s-%s" % filters

        cmd = self.removeSysrootPrefix(self.bin)
        argv = self.args[:]
        argv[0] = self.removeSysrootPrefix(argv[0])
        if gtest_filter != "-":
            argv.append("--gtest_filter=" + gtest_filter)

        # Some programs expect to find data files via $CWD, so doing a chroot
        # and dropping them into / would make them fail.
        cwd = self.removeSysrootPrefix(os.getcwd())

        # Make orphaned child processes reparent to this process
        # instead of the init process.  This allows us to kill them if
        # they do not terminate after the test has finished running.
        _MakeProcessSubreaper()

        # Fork off a child to run the test.  This way we can make tweaks to the
        # env that only affect the child (gid/uid/chroot/cwd/etc...).  We have
        # to fork anyways to run the test, so might as well do it all ourselves
        # to avoid (slow) chaining through programs like:
        # sudo -u $SUDO_UID -g $SUDO_GID chroot $SYSROOT bash -c 'cd $CWD; $BIN'
        child = os.fork()
        if child == 0:
            print("chroot: %s" % self.sysroot)
            print("cwd: %s" % cwd)
            if self.env_vars:
                print(
                    "extra_env: %s"
                    % (", ".join("%s=%s" % x for x in self.env_vars.items()))
                )
            print("cmd: {%s} %s" % (cmd, " ".join(repr(x) for x in argv)))
            os.chroot(self.sysroot)
            os.chdir(cwd)

            # Set the child's pgid to its pid, so we can kill any processes
            # that the child creates after the child terminates.
            os.setpgid(0, 0)

            # Remove sysroot from path environment variables.
            for var in ("OUT", "SRC", "T", "LLVM_PROFILE_FILE"):
                if var in os.environ:
                    os.environ[var] = self.removeSysrootPrefix(os.environ[var])

            # Remove sysroot from path on sanitazion options environment
            # variables.
            for key, value in os.environ.items():
                if SAN_OPTIONS.match(key):
                    san_options = dict(x.split("=", 1) for x in value.split())
                    for opt in ("log_path", "suppressions"):
                        if opt in san_options:
                            san_options[opt] = self.removeSysrootPrefix(
                                san_options[opt]
                            )
                    os.environ[key] = " ".join(
                        "=".join(x) for x in san_options.items()
                    )

            # The TERM the user is leveraging might not exist in the sysroot.
            # Force a sane default that supports standard color sequences.
            os.environ["TERM"] = "ansi"
            # Some progs want this like bash else they get super confused.
            os.environ["PWD"] = cwd
            os.environ["GTEST_COLOR"] = "yes"
            if self.user != "root":
                user, uid, gid, home = self.GetNonRootAccount(self.user)
                os.setgid(gid)
                os.setuid(uid)
                os.environ["HOME"] = home
                os.environ["USER"] = user

            for name, value in self.env_vars.items():
                os.environ[name] = value
            try:
                sys.exit(os.execvp(cmd, argv))
            except OSError as e:
                # This is a common user error, so diagnose it better
                # than a traceback.
                print(f"error: execing {cmd} failed: {e}", file=sys.stderr)
                sys.exit(127 if e.errno == errno.ENOENT else 1)

        if sys.stdin.isatty():
            # Make the child's process group the foreground process group.
            os.tcsetpgrp(sys.stdin.fileno(), child)

        proctitle.settitle("sysroot watcher", cmd)

        # Mask SIGINT with the assumption that the child will catch &
        # process it.  We'll pass that back up below.
        signal.signal(signal.SIGINT, signal.SIG_IGN)

        # Reap any processes that were reparented to us until the child exits.
        status = _ReapUntilProcessExits(child)

        leaked_children = psutil.Process().children(recursive=True)
        if leaked_children:
            # It's possible the child forked and the forked processes are still
            # running.  Kill the forked processes.
            try:
                os.killpg(child, signal.SIGTERM)
            except OSError as e:
                if e.errno != errno.ESRCH:
                    print(
                        "Warning: while trying to kill pgid %s caught exception"
                        "\n%s" % (child, e),
                        file=sys.stderr,
                    )

            # Kill any orphaned processes originally created by the test
            # that were in a different process group.  This will also kill any
            # processes that did not respond to the SIGTERM.
            for child in leaked_children:
                try:
                    child.kill()
                except psutil.NoSuchProcess:
                    pass

        failmsg = None
        if os.WIFSIGNALED(status):
            sig = os.WTERMSIG(status)
            failmsg = "signal %s(%i)" % (signals.StrSignal(sig), sig)
        else:
            exit_status = os.WEXITSTATUS(status)
            if exit_status:
                failmsg = "exit code %i" % exit_status
        if failmsg:
            print("Error: %s: failed with %s" % (cmd, failmsg), file=sys.stderr)

        if leaked_children:
            for p in leaked_children:
                try:
                    name = p.name()
                except psutil.NoSuchProcess:
                    name = "<unknown>"
                print(
                    "Error: the test leaked process %s with pid %s (it was "
                    "forcefully killed)" % (name, p.pid),
                    file=sys.stderr,
                )
            # TODO(vapier): Make this an error.  We need to track down
            # some scenarios where processes do leak though before we
            # can make this fatal :(.
            # sys.exit(100)

        process_util.ExitAsStatus(status)


def _SudoCommand():
    """Get the 'sudo' command, along with all needed environment variables."""
    cmd = ["sudo"]
    for key, value in os.environ.items():
        for pattern in ENV_PASSTHRU_REGEX_LIST:
            if pattern.match(key):
                cmd += ["%s=%s" % (key, value)]
                break

    return cmd


def _ReExecuteIfNeeded(argv, ns_net=True, ns_pid=True):
    """Re-execute tests as root.

    We often need to do things as root, so make sure we're that.  Like chroot
    for proper library environment or do bind mounts.

    Also unshare the mount namespace so as to ensure that doing bind mounts for
    tests don't leak out to the normal chroot.  Also unshare the UTS namespace
    so changes to `hostname` do not impact the host.
    """
    # Disable the Gentoo sandbox if it's active to avoid warnings/errors.
    if os.environ.get("SANDBOX_ON") == "1":
        os.environ["SANDBOX_ON"] = "0"
        os.execvp(argv[0], argv)
    elif os.geteuid() != 0:
        # Clear the LD_PRELOAD var since it won't be usable w/sudo
        # (and the Gentoo sandbox normally sets it for us).
        os.environ.pop("LD_PRELOAD", None)
        cmd = _SudoCommand() + ["--"] + argv
        os.execvp(cmd[0], cmd)
    else:
        namespaces.SimpleUnshare(net=ns_net, pid=ns_pid)


def GetParser():
    """Return a command line parser."""
    actions = ["pre_test", "post_test", "run"]

    parser = commandline.ArgumentParser(description=__doc__)
    group = parser.add_argument_group("Namespaces")
    group.add_argument(
        "--no-ns-net",
        dest="ns_net",
        default=True,
        action="store_false",
        help="Do not create a new network namespace",
    )
    group.add_argument(
        "--no-ns-pid",
        dest="ns_pid",
        default=True,
        action="store_false",
        help="Do not create a new PID namespace",
    )

    parser.add_argument(
        "--action", default="run", choices=actions, help="action to perform"
    )
    parser.add_argument("--bin", help="test binary to run")
    parser.add_argument("--board", default=None, help="board to build for")
    parser.add_argument(
        "--sysroot", default=None, help="sysroot to run tests inside"
    )
    parser.add_argument(
        "--framework",
        default="auto",
        choices=("auto", "ldso", "qemu"),
        help="framework to be used to run tests",
    )
    parser.add_argument(
        "--gtest_filter", default="", help="args to pass to gtest/test binary"
    )
    parser.add_argument(
        "--host",
        action="store_true",
        default=False,
        help="specify that we're testing for the host",
    )
    parser.add_argument(
        "--bind-mount-dev",
        action="store_true",
        default=False,
        help="bind mount /dev instead of creating a pseudo one",
    )
    parser.add_argument("-u", "--user", help="user to run as (default: $USER)")
    parser.add_argument(
        "--run_as_root",
        dest="user",
        action="store_const",
        const="root",
        help="should the test be run as root",
    )
    parser.add_argument(
        "--user_gtest_filter", default="", help=argparse.SUPPRESS
    )
    parser.add_argument(
        "--env",
        action="append",
        default=[],
        help="environmental variable(s) to set: <name>=<value>",
    )
    parser.add_argument("cmdline", nargs="*")

    return parser


def main(argv):
    parser = GetParser()
    options = parser.parse_args(argv)

    if options.action == "run" and (
        (not options.bin or len(options.bin) == 0) and not options.cmdline
    ):
        parser.error(message='You must specify a binary for the "run" action')

    if options.host and options.board:
        parser.error(message="You must provide only one of --board or --host")
    elif not options.host and not options.board and not options.sysroot:
        parser.error(message="You must provide --board or --host or --sysroot")

    if options.sysroot:
        # Normalize the value so we can assume certain aspects.
        options.sysroot = osutils.ExpandPath(options.sysroot)
        if not os.path.isdir(options.sysroot):
            parser.error(message="Sysroot does not exist: %s" % options.sysroot)

    # Once we've finished sanity checking args, make sure we're root.
    _ReExecuteIfNeeded(
        [sys.argv[0]] + argv, ns_net=options.ns_net, ns_pid=options.ns_pid
    )

    env_vars = {}
    for env_entry in options.env:
        try:
            name, value = env_entry.split("=", 1)
            env_vars[name] = value
        except ValueError:
            parser.error(
                message="--env expects <name>=<value>; got: %s" % env_entry
            )

    p2test = Platform2Test(
        options.bin,
        options.board,
        options.host,
        options.framework,
        options.user,
        options.gtest_filter,
        options.user_gtest_filter,
        options.sysroot,
        options.bind_mount_dev,
        env_vars,
        options.cmdline,
    )
    getattr(p2test, options.action)()


if __name__ == "__main__":
    commandline.ScriptWrapperMain(lambda _: main)
