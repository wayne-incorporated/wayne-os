// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Encapsulates the logic used to setup sandboxes for TEE applications.

use std::fs::OpenOptions;
use std::io::Write;
use std::io::{self};
use std::os::unix::io::RawFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::process::{self};

use libc;
use libc::pid_t;
use log::info;
use minijail;
use minijail::Minijail;

use crate::sys::dup;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to setup jail: {0}")]
    Jail(#[source] minijail::Error),
    #[error("failed to fork jail process: {0}")]
    ForkingJail(#[source] minijail::Error),
    #[error("failed to bind '{0}' to '{1}': {2}")]
    Bind(String, String, #[source] minijail::Error),
    #[error("dup failed: {0}")]
    Dup(#[source] io::Error),
    #[error("failed to pivot root: {0}")]
    PivotRoot(#[source] minijail::Error),
    #[error("failed to parse seccomp policy: {0}")]
    SeccompPolicy(#[source] minijail::Error),
    #[error("failed to set max open files: {0}")]
    SettingMaxOpenFiles(#[source] minijail::Error),
    #[error("failed to wait on jailed process to complete: {0}")]
    MinijailWait(#[source] minijail::Error),
    #[error("failed to fork process: {0}")]
    ForkingProcess(#[source] std::io::Error),
    #[error("missing argument")]
    MissingArgument,
    #[error("VM not created")]
    VmNotCreated,
    #[error("failed to wait for process: {0}")]
    Wait(#[source] std::io::Error),
    #[error("unimplemented functionality")]
    Unimplemented,
    #[error("sibling VM is already running")]
    SiblingVmRunning,
}

/// The result of an operation in this crate.
pub type Result<T> = std::result::Result<T, Error>;

const NEW_ROOT: &str = "/mnt/empty";

pub trait Sandbox {
    /// Execute `cmd` with the specified arguments `args`. The specified file
    /// descriptors are connected to stdio for the child process.
    fn run(&mut self, cmd: &Path, args: &[&str], keep_fds: &[(RawFd, RawFd)]) -> Result<pid_t>;

    fn run_raw(&mut self, cmd: RawFd, args: &[&str], keep_fds: &[(RawFd, RawFd)]) -> Result<pid_t>;

    /// Wait until the child process completes. Non-zero return codes are
    /// returned as an error.
    fn wait_for_completion(&mut self) -> Result<()>;
}

/// An abstraction for the TEE application sandbox.
pub struct MinijailSandbox(minijail::Minijail);

impl MinijailSandbox {
    /// Setup default sandbox / namespaces
    pub fn new(seccomp_bpf_file: Option<&Path>) -> Result<Self> {
        // All child jails run in a new user namespace without any users mapped,
        // they run as nobody unless otherwise configured.
        let mut j = Minijail::new().map_err(Error::Jail)?;

        j.namespace_pids();

        // TODO() determine why uid sandboxing doesn't work.
        //j.namespace_user();
        //j.namespace_user_disable_setgroups();

        j.change_user("nobody").unwrap();
        j.change_group("nobody").unwrap();

        j.use_caps(0);
        j.namespace_vfs();
        j.namespace_net();
        j.no_new_privs();

        if let Some(path) = seccomp_bpf_file {
            j.parse_seccomp_program(&path)
                .map_err(Error::SeccompPolicy)?;
            j.use_seccomp_filter();
        }

        let new_root = Path::new(NEW_ROOT);
        // The initramfs cannot be unmounted so bind mount /mnt/empty as read only and chroot.
        j.mount_bind(new_root, Path::new("/"), false)
            .map_err(|err| Error::Bind(NEW_ROOT.to_string(), NEW_ROOT.to_string(), err))?;
        j.enter_chroot(new_root).map_err(Error::PivotRoot)?;

        let limit = 1024u64;
        j.set_rlimit(libc::RLIMIT_NOFILE as i32, limit, limit)
            .map_err(Error::SettingMaxOpenFiles)?;

        Ok(MinijailSandbox(j))
    }

    /// A version of the sandbox for use with tests because it doesn't require
    /// elevated privilege. It is also used for developer tools.
    pub fn passthrough() -> Result<Self> {
        let j = Minijail::new().map_err(Error::Jail)?;
        Ok(MinijailSandbox(j))
    }
}

impl Sandbox for MinijailSandbox {
    fn run(&mut self, cmd: &Path, args: &[&str], keep_fds: &[(RawFd, RawFd)]) -> Result<pid_t> {
        let pid = match self
            .0
            .run_remap(cmd, keep_fds, args)
            .map_err(Error::ForkingJail)?
        {
            0 => {
                unsafe { libc::exit(0) };
            }
            p => p,
        };

        Ok(pid)
    }

    fn run_raw(&mut self, cmd: RawFd, args: &[&str], keep_fds: &[(RawFd, RawFd)]) -> Result<pid_t> {
        let pid = match self
            .0
            .run_fd_remap(&cmd, keep_fds, args)
            .map_err(Error::ForkingJail)?
        {
            0 => {
                unsafe { libc::exit(0) };
            }
            p => p,
        };

        Ok(pid)
    }

    fn wait_for_completion(&mut self) -> Result<()> {
        self.0.wait().map_err(Error::MinijailWait)
    }
}

pub struct VmConfig {
    pub crosvm_path: PathBuf,
}

// Sandbox to run an instance of "crosvm" that will run a VM.
pub struct VmSandbox {
    config: VmConfig,
    vm: Option<Child>,
}

impl VmSandbox {
    /// Setup default sandbox / namespaces
    pub fn new(config: VmConfig) -> Result<Self> {
        Ok(VmSandbox { config, vm: None })
    }
}

impl Sandbox for VmSandbox {
    fn run(&mut self, _cmd: &Path, _args: &[&str], _keep_fds: &[(RawFd, RawFd)]) -> Result<pid_t> {
        Err(Error::Unimplemented)
    }

    fn run_raw(
        &mut self,
        _cmd: RawFd,
        args: &[&str],
        keep_fds: &[(RawFd, RawFd)],
    ) -> Result<pid_t> {
        if self.vm.is_some() {
            return Err(Error::SiblingVmRunning);
        }

        // The first arg will contain the path to the "fd" that points to the contents of the
        // kernel.
        if args.is_empty() {
            return Err(Error::MissingArgument);
        }

        info!("crosvm args: {:?}", args);

        let mut cmd = Command::new(&self.config.crosvm_path);

        // Sandboxing is only used from single-threaded processes, so we don't have to worry
        // about the async-signal-safety concerns of forking. The closure also doesn't interact
        // with any existing fds, so there aren't any safety concerns there, and it doesn't
        // panic.
        unsafe {
            cmd.pre_exec(|| {
                let mut cgroup_processes = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(Path::new("/sys/kernel/cgroup/cgroup.procs"))?;
                cgroup_processes.write_all(process::id().to_string().as_bytes())?;
                Ok(())
            });
        }

        for (in_fd, out_fd) in keep_fds {
            // dup is required because |Stdio| takes ownership and an fd should not be closed twice.
            let fd: Stdio = dup(*in_fd).map_err(Error::Dup)?;
            match out_fd {
                0 => {
                    cmd.stdin(fd);
                }
                1 => {
                    cmd.stdout(fd);
                }
                2 => {
                    cmd.stderr(fd);
                }
                _ => (),
            };
        }

        // The first arg in `args` is the fd to the kernel. This needs to be the last argument to "crosvm
        // run". Manipulate `args` to move the kernel fd at the end.
        if args.len() > 1 {
            cmd.args(&args[1..]);
        }
        let vm = cmd.arg(&args[0]).spawn().map_err(Error::ForkingProcess)?;
        let pid = vm.id();
        self.vm = Some(vm);
        Ok(pid as i32)
    }

    fn wait_for_completion(&mut self) -> Result<()> {
        if self.vm.is_none() {
            return Err(Error::VmNotCreated);
        }

        match self.vm.as_mut().unwrap().wait() {
            Ok(_) => Ok(()),
            Err(e) => Err(Error::Wait(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::io::Write;
    use std::os::unix::io::AsRawFd;

    use libchromeos::sys::unix::pipe;

    use super::*;
    use crate::transport::CROS_CONNECTION_ERR_FD;
    use crate::transport::CROS_CONNECTION_R_FD;
    use crate::transport::CROS_CONNECTION_W_FD;

    fn do_test(s: &mut dyn Sandbox) {
        const STDOUT_TEST: &str = "stdout test";
        const STDERR_TEST: &str = "stderr test";

        let (r_stdin, mut w_stdin) = pipe(true).unwrap();
        let (mut r_stdout, w_stdout) = pipe(true).unwrap();
        let (mut r_stderr, w_stderr) = pipe(true).unwrap();

        let keep_fds: [(RawFd, RawFd); 3] = [
            (r_stdin.as_raw_fd(), CROS_CONNECTION_R_FD),
            (w_stdout.as_raw_fd(), CROS_CONNECTION_W_FD),
            (w_stderr.as_raw_fd(), CROS_CONNECTION_ERR_FD),
        ];

        println!("Starting sandboxed process.");
        s.run(Path::new("/bin/sh"), &["/bin/sh"], &keep_fds)
            .unwrap();
        std::mem::drop(r_stdin);
        std::mem::drop(w_stdout);
        std::mem::drop(w_stderr);

        println!("Writing to stdin.");
        // The sleep was added to possibly resolve https://crbug.com/1171078.
        write!(
            &mut w_stdin,
            "echo -n '{}'; sleep 0.05; echo -n '{}' 1>&2; exit;",
            STDOUT_TEST, STDERR_TEST
        )
        .unwrap();
        w_stdin.flush().unwrap();
        std::mem::drop(w_stdin);

        println!("Reading stdout.");
        let mut stdout_result = String::new();
        r_stdout.read_to_string(&mut stdout_result).unwrap();

        println!("Reading stderr.");
        let mut stderr_result = String::new();
        r_stderr.read_to_string(&mut stderr_result).unwrap();

        println!("Waiting for sandboxed process.");
        let result = s.wait_for_completion();

        println!("Validating result.");
        if result.is_err() {
            eprintln!("Got error code: {:?}", result)
        }

        assert_eq!(
            (stdout_result, stderr_result),
            (STDOUT_TEST.to_string(), STDERR_TEST.to_string())
        );

        result.unwrap();
    }

    #[test]
    #[ignore] // privileged operation.
    fn sandbox() {
        let mut s = MinijailSandbox::new(None).unwrap();
        do_test(&mut s);
    }

    #[test]
    fn sandbox_unpriviledged() {
        let mut s = MinijailSandbox::passthrough().unwrap();
        do_test(&mut s);
    }
}
