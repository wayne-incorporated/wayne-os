// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use clap::{arg_enum, command, value_t, Arg};
use libc::syscall;
use std::ffi::CString;
use std::fs::File;
use std::os::unix::io::IntoRawFd;

arg_enum! {
    #[derive(Clone, Copy)]
    pub enum Action {
        RebootKexec,
        LoadCrash,
    }
}

fn syscall_parse(ret: libc::c_long) -> std::io::Result<()> {
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn syscall_kexec_file_load(
    kernel_fd: libc::c_int,
    initrd_fd: libc::c_int,
    cmdline: &str,
    flags: libc::c_int,
) -> std::io::Result<()> {
    let c_cmdline = CString::new(cmdline)?;
    let ret = unsafe {
        syscall(
            libc::SYS_kexec_file_load,
            kernel_fd,
            initrd_fd,
            cmdline.len() + 1,
            c_cmdline.as_ptr(),
            flags,
        )
    };
    syscall_parse(ret)
}

fn syscall_reboot_kexec() -> std::io::Result<()> {
    let ret = unsafe {
        syscall(
            libc::SYS_reboot,
            libc::LINUX_REBOOT_MAGIC1,
            libc::LINUX_REBOOT_MAGIC2,
            libc::LINUX_REBOOT_CMD_KEXEC,
            0,
        )
    };
    syscall_parse(ret)
}

fn main() -> std::io::Result<()> {
    let matches = command!()
        .about("Minimalistic implementation of kexec-tools")
        .arg(
            Arg::with_name("action")
                .short('a')
                .required(true)
                .long("action")
                .possible_values(&Action::variants())
                .case_insensitive(true)
                .help("Action to do with the provided images"),
        )
        .arg(
            Arg::with_name("cmdline")
                .short('c')
                .long("cmdline")
                .required(true)
                .takes_value(true)
                .help("Command Line to pass to the kernel"),
        )
        .arg(
            Arg::with_name("kernel")
                .short('k')
                .long("kernel")
                .required(true)
                .takes_value(true)
                .help("Kernel image"),
        )
        .arg(
            Arg::with_name("initrd")
                .short('i')
                .long("initrd")
                .takes_value(true)
                .help("Initird image"),
        )
        .get_matches();

    let kernel_fd = File::open(matches.value_of("kernel").unwrap())?.into_raw_fd();

    let initrd_fd = match matches.value_of("initrd") {
        Some(fname) => File::open(fname)?.into_raw_fd(),
        None => -1,
    };

    let cmdline = matches.value_of("cmdline").unwrap();

    let action = value_t!(matches, "action", Action).unwrap();

    let flags: libc::c_int = match (initrd_fd, action) {
        (-1, Action::LoadCrash) => libc::KEXEC_FILE_NO_INITRAMFS | libc::KEXEC_FILE_ON_CRASH,
        (_, Action::LoadCrash) => libc::KEXEC_FILE_ON_CRASH,
        (-1, _) => libc::KEXEC_FILE_NO_INITRAMFS,
        (_, _) => 0,
    };

    syscall_kexec_file_load(kernel_fd, initrd_fd, cmdline, flags)?;

    if matches!(action, Action::RebootKexec) {
        syscall_reboot_kexec()?;
        panic!("System Failed to reboot");
    }

    Ok(())
}
