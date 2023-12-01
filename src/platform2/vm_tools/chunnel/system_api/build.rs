// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;
use std::ffi::OsStr;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

fn paths_to_strs<P: AsRef<Path>>(paths: &[P]) -> Vec<&str> {
    paths
        .iter()
        .map(|p| p.as_ref().as_os_str().to_str().unwrap())
        .collect()
}

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let proto_root = match env::var("SYSROOT") {
        Ok(dir) => {
            let sysroot = PathBuf::from(dir);
            sysroot.join(
                if matches!(sysroot.file_name(), Some(name) if name == OsStr::new("usr")) {
                    "include/chromeos"
                } else {
                    "usr/include/chromeos"
                },
            )
        }
        // Make this work when typing "cargo build" in platform2/vm_tools/chunnel.
        Err(_) => PathBuf::from("../../../system_api"),
    };
    let chunneld_dir = proto_root.join("dbus/chunneld");
    let cicerone_dir = proto_root.join("dbus/vm_cicerone");
    let input_files = [
        chunneld_dir.join("chunneld_service.proto"),
        cicerone_dir.join("cicerone_service.proto"),
    ];
    let include_dirs = [chunneld_dir, cicerone_dir];

    protobuf_codegen::Codegen::new()
        .out_dir(out_dir.as_os_str().to_str().unwrap())
        .inputs(&paths_to_strs(&input_files))
        .includes(&paths_to_strs(&include_dirs))
        .customize(Default::default())
        .run()
        .expect("protoc");

    let mut path_include_mods = String::new();
    for input_file in input_files.iter() {
        let stem = input_file.file_stem().unwrap().to_str().unwrap();
        let mod_path = out_dir.join(format!("{}.rs", stem));
        writeln!(
            &mut path_include_mods,
            "#[path = \"{}\"]",
            mod_path.display()
        )
        .unwrap();
        writeln!(&mut path_include_mods, "pub mod {};", stem).unwrap();
    }

    let mut mod_out = fs::File::create(out_dir.join("proto_include.rs")).unwrap();
    writeln!(
        mod_out,
        "pub mod system_api {{\n{}}}\npub use system_api::*;",
        path_include_mods
    )
    .unwrap();
}
