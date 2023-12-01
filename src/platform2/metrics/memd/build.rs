// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Outputs rerun-if-changed directives to cargo, as described
/// in https://doc.rust-lang.org/cargo/reference/build-scripts.html. These are required if we want
/// `cargo` to rerun this script when external dependencies (e.g., proto files) get updated.
fn note_rerun_if_changed(p: &Path) {
    println!("cargo:rerun-if-changed={}", p.display());
    if p.is_dir() {
        let error_message = format!("reading dir {}", p.display());
        for ent in p.read_dir().expect(&error_message) {
            note_rerun_if_changed(&ent.expect(&error_message).path());
        }
    }
}

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let proto_root = match env::var("SYSROOT") {
        Ok(dir) => PathBuf::from(dir).join("usr/include/chromeos"),
        // Make this work when typing "cargo build" in platform2/metrics/memd
        Err(_) => PathBuf::from("../../system_api"),
    };
    let proto_dir = proto_root.join("dbus/metrics_event");
    let proto_file = proto_dir.join("metrics_event.proto");

    let input_files = &[proto_file];
    for file in input_files {
        note_rerun_if_changed(file);
    }
    let includes_files = &[proto_dir];
    for file in includes_files {
        note_rerun_if_changed(file);
    }

    protobuf_codegen::Codegen::new()
        .out_dir(out_dir.as_os_str().to_str().unwrap())
        .inputs(
            &input_files
                .iter()
                .map(|x| x.to_str().unwrap())
                .collect::<Vec<&str>>(),
        )
        .includes(
            &includes_files
                .iter()
                .map(|x| x.to_str().unwrap())
                .collect::<Vec<&str>>(),
        )
        .customize(Default::default())
        .run()
        .expect("protoc");

    let mut mod_out = fs::File::create(out_dir.join("proto_include.rs")).unwrap();
    writeln!(
        mod_out,
        "#[path = \"{}\"] pub mod plugin_proto;\npub use plugin_proto::*;",
        out_dir.join("metrics_event.rs").display()
    )
    .unwrap();
}
