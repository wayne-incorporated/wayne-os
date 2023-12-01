// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use serde::Deserialize;
use std::path::PathBuf;
use std::process::Command;
use std::{env, fs};

/// Clang AST node.
#[derive(Deserialize)]
struct Node {
    kind: String,
    name: Option<String>,
    value: Option<String>,
    #[serde(default)]
    inner: Vec<Node>,
}

/// Convert "kVarName" to "VAR_NAME".
fn convert_var_name(mut name: &str) -> String {
    // Drop the "k" prefix.
    if name.starts_with('k') {
        name = &name[1..];
    }

    let mut out = String::new();
    for c in name.chars() {
        if !out.is_empty() && c.is_uppercase() {
            out.push('_')
        }
        out.push_str(&c.to_uppercase().to_string());
    }
    out
}

/// Extract the variable declarations from the AST and convert them to
/// Rust code. For example, this C++ code:
///
///     constexpr char kInstallMethod[] = "StartOsInstall";
///
/// Is converted to this Rust code:
///
///     pub const INSTALL_METHOD: &str = "StartOsInstall";
fn get_var_lines(ast: &Node) -> Option<String> {
    // Find the os_install_service namespace.
    let namespace_node = ast.inner.iter().find(|node| {
        node.kind == "NamespaceDecl" && node.name == Some("os_install_service".to_string())
    })?;

    // Get an iterator of (var-name, var-value) pairs.
    let vars = namespace_node.inner.iter().filter_map(|node| {
        if node.kind == "VarDecl" && node.inner.len() == 1 {
            let name = node.name.as_ref()?;
            let value = node.inner[0].value.as_ref()?;
            Some((convert_var_name(name), value))
        } else {
            None
        }
    });

    let var_lines: Vec<_> = vars
        .map(|(name, val)| format!("pub const {}: &str = {};", name, val))
        .collect();

    Some(var_lines.join("\n"))
}

/// Get the directory containing the dbus headers. This is needed so
/// that standalone "cargo build" works as well as building in the
/// chroot.
fn get_system_api_dir() -> PathBuf {
    match env::var("SYSROOT") {
        Ok(path) => PathBuf::from(path).join("usr/include/chromeos"),
        Err(_) => PathBuf::from("../system_api"),
    }
}

/// Get the name of the clang++ executable. This is needed so that
/// standalone "cargo build" works as well as building in the chroot.
fn get_clang_name() -> String {
    match env::var("CBUILD") {
        Ok(cbuild) => format!("{}-clang++", cbuild),
        Err(_) => "clang++".to_owned(),
    }
}

fn main() {
    let header_path = get_system_api_dir().join("dbus/os_install_service/dbus-constants.h");
    assert!(header_path.exists());

    // Rebuild if the header changes.
    println!("cargo:rerun-if-changed={}", header_path.display());

    // Use clang to get an AST in JSON.
    let output = Command::new(get_clang_name())
        .args(["-Xclang", "-ast-dump=json", "-fsyntax-only"])
        .arg(header_path)
        .output()
        .unwrap();
    assert!(output.status.success());

    // Parse the JSON.
    let ast: Node = serde_json::from_slice(&output.stdout).unwrap();

    // Convert C++ declarations to Rust.
    let lines = get_var_lines(&ast).unwrap();

    // Write the Rust code to $OUT_DIR/dbus_constants.rs.
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    fs::write(out_dir.join("dbus_constants.rs"), lines).unwrap();
}
