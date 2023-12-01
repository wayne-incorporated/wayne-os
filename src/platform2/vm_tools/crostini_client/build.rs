// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::env;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Command that uses clang to parse a C++ file into its AST and outputs it as JSON. This is used
/// with the below jq script.
const CLANG_ARGS: &str = "-Xclang -ast-dump=json -fsyntax-only";

/// Script that recursively finds all objects with a `kind` field equal to `VarDecl` and extracts
/// the inner string literal. The output will be pairs of lines with the name followed by the value.
/// This is intended to be used with clangs' JSON formatted AST dump of a header file with string
/// constants.
const JQ_SCRIPT: &str = r#"'.. | select(.kind?=="VarDecl") | .name, .inner[0].value'"#;

/// Runs a shell command with `sh` and returns the stdout.
fn shell_helper(cmd: &str) -> String {
    let child = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start shell process");

    let output = child
        .wait_with_output()
        .expect("Failed to wait on shell process");

    if output.status.success() {
        String::from_utf8(output.stdout).expect("Failed to convert shell process output to String")
    } else {
        panic!("Failed shell command: {}", cmd);
    }
}

/// Converts a camel case a string such as `aVariableName` to upper snake case such as
/// `A_VARIABLE_NAME`.
fn upper_snake_case(input: &str) -> String {
    let mut output = String::new();
    for c in input.chars() {
        // Assumes that uppercase symbols indicate word breaks. Sort of gets confused by capitalized
        // acronyms.
        if c.is_ascii_uppercase() && !output.is_empty() {
            output.push('_')
        }
        output.push(c.to_ascii_uppercase());
    }
    output
}

/// Used to declare constant path information about system_api style APIs to parse and generate Rust
/// bindings for.
struct SystemApiDbus {
    path: &'static str,
    proto: Option<&'static str>,
}

impl SystemApiDbus {
    /// Declare a full D-Bus api with .proto and dbus-constants.h file.
    const fn new(path: &'static str, proto: &'static str) -> SystemApiDbus {
        SystemApiDbus {
            path,
            proto: Some(proto),
        }
    }

    /// Declare a full D-Bus api with only dbus-constants.h file under the given path. A path may
    /// also contain the relative file name if dbus-constants.h isn't the appropriate constants
    /// file.
    const fn constants(path: &'static str) -> SystemApiDbus {
        SystemApiDbus { path, proto: None }
    }

    /// Gets the include path in order to parse the .proto file for this API.
    fn get_include_path(&self, proto_root: &Path) -> impl AsRef<Path> {
        proto_root.join(self.path)
    }

    /// Gets the path to the .proto file for this API, if there is one.
    fn get_input_path(&self, proto_root: &Path) -> Option<PathBuf> {
        let proto = self.proto?;
        Some(proto_root.join(self.path).join(proto))
    }

    /// Parses the string constants in dbus-constants.h or the appropriate alternative header if
    /// appropriate. The given `constants` will be appended to with the name and value of each
    /// constant, converted to correct Rust style. If there are duplicate constant names, they will
    /// be overwritten.
    fn parse_constants(&self, proto_root: &Path, constants: &mut BTreeMap<String, String>) {
        let mut constants_path = proto_root.join(self.path);
        if !constants_path.is_file() {
            constants_path.push("dbus-constants.h");
            if !constants_path.is_file() {
                panic!("Failed to find header at {}", self.path);
            }
        }
        let clang = match env::var("CBUILD").ok() {
            Some(cbuild) => format!("{}-clang++", cbuild),
            None => "clang++".to_owned(),
        };
        let shell_parse_cmd = format!(
            r#"set -o pipefail && {} {} "{}" | jq -e -r {}"#,
            clang,
            CLANG_ARGS,
            constants_path.display(),
            JQ_SCRIPT,
        );
        let parse_output = shell_helper(&shell_parse_cmd);
        let mut lines = parse_output.lines();
        loop {
            if let (Some(var_name), Some(var_literal)) = (lines.next(), lines.next()) {
                if var_name.starts_with('k') {
                    let name = upper_snake_case(var_name.trim_matches('k'));
                    let value = var_literal.trim_matches('"').to_owned();
                    constants.insert(name, value);
                }
            } else {
                break;
            }
        }
    }
}

/// A list of system_api style APIs to generate Rust bindings for.
const APIS: &[SystemApiDbus] = &[
    SystemApiDbus::constants("dbus/debugd"),
    SystemApiDbus::constants("dbus/permission_broker"),
    // service_constants.h is the only header file needed that isn't called dbus_constants.h.
    SystemApiDbus::constants("dbus/service_constants.h"),
    SystemApiDbus::new("dbus/vm_concierge", "concierge_service.proto"),
    SystemApiDbus::new("dbus/vm_cicerone", "cicerone_service.proto"),
    SystemApiDbus::new("dbus/dlcservice", "dlcservice.proto"),
    SystemApiDbus::new("dbus/seneschal", "seneschal_service.proto"),
    SystemApiDbus::new("dbus/vm_plugin_dispatcher", "vm_plugin_dispatcher.proto"),
    SystemApiDbus::new("dbus/vm_launch", "launch.proto"),
];

/// A list of proto files to generate Rust bindings for without dbus_constants.h.
const PROTOS: &[SystemApiDbus] = &[SystemApiDbus::new("dbus", "arc/arc.proto")];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let system_api_root = match env::var("SYSROOT") {
        Ok(path) => PathBuf::from(path).join("usr/include/chromeos"),
        // Make this work when typing "cargo build" in platform2/vm_tools/crostini_client
        Err(_) => PathBuf::from("../../system_api"),
    };
    let system_api_dbus_source_root = system_api_root.join("dbus");
    println!(
        "cargo:rerun-if-changed={}",
        system_api_dbus_source_root.display()
    );

    let mut input_paths = Vec::new();
    let mut generator = protobuf_codegen::Codegen::new();
    let mut constants = Default::default();
    for api in APIS {
        // Some APIs have no .proto file that needs parsing.
        if let Some(input_path) = api.get_input_path(&system_api_root) {
            generator.input(&input_path);
            generator.include(api.get_include_path(&system_api_root));
            input_paths.push(input_path);
        }
        api.parse_constants(&system_api_root, &mut constants);
    }
    for proto in PROTOS {
        if let Some(input_path) = proto.get_input_path(&system_api_root) {
            generator.input(&input_path);
            generator.include(proto.get_include_path(&system_api_root));
            input_paths.push(input_path);
        }
    }

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    generator.out_dir(&out_path);
    generator.run().expect("protoc");

    // Build up a string of code which gets included as the proto.rs module.
    let mut proto_include_code = String::new();
    // Collects all the Rust source files outputted by protoc as a series of modules.
    for input_file in input_paths.iter() {
        let stem = input_file.file_stem().unwrap().to_str().unwrap();
        let mod_path = out_path.join(format!("{}.rs", stem));
        writeln!(
            &mut proto_include_code,
            "#[path = \"{}\"]",
            mod_path.display()
        )
        .unwrap();
        writeln!(&mut proto_include_code, "pub mod {};", stem).unwrap();
    }

    // Also put all the collected string constants from `parse_constants` into the included module.
    for (name, value) in constants {
        writeln!(
            &mut proto_include_code,
            "pub const {}: &str = r###\"{}\"###;", // Uses Rust raw strings for safe inclusion.
            name, value
        )
        .unwrap();
    }

    // The proto_include.rs file gets included directly by proto.rs.
    let mut mod_out = fs::File::create(out_path.join("proto_include.rs")).unwrap();
    writeln!(mod_out, "pub mod system_api {{\n{}}}", proto_include_code).unwrap();
}
