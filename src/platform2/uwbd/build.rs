// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Generates the Rust D-Bus bindings for uwbd.

use std::path::Path;

use chromeos_dbus_bindings::{generate_module, BindingsType, CROSSROADS_SERVER_OPTS};

// The parent path of uwbd.
const SOURCE_DIR: &str = ".";

// (<module name>, <relative path to source xml>)
const BINDINGS_TO_GENERATE: &[(&str, &str, BindingsType)] = &[(
    "org_chromium_uwbd",
    "dbus_bindings/org.chromium.uwbd.xml",
    BindingsType::Both {
        client_opts: None,
        server_opts: CROSSROADS_SERVER_OPTS,
    },
)];

fn main() {
    // Generate the D-Bus bindings to "src/bindings/include_modules.rs".
    generate_module(Path::new(SOURCE_DIR), BINDINGS_TO_GENERATE).unwrap();
}
