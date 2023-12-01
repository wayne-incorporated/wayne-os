// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Generates the Rust D-Bus bindings for sirenia.

use std::path::Path;

use chromeos_dbus_bindings::generate_module;
use chromeos_dbus_bindings::BindingsType;
use chromeos_dbus_bindings::CROSSROADS_SERVER_OPTS;

// The parent path of sirenia.
const SOURCE_DIR: &str = ".";

// (<module name>, <relative path to source xml>)
const BINDINGS_TO_GENERATE: &[(&str, &str, BindingsType)] = &[(
    "org_chromium_manatee",
    "dbus_bindings/org.chromium.ManaTEE1.xml",
    BindingsType::Server(CROSSROADS_SERVER_OPTS),
)];

fn main() {
    let source_path = Path::new(SOURCE_DIR);
    generate_module(source_path, BINDINGS_TO_GENERATE).unwrap();
}
