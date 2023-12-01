// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Generates the Rust D-Bus bindings for sirenia.

use std::env;
use std::fs::write;
use std::path::Path;

use chrono::offset::Utc;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    write(
        Path::new(&out_dir).join("build_info.rs"),
        format!(
            "pub const BUILD_TIMESTAMP: &str = \"{}\";\n",
            Utc::now().to_rfc3339()
        ),
    )
    .expect("Failed to generate build_info.rs.");
}
