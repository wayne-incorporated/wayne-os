// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

fn main() {
    // Dynamically link to libfeatures_c.
    println!("cargo:rustc-link-lib=dylib=features_c");
    println!("cargo:rustc-link-lib=dylib=c_fake_feature_library");
}
