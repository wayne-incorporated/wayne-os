// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;
use std::path::Path;
use std::process::exit;

use hwsec_utils::context::RealContext;
use hwsec_utils::cr50::cr50_verify_ro;
use hwsec_utils::cr50::update_dut_if_needed;

/// The two arguments are the Cr50 image file of the lowest
/// version DUT should be running, and the RO verification
/// descriptors database file.
pub fn parse_args(args: Vec<&str>) -> Option<(&Path, &Path)> {
    if args.len() != 3 {
        return None;
    }
    let new_image = Path::new(args[1]);
    if !new_image.is_file() {
        eprintln!(
            "The Cr50 image file `{}` does not exist.",
            new_image.display()
        );
        return None;
    }
    let ro_descriptions = Path::new(args[2]);
    if !ro_descriptions.is_dir() {
        eprintln!(
            "The RO verification descriptors database file `{}` does not exist.",
            ro_descriptions.display()
        );
        return None;
    }
    Some((new_image, ro_descriptions))
}

fn main() {
    let mut real_ctx = RealContext::new();
    let args_string: Vec<String> = env::args().collect();
    let args: Vec<&str> = args_string.iter().map(|s| s.as_str()).collect();

    let Some((new_image, ro_descriptions)) = parse_args(args) else {
        eprintln!("Two parameters are required: name of the Cr50 image file \
        and name of the RO verification descriptors database file");
        exit(1);
    };

    if update_dut_if_needed(&mut real_ctx, new_image).is_err() {
        exit(1)
    };

    let result = cr50_verify_ro(&mut real_ctx, ro_descriptions);
    exit(result.is_ok() as i32);
}
