// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use hwsec_utils::context::RealContext;
use hwsec_utils::cr50::cr50_reset;

fn main() {
    let mut real_ctx = RealContext::new();
    if cr50_reset(&mut real_ctx).is_err() {
        eprintln!("Cr50 Reset Error.");
    }
}
