// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use hwsec_utils::context::RealContext;
use hwsec_utils::cr50::cr50_read_rma_sn_bits;

fn main() {
    let mut real_ctx = RealContext::new();
    let result = cr50_read_rma_sn_bits(&mut real_ctx);
    match result {
        Ok(rma_sn_bits) => {
            let sn_data_version = rma_sn_bits
                .sn_data_version
                .iter()
                .map(|byte| format!("{:02x}", byte))
                .collect::<String>();

            let rma_status = format!("{:02x}", rma_sn_bits.rma_status);

            let sn_bits = rma_sn_bits
                .sn_bits
                .iter()
                .map(|byte| format!("{:02x}", byte))
                .collect::<String>();

            let ret = format!("{}:{}:{}", sn_data_version, rma_status, sn_bits);

            println!("{}", ret);
        }
        Err(e) => eprintln!("{}", e),
    }
}
