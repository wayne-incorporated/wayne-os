// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;
use std::process::exit;

use hwsec_utils::command_runner::CommandRunner;
use hwsec_utils::context::Context;
use hwsec_utils::context::RealContext;
use hwsec_utils::cr50::board_id_is_set;
use hwsec_utils::cr50::cr50_check_sn_bits;
use hwsec_utils::cr50::cr50_compute_updater_sn_bits;
use hwsec_utils::cr50::cr50_set_sn_bits;
use hwsec_utils::cr50::Cr50SetSnBitsVerdict;

fn main() {
    const VPD_KEY: &str = "attested_device_id";
    let mut real_ctx = RealContext::new();
    let args_string: Vec<String> = env::args().collect();
    let args: Vec<&str> = args_string.iter().map(|s| s.as_str()).collect();
    let dry_run = args.len() > 1 && args[1] == "-n";

    // TODO: seek if there's any library with
    // function obtaining vpd_output
    let vpd_raw_output = real_ctx
        .cmd_runner()
        .run("vpd", vec!["-g", VPD_KEY])
        .map_err(|_| {
            eprintln!("ERROR: Failed to access vpd key.");
            exit(Cr50SetSnBitsVerdict::GeneralError as i32);
        })
        .unwrap()
        .stdout;
    let sn = std::str::from_utf8(&vpd_raw_output).unwrap();
    if sn.is_empty() {
        eprintln!(
            "ERROR: The RO VPD key {} must present and not empty.",
            VPD_KEY
        );
        exit(Cr50SetSnBitsVerdict::MissingVpdKeyError as i32);
    }

    let sn_bits = cr50_compute_updater_sn_bits(sn);
    cr50_check_sn_bits(&mut real_ctx, sn_bits, dry_run)
        .map_err(|e| {
            exit(e as i32);
        })
        .unwrap();

    if dry_run {
        print!("SN Bits have not been set yet.");
        if board_id_is_set(&mut real_ctx)
            .map_err(|e| exit(e as i32))
            .unwrap()
        {
            print!(" (BoardID is set)");
        }
        println!(".");
        exit(0);
    }

    cr50_set_sn_bits(&mut real_ctx, sn_bits)
        .map_err(|e| {
            exit(e as i32);
        })
        .unwrap();

    println!("Successfully updated SN Bits for {}.", sn);
}
