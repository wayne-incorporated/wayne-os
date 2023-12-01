// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;
use std::process::exit;

use hwsec_utils::command_runner::CommandRunner;
use hwsec_utils::context::Context;
use hwsec_utils::context::RealContext;
use hwsec_utils::cr50::check_cr50_support_partial_board_id;
use hwsec_utils::cr50::check_device;
use hwsec_utils::cr50::cr50_check_board_id_and_flag;
use hwsec_utils::cr50::cr50_set_board_id_and_flag;
use hwsec_utils::cr50::Cr50SetBoardIDVerdict;
use hwsec_utils::cr50::GSC_NAME;

pub fn die(message: &str) -> ! {
    eprintln!("ERROR: {}", message);
    exit(Cr50SetBoardIDVerdict::GeneralError as i32)
}

fn exit_if_not_support_partial_board_id(ctx: &mut impl Context) {
    check_cr50_support_partial_board_id(ctx)
        .map_err(|e| exit(e as i32))
        .unwrap();
}
fn main() {
    let mut real_ctx = RealContext::new();
    let args_string: Vec<String> = env::args().collect();
    let args: Vec<&str> = args_string.iter().map(|s| s.as_str()).collect();
    if args.len() <= 1 || args.len() >= 4 {
        die(&format!("Usage: {} phase [board_id]", args[0]));
    }
    let phase: &str = args[1];
    if phase == "check_device" {
        check_device(&mut real_ctx)
            .map_err(|e| exit(e as i32))
            .unwrap();
    }
    let mut rlz: &str = if args.len() == 3 { args[2] } else { "" };
    let flag: u16 = if phase == "whitelabel_pvt_flags" {
        // Whitelabel flags are set by using 0xffffffff as the rlz and the
        // whitelabel flags. Cr50 images that support partial board id will ignore
        // the board id type if it's 0xffffffff and only set the flags.
        // Partial board id support was added in 0.3.24 and 0.4.24. Before that
        // images won't ever ignore the type field. They always set
        // board_id_type_inv to ~board_id_type. Trying the whitelabel_flags command
        // on these old images would blow the board id type in addition to the
        // flags, and prevent setting the RLZ later. Exit here if the image doesn't
        // support partial board id.
        if GSC_NAME == "cr50" {
            exit_if_not_support_partial_board_id(&mut real_ctx);
        }
        rlz = "0xffffffff";
        0x3f80
    } else if phase == "whitelabel_dev_flags" {
        if GSC_NAME == "cr50" {
            exit_if_not_support_partial_board_id(&mut real_ctx);
        }
        rlz = "0xffffffff";
        // Per discussion in b/179626571
        0x3f7f
    } else if phase == "whitelabel_pvt" {
        0x3f80
    } else if phase == "whitelabel_dev" {
        // Per discussion in b/179626571
        0x3f7f
    } else if phase == "unknown" {
        0xff00
    } else if phase == "dev"
        || phase.starts_with("proto")
        || phase.starts_with("evt")
        || phase.starts_with("dvt")
    {
        // Per discussion related in b/67009607 and
        // go/cr50-board-id-in-factory#heading=h.7woiaqrgyoe1, 0x8000 is reserved.
        0x7f7f
    } else if phase.starts_with("mp") || phase.starts_with("pvt") {
        0x7f80
    } else {
        die(&format!("Unknown phase ({})", phase))
    };

    let tmp_vec: Vec<u8>;
    if rlz.is_empty() {
        // To provision board ID, we use RLZ brand code which is a four letter code
        // (see full list on go/crosrlz) from cros_config.
        if let Ok(cros_config_exec_result) = real_ctx
            .cmd_runner()
            .run("cros_config", vec!["/", "brand-code"])
        {
            if cros_config_exec_result.status.success() {
                tmp_vec = cros_config_exec_result.stdout;
                rlz = std::str::from_utf8(&tmp_vec).unwrap();
            } else {
                die("cros_config returned non-zero.");
            }
        } else {
            die("Failed to run cros_config.");
        }
    }

    match rlz.len() {
        0 => {
            die("No RLZ brand code assigned yet.");
        }
        4 => {
            // Valid RLZ consists of 4 letters
        }
        10 => {
            if rlz != "0xffffffff" {
                die(&format!("Only support erased hex RLZ not {}", rlz));
            }
        }
        _ => {
            die(&format!("Invalid RLZ brand code ({}).", rlz));
        }
    };

    let hooray_message: String = format!(
        r"Successfully updated board ID to '{}' with '{}'.",
        rlz, phase
    );

    let rlz: u32 = if rlz.len() == 10 {
        0xffffffff
    } else {
        u32::from_be_bytes(rlz.as_bytes().try_into().unwrap())
    };

    cr50_check_board_id_and_flag(&mut real_ctx, rlz, flag)
        .map_err(|e| exit(e as i32))
        .unwrap();

    cr50_set_board_id_and_flag(&mut real_ctx, rlz, flag)
        .map_err(|e| exit(e as i32))
        .unwrap();

    println!("{}", hooray_message);
}
