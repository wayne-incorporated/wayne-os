// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use hwsec_utils::context::RealContext;
use hwsec_utils::tpm2::read_board_id;

fn main() {
    let mut real_ctx = RealContext::new();
    let result = read_board_id(&mut real_ctx);
    match result {
        Ok(board_id) => println!(
            "{:08x}:{:08x}:{:08x}",
            board_id.part_1, board_id.part_2, board_id.flag
        ),
        Err(e) => eprintln!("{}", e),
    }
}
