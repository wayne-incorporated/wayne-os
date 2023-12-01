// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::nv_read;
use super::BoardID;
use super::BOARD_ID_INDEX;
use super::BOARD_ID_LENGTH;
use crate::context::Context;
use crate::error::HwsecError;

pub fn read_board_id(ctx: &mut impl Context) -> Result<BoardID, HwsecError> {
    let raw_board_id = nv_read(ctx, BOARD_ID_INDEX, BOARD_ID_LENGTH)?;
    Ok(BoardID {
        part_1: u32::from_le_bytes(raw_board_id[0..4].try_into().unwrap()),
        part_2: u32::from_le_bytes(raw_board_id[4..8].try_into().unwrap()),
        flag: u32::from_le_bytes(raw_board_id[8..12].try_into().unwrap()),
    })
}

#[cfg(test)]
mod tests {
    use crate::context::mock::MockContext;
    use crate::context::Context;
    use crate::error::HwsecError;
    use crate::tpm2::read_board_id;
    use crate::tpm2::tests::split_into_hex_strtok;
    use crate::tpm2::BoardID;

    #[test]
    fn test_read_board_id_successful() {
        let mut mock_ctx = MockContext::new();

        mock_ctx.cmd_runner().set_trunksd_running(true);
        mock_ctx.cmd_runner().add_tpm_interaction(
            "trunks_send",
            vec!["--raw"],
            split_into_hex_strtok(
                "80 02 00 00 00 23 00 00 \
                01 4e 01 3f ff 00 01 3f \
                ff 00 00 00 00 09 40 00 \
                00 09 00 00 00 00 00 00 \
                0c 00 00",
            ),
            0,
            "800200000021000000000000000E000C4646524DB9B9ADB27F7F00000000010000",
            "",
        );

        let result = read_board_id(&mut mock_ctx);
        assert_eq!(
            result,
            Ok(BoardID {
                part_1: 0x4d524646,
                part_2: 0xb2adb9b9,
                flag: 0x00007f7f
            })
        );
    }
    #[test]
    fn test_read_board_id_nonzero_exit_status() {
        let mut mock_ctx = MockContext::new();

        mock_ctx.cmd_runner().set_trunksd_running(true);
        mock_ctx.cmd_runner().add_tpm_interaction(
            "trunks_send",
            vec!["--raw"],
            split_into_hex_strtok(
                "80 02 00 00 00 23 00 00 \
                01 4e 01 3f ff 00 01 3f \
                ff 00 00 00 00 09 40 00 \
                00 09 00 00 00 00 00 00 \
                0c 00 00",
            ),
            1,
            "",
            "",
        );

        let result = read_board_id(&mut mock_ctx);
        assert_eq!(result, Err(HwsecError::CommandRunnerError));
    }
}
