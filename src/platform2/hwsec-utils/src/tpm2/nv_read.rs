// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::context::Context;
use crate::error::HwsecError;
use crate::tpm2::gen_tpm_cmd;
use crate::tpm2::run_tpm_cmd;
use crate::tpm2::CommandArg;
use crate::tpm2::SessionOption;
use crate::tpm2::TpmiStCommandTag;

pub fn nv_read(ctx: &mut impl Context, index: u32, length: u16) -> Result<Vec<u8>, HwsecError> {
    const SESSION_DESCRIPTION_LENGTH: usize = 6;
    let tpm_cmd = gen_tpm_cmd(
        TpmiStCommandTag::TPM_ST_SESSIONS(SessionOption::EmptyPassword),
        CommandArg::TPM_CC_NV_Read(length),
        index,
    )?;
    let response = run_tpm_cmd(ctx, tpm_cmd)?;
    if response.success() {
        if response.body().len() < SESSION_DESCRIPTION_LENGTH + length as usize {
            // This only happens when TPM is not functioning correctly
            // by returning less bytes than we requested.
            Err(HwsecError::InternalError)
        } else {
            Ok(response.body()
                [SESSION_DESCRIPTION_LENGTH..(SESSION_DESCRIPTION_LENGTH + length as usize)]
                .to_vec())
        }
    } else {
        Err(HwsecError::Tpm2Error(response.return_code()))
    }
}

#[cfg(test)]
mod tests {
    use crate::context::mock::MockContext;
    use crate::context::Context;
    use crate::error::HwsecError;
    use crate::tpm2::nv_read;
    use crate::tpm2::tests::split_into_hex_strtok;
    use crate::tpm2::BOARD_ID_INDEX;
    use crate::tpm2::BOARD_ID_LENGTH;

    #[test]
    fn test_nv_read_successful() {
        let index = BOARD_ID_INDEX;
        let length = BOARD_ID_LENGTH;

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

        let result = nv_read(&mut mock_ctx, index, length);

        assert_eq!(
            result,
            Ok(vec![
                0x46, 0x46, 0x52, 0x4d, 0xb9, 0xb9, 0xad, 0xb2, 0x7f, 0x7f, 0x00, 0x00
            ])
        );
    }
    #[test]
    fn test_nv_read_length_too_large() {
        let index = BOARD_ID_INDEX;
        let length = 13_u16;

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
                0d 00 00",
            ),
            0,
            "80010000000A00000146",
            "",
        );

        let result = nv_read(&mut mock_ctx, index, length);

        // return code 0x00000146 = TPM_RC_NV_RANGE = RC_VER1(0x100) + 0x046
        assert_eq!(result, Err(HwsecError::Tpm2Error(0x00000146)));
    }
    #[test]
    fn test_nv_read_nonzero_exit_status() {
        let index = BOARD_ID_INDEX;
        let length = 13_u16;

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
                0d 00 00",
            ),
            1,
            "",
            "",
        );

        let result = nv_read(&mut mock_ctx, index, length);
        assert_eq!(result, Err(HwsecError::CommandRunnerError));
    }
    #[test]
    fn test_tpmc_raw_successful() {
        let index = BOARD_ID_INDEX;
        let length = 12_u16;

        let mut mock_ctx = MockContext::new();

        mock_ctx.cmd_runner().set_trunksd_running(false);
        mock_ctx.cmd_runner().add_tpm_interaction(
            "tpmc",
            vec!["raw"],
            split_into_hex_strtok(
                "80 02 00 00 00 23 00 00 \
                01 4e 01 3f ff 00 01 3f \
                ff 00 00 00 00 09 40 00 \
                00 09 00 00 00 00 00 00 \
                0c 00 00",
            ),
            0,
            "0x80 0x02 0x00 0x00 0x00 0x21 0x00 0x00 \n
            0x00 0x00 0x00 0x00 0x00 0x0e 0x00 0x0c \n
            0x46 0x46 0x52 0x4d 0xb9 0xb9 0xad 0xb2 \n
            0x7f 0x7f 0x00 0x00 0x00 0x00 0x01 0x00 \n
            0x00",
            "",
        );

        let result = nv_read(&mut mock_ctx, index, length);
        assert_eq!(
            result,
            Ok(vec![
                0x46, 0x46, 0x52, 0x4d, 0xb9, 0xb9, 0xad, 0xb2, 0x7f, 0x7f, 0x00, 0x00
            ])
        );
    }
    #[test]
    fn nonzero_tpmc_return_code() {
        let index = BOARD_ID_INDEX;
        let length = 12_u16;

        let mut mock_ctx = MockContext::new();

        mock_ctx.cmd_runner().set_trunksd_running(false);
        mock_ctx.cmd_runner().add_tpm_interaction(
            "tpmc",
            vec!["raw"],
            split_into_hex_strtok(
                "80 02 00 00 00 23 00 00 \
                01 4e 01 3f ff 00 01 3f \
                ff 00 00 00 00 09 40 00 \
                00 09 00 00 00 00 00 00 \
                0c 00 00",
            ),
            -1,
            "",
            "bad byte value \"8002000000230000014e013\
            fff00013fff0000000009400000090000000000000c0000\"",
        );

        let result = nv_read(&mut mock_ctx, index, length);
        assert_eq!(result, Err(HwsecError::CommandRunnerError));
    }
}
