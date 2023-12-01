// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::gen_tpm_cmd;
use super::run_tpm_cmd;
use super::CommandArg;
use super::SessionOption;
use super::TpmiStCommandTag;
use crate::context::Context;
use crate::error::HwsecError;

pub fn nv_write(ctx: &mut impl Context, index: u32, data: Vec<u8>) -> Result<(), HwsecError> {
    let tpm_cmd = gen_tpm_cmd(
        TpmiStCommandTag::TPM_ST_SESSIONS(SessionOption::EmptyPassword),
        CommandArg::TPM_CC_NV_Write(data),
        index,
    )?;
    let response = run_tpm_cmd(ctx, tpm_cmd)?;
    if response.success() {
        Ok(())
    } else {
        Err(HwsecError::Tpm2Error(response.return_code()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::mock::MockContext;
    use crate::tpm2::tests::split_into_hex_strtok;
    use crate::tpm2::BOARD_ID_INDEX;

    #[test]
    fn test_nv_write_successful() {
        let index = BOARD_ID_INDEX;
        let data: Vec<u8> = vec![0xff, 0x01, 0x23];

        let mut mock_ctx = MockContext::new();

        mock_ctx.cmd_runner().set_trunksd_running(true);
        mock_ctx.cmd_runner().add_tpm_interaction(
            "trunks_send",
            vec!["--raw"],
            split_into_hex_strtok(
                "80 02 00 00 00 26 00 00 \
                01 37 01 3f ff 00 01 3f \
                ff 00 00 00 00 09 40 00 \
                00 09 00 00 00 00 00 00 \
                03 ff 01 23 00 00",
            ),
            0,
            "800200000021000000000000000E000C4646524DB9B9ADB27F7F00000000010000",
            "",
        );

        let result = nv_write(&mut mock_ctx, index, data);
        assert_eq!(result, Ok(()));
    }
    #[test]
    fn test_nv_write_bad_formatted_response() {
        let index = 0x89abcdef_u32;
        let data: Vec<u8> = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];

        let mut mock_ctx = MockContext::new();

        mock_ctx.cmd_runner().set_trunksd_running(true);
        mock_ctx.cmd_runner().add_tpm_interaction(
            "trunks_send",
            vec!["--raw"],
            split_into_hex_strtok(
                "80 02 00 00 00 33 00 00 \
                01 37 89 ab cd ef 89 ab \
                cd ef 00 00 00 09 40 00 \
                00 09 00 00 00 00 00 00 \
                10 00 11 22 33 44 55 66 \
                77 88 99 aa bb cc dd ee \
                ff 00 00",
            ),
            0,
            // out[4..12]: 0x0000000B isn't its length, should have been 0x0000000A
            // this inaccurate description of length triggers a bad format error,
            // which is what we want to test here.
            "80010000000B00009487",
            "",
        );

        let result = nv_write(&mut mock_ctx, index, data);
        assert_eq!(result, Err(HwsecError::Tpm2ResponseBadFormatError));
    }
    #[test]
    fn test_nv_write_nonzero_exit_status() {
        let index = 0x89abcdef_u32;
        let data: Vec<u8> = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];

        let mut mock_ctx = MockContext::new();

        mock_ctx.cmd_runner().set_trunksd_running(true);
        mock_ctx.cmd_runner().add_tpm_interaction(
            "trunks_send",
            vec!["--raw"],
            split_into_hex_strtok(
                "80 02 00 00 00 33 00 00 \
                01 37 89 ab cd ef 89 ab \
                cd ef 00 00 00 09 40 00 \
                00 09 00 00 00 00 00 00 \
                10 00 11 22 33 44 55 66 \
                77 88 99 aa bb cc dd ee \
                ff 00 00",
            ),
            1,
            "",
            "",
        );

        let result = nv_write(&mut mock_ctx, index, data);
        assert_eq!(result, Err(HwsecError::CommandRunnerError));
    }
    #[test]
    fn test_nv_write_data_too_large() {
        let index = BOARD_ID_INDEX;
        let data: Vec<u8> = vec![0x99; 1000000];

        let mut mock_ctx = MockContext::new();

        let result = nv_write(&mut mock_ctx, index, data);
        assert_eq!(result, Err(HwsecError::InvalidArgumentError));
    }
}
