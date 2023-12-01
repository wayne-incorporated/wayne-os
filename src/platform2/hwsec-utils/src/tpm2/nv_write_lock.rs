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

pub fn nv_write_lock(ctx: &mut impl Context, index: u32) -> Result<(), HwsecError> {
    let tpm_cmd = gen_tpm_cmd(
        TpmiStCommandTag::TPM_ST_SESSIONS(SessionOption::EmptyPassword),
        CommandArg::TPM_CC_NV_WriteLock,
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
    use crate::context::mock::MockContext;
    use crate::context::Context;
    use crate::error::HwsecError;
    use crate::tpm2::nv_write_lock;
    use crate::tpm2::tests::split_into_hex_strtok;
    use crate::tpm2::BOARD_ID_INDEX;

    #[test]
    fn test_nv_write_lock_successful() {
        let index = BOARD_ID_INDEX;

        let mut mock_ctx = MockContext::new();

        mock_ctx.cmd_runner().set_trunksd_running(true);
        mock_ctx.cmd_runner().add_tpm_interaction(
            "trunks_send",
            vec!["--raw"],
            split_into_hex_strtok(
                "80 02 00 00 00 1f 00 00 \
                01 38 01 3f ff 00 01 3f \
                ff 00 00 00 00 09 40 00 \
                00 09 00 00 00 00 00",
            ),
            0,
            "800200000021000000000000000E000C4646524DB9B9ADB27F7F00000000010000",
            "",
        );

        let result = nv_write_lock(&mut mock_ctx, index);
        assert_eq!(result, Ok(()));
    }
    #[test]
    fn test_nv_write_lock_unsuccessful_response() {
        let index = 0x76543210_u32;

        let mut mock_ctx = MockContext::new();

        mock_ctx.cmd_runner().set_trunksd_running(true);
        mock_ctx.cmd_runner().add_tpm_interaction(
            "trunks_send",
            vec!["--raw"],
            split_into_hex_strtok(
                "80 02 00 00 00 1f 00 00 \
                01 38 76 54 32 10 76 54 \
                32 10 00 00 00 09 40 00 \
                00 09 00 00 00 00 00",
            ),
            0,
            "80010000000A13371337",
            "",
        );

        let result = nv_write_lock(&mut mock_ctx, index);
        // 0x13371337 is just a piece of random stuff to test response parsing,
        // not referring to any specific error
        assert_eq!(result, Err(HwsecError::Tpm2Error(0x13371337)));
    }
    #[test]
    fn test_nv_write_lock_nonzero_exit_status() {
        let index = 0x76543210_u32;

        let mut mock_ctx = MockContext::new();

        mock_ctx.cmd_runner().set_trunksd_running(true);
        mock_ctx.cmd_runner().add_tpm_interaction(
            "trunks_send",
            vec!["--raw"],
            split_into_hex_strtok(
                "80 02 00 00 00 1f 00 00 \
                01 38 76 54 32 10 76 54 \
                32 10 00 00 00 09 40 00 \
                00 09 00 00 00 00 00",
            ),
            1,
            "",
            "",
        );

        let result = nv_write_lock(&mut mock_ctx, index);
        assert_eq!(result, Err(HwsecError::CommandRunnerError));
    }
}
