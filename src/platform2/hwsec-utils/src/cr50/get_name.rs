// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use log::info;

use crate::context::Context;
use crate::cr50::extract_board_id_from_gsctool_response;
use crate::cr50::run_gsctool_cmd;
use crate::cr50::GSCTOOL_CMD_NAME;
use crate::cr50::GSC_IMAGE_BASE_NAME;
use crate::error::HwsecError;
use crate::tpm2::ERASED_BOARD_ID;

pub fn cr50_get_name(
    ctx: &mut impl Context,
    gsctool_command_options: &[&str],
) -> Result<String, HwsecError> {
    const PRE_PVT_FLAG: u32 = 0x10;

    info!("updater is {}", GSCTOOL_CMD_NAME);

    let exe_result = run_gsctool_cmd(ctx, [gsctool_command_options, &["--board_id"]].concat())?;
    let exit_status = exe_result.status.code().unwrap();
    let output = format!(
        "{}{}",
        std::str::from_utf8(&exe_result.stdout)
            .map_err(|_| HwsecError::Tpm2ResponseBadFormatError)?,
        std::str::from_utf8(&exe_result.stderr)
            .map_err(|_| HwsecError::Tpm2ResponseBadFormatError)?
    );
    let mut ext = "prod";

    let board_id = extract_board_id_from_gsctool_response(&output)?;

    let board_flags = format!("0x{:02x}", board_id.flag);

    if exit_status != 0 {
        info!("exit status: {}", exit_status);
        info!("output: {}", output);
    } else if board_id == ERASED_BOARD_ID {
        info!("board ID is erased using {} image", ext);
    } else if board_id.flag & PRE_PVT_FLAG != 0 {
        ext = "prepvt";
    }

    info!(
        r"board_id: '{:02x}:{:02x}:{:02x}' board_flags: '{}', extension: '{}'",
        board_id.part_1, board_id.part_2, board_id.flag, board_flags, ext
    );

    Ok(format!("{}.{}", GSC_IMAGE_BASE_NAME, ext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::mock::MockContext;
    use crate::cr50::GSC_IMAGE_BASE_NAME;
    #[test]
    fn test_cr50_get_name() {
        let mut mock_ctx = MockContext::new();

        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--any", "--board_id"],
            0,
            "finding_device 18d1:5014\n\
            Found device.\n\
            found interface 3 endpoint 4, chunk_len 64\n\
            READY\n\
            -------\n\
            Board ID space: 43425559:bcbdaaa6:00007f80\n",
            "",
        );

        let name = cr50_get_name(&mut mock_ctx, &["--any"]);

        assert_eq!(name, Ok(String::from(GSC_IMAGE_BASE_NAME) + ".prod"));
    }

    #[test]
    fn test_cr50_get_name_board_id_not_found() {
        let mut mock_ctx = MockContext::new();

        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--any", "--board_id"],
            0,
            "finding_device 18d1:5014\n\
            Found device.\n\
            found interface 3 endpoint 4, chunk_len 64\n\
            READY\n\
            -------\n\
            Board ID space: 43425559:bxbdaaa6:00007f80\n",
            "",
        );

        let name = cr50_get_name(&mut mock_ctx, &["--any"]);
        assert_eq!(name, Err(HwsecError::GsctoolResponseBadFormatError));
    }

    #[test]
    fn test_cr50_get_name_different_ext() {
        let mut mock_ctx = MockContext::new();

        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--any", "--board_id"],
            0,
            "finding_device 18d1:5014\n\
            Found device.\n\
            found interface 3 endpoint 4, chunk_len 64\n\
            READY\n\
            -------\n\
            Board ID space: 43425559:bcbdaaa6:00007f10\n",
            "",
        );

        let name = cr50_get_name(&mut mock_ctx, &["--any"]);

        assert_eq!(name, Ok(String::from(GSC_IMAGE_BASE_NAME) + ".prepvt"));
    }
}
