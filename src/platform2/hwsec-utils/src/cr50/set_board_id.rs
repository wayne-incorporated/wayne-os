// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt;
use std::fmt::Display;

use super::extract_board_id_from_gsctool_response;
use super::run_gsctool_cmd;
use super::Version;
use crate::command_runner::CommandRunner;
use crate::context::Context;
use crate::cr50::get_value_from_gsctool_output;
use crate::cr50::parse_version;
use crate::tpm2::ERASED_BOARD_ID;

pub const WHITELABEL: u32 = 0x4000;
pub const VIRTUAL_NV_INDEX_START: u32 = 0x013fff00;

#[derive(Debug, PartialEq, Eq)]
pub enum Cr50SetBoardIDVerdict {
    Successful,
    GeneralError,
    AlreadySetError,
    AlreadySetDifferentlyError,
    DeviceStateError,
}

impl Display for Cr50SetBoardIDVerdict {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Cr50SetBoardIDVerdict::Successful => write!(f, "Successful"),
            Cr50SetBoardIDVerdict::GeneralError => write!(f, "GeneralError"),
            Cr50SetBoardIDVerdict::AlreadySetError => write!(f, "AlreadySetError"),
            Cr50SetBoardIDVerdict::AlreadySetDifferentlyError => {
                write!(f, "AlreadySetDifferentlyError")
            }
            Cr50SetBoardIDVerdict::DeviceStateError => write!(f, "DeviceStateError"),
        }
    }
}

impl From<Cr50SetBoardIDVerdict> for i32 {
    fn from(verdict: Cr50SetBoardIDVerdict) -> Self {
        match verdict {
            Cr50SetBoardIDVerdict::Successful => 0,
            Cr50SetBoardIDVerdict::GeneralError => 1,
            Cr50SetBoardIDVerdict::AlreadySetError => 2,
            Cr50SetBoardIDVerdict::AlreadySetDifferentlyError => 3,
            Cr50SetBoardIDVerdict::DeviceStateError => 4,
        }
    }
}

pub fn cr50_check_board_id_and_flag(
    ctx: &mut impl Context,
    new_board_id: u32,
    new_flag: u16,
) -> Result<(), Cr50SetBoardIDVerdict> {
    let board_id_output = {
        let gsctool_raw_response =
            run_gsctool_cmd(ctx, vec!["--any", "--board_id"]).map_err(|_| {
                eprintln!("Failed to run gsctool.");
                Cr50SetBoardIDVerdict::GeneralError
            })?;
        let board_id_output = std::str::from_utf8(&gsctool_raw_response.stdout).unwrap();
        extract_board_id_from_gsctool_response(board_id_output)
    };
    let board_id = board_id_output.map_err(|e| {
        eprintln!(
            "Failed to execute gsctool or failed to read board id - {}",
            e
        );
        Cr50SetBoardIDVerdict::GeneralError
    })?;

    if board_id.part_1 == ERASED_BOARD_ID.part_1 && board_id.part_2 == ERASED_BOARD_ID.part_2 {
        // Board ID is type cleared, it's ok to go ahead and set it.
        Ok(())
    } else if board_id.part_1 != new_board_id {
        eprintln!("Board ID had been set differently.");
        Err(Cr50SetBoardIDVerdict::AlreadySetDifferentlyError)
    } else if (board_id.flag ^ (new_flag as u32)) == WHITELABEL {
        // The 0x4000 bit is the difference between MP and whitelabel flags. Factory
        // scripts can ignore this mismatch if it's the only difference between the set
        // board id and the new board id.
        eprintln!("Board ID and flag have already been set. Whitelabel mismatched.");
        Err(Cr50SetBoardIDVerdict::AlreadySetError)
    } else if board_id.flag != new_flag as u32 {
        eprintln!("Flag had been set differently.");
        Err(Cr50SetBoardIDVerdict::AlreadySetDifferentlyError)
    } else {
        eprintln!("Board ID and flag have already been set.");
        Err(Cr50SetBoardIDVerdict::AlreadySetError)
    }
}

pub fn cr50_set_board_id_and_flag(
    ctx: &mut impl Context,
    board_id: u32,
    flag: u16,
) -> Result<(), Cr50SetBoardIDVerdict> {
    let updater_arg = &format!("{:08x}:{:08x}", board_id, flag);
    let update_output =
        run_gsctool_cmd(ctx, vec!["--any", "--board_id", updater_arg]).map_err(|_| {
            eprintln!("Failed to run gsctool.");
            Cr50SetBoardIDVerdict::GeneralError
        })?;
    if !update_output.status.success() {
        eprintln!("Failed to update with {}.", updater_arg);
        Err(Cr50SetBoardIDVerdict::GeneralError)
    } else {
        Ok(())
    }
}

// Exit if cr50 is running an image with a version less than the given prod or
// prepvt version. The arguments are the lowest prod version the DUT should be
// running, the lowest prepvt version the DUT should be running, and a
// description of the feature.
pub fn check_cr50_support(
    ctx: &mut impl Context,
    target_prod: Version,
    target_prepvt: Version,
    desc: &str,
) -> Result<(), Cr50SetBoardIDVerdict> {
    let gsctool_output =
        run_gsctool_cmd(ctx, vec!["--any", "--fwver", "--machine"]).map_err(|_| {
            eprintln!("Failed to run gsctool.");
            Cr50SetBoardIDVerdict::GeneralError
        })?;
    if !gsctool_output.status.success() {
        eprintln!("Failed to get the version");
        return Err(Cr50SetBoardIDVerdict::GeneralError);
    }

    let output = std::str::from_utf8(&gsctool_output.stdout).map_err(|_| {
        eprintln!("Internal error occurred.");
        Cr50SetBoardIDVerdict::GeneralError
    })?;

    let rw_version_str = get_value_from_gsctool_output(output, "RW_FW_VER").map_err(|_| {
        eprintln!("Failed to extract RW_FW_VERSION from gsctool response");
        Cr50SetBoardIDVerdict::GeneralError
    })?;
    eprintln!("{}", rw_version_str);
    let Some(rw_version) = parse_version(rw_version_str) else {
        eprintln!("Failed to parse {} into version", rw_version_str);
        return Err(Cr50SetBoardIDVerdict::GeneralError);
    };

    let target = if rw_version.is_prod_image() {
        target_prod
    } else {
        target_prepvt
    };
    if rw_version.to_ord() < target.to_ord() {
        eprintln!(
            "Running cr50 {}. {} support was added in .{}.",
            rw_version, desc, target
        );
        Err(Cr50SetBoardIDVerdict::GeneralError)
    } else {
        Ok(())
    }
}

pub fn check_cr50_support_partial_board_id(
    ctx: &mut impl Context,
) -> Result<(), Cr50SetBoardIDVerdict> {
    check_cr50_support(
        ctx,
        Version {
            epoch: 0,
            major: 3,
            minor: 24,
        },
        Version {
            epoch: 0,
            major: 4,
            minor: 24,
        },
        "partial board id",
    )
}

// Only check and set Board ID in normal mode without debug features turned on
// and only if the device has been finalized, as evidenced by the software
// write protect status. In some states scripts should also skip the reboot
// after update. If the SW WP is disabled or the state can not be gotten, skip
// reboot. Use ERR_GENERAL when the board id shouldn't be set. Use the
// ERR_DEVICE_STATE exit status when the reboot and setting the board id should
// be skipped
pub fn check_device(ctx: &mut impl Context) -> Result<(), Cr50SetBoardIDVerdict> {
    let flash_output = ctx
        .cmd_runner()
        .run("flashrom", vec!["-p", "host", "--wp-status"])
        .map_err(|_| {
            eprintln!("Failed to run flashrom.");
            Cr50SetBoardIDVerdict::GeneralError
        })?;

    if !flash_output.status.success() {
        eprintln!(
            "{}{}",
            String::from_utf8_lossy(&flash_output.stdout),
            String::from_utf8_lossy(&flash_output.stderr)
        );
        return Err(Cr50SetBoardIDVerdict::DeviceStateError);
    }

    let crossystem_output = ctx
        .cmd_runner()
        .run(
            "crossystem",
            vec![r"'mainfw_type?normal'", r"'cros_debug?0'"],
        )
        .map_err(|_| {
            eprintln!("Failed to run crossystem");
            Cr50SetBoardIDVerdict::GeneralError
        })?;
    if !crossystem_output.status.success() {
        eprintln!("Not running normal image.");
        return Err(Cr50SetBoardIDVerdict::GeneralError);
    }

    let flash_output_string = format!(
        "{}{}",
        String::from_utf8_lossy(&flash_output.stdout),
        String::from_utf8_lossy(&flash_output.stderr)
    );
    if flash_output_string.contains("write protect is disabled") {
        eprintln!("write protection is disabled");
        Err(Cr50SetBoardIDVerdict::DeviceStateError)
    } else {
        Err(Cr50SetBoardIDVerdict::Successful)
    }
}

#[cfg(test)]
mod tests {
    use crate::command_runner::MockCommandInput;
    use crate::command_runner::MockCommandOutput;
    use crate::context::mock::MockContext;
    use crate::context::Context;
    use crate::cr50::check_cr50_support_partial_board_id;
    use crate::cr50::check_device;
    use crate::cr50::cr50_check_board_id_and_flag;
    use crate::cr50::cr50_set_board_id_and_flag;
    use crate::cr50::Cr50SetBoardIDVerdict;

    #[test]
    fn test_cr50_check_board_id_and_flag_ok() {
        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--any", "--board_id"],
            0,
            "Board ID space: ffffffff:ffffffff:ffffffff",
            "",
        );

        let result = cr50_check_board_id_and_flag(&mut mock_ctx, 0x00000000, 0x0000);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_cr50_check_board_id_and_flag_part_1_neq_new_board_id() {
        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--any", "--board_id"],
            0,
            "Board ID space: 12345678:23456789:34567890",
            "",
        );

        let result = cr50_check_board_id_and_flag(&mut mock_ctx, 0x1234567a, 0x0000);
        assert_eq!(
            result,
            Err(Cr50SetBoardIDVerdict::AlreadySetDifferentlyError)
        );
    }

    #[test]
    fn test_cr50_check_board_id_and_flag_flag_xor_new_flag_eq_whitelabel() {
        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--any", "--board_id"],
            0,
            "Board ID space: 12345678:23456789:00000087",
            "",
        );

        let result = cr50_check_board_id_and_flag(&mut mock_ctx, 0x12345678, 0x4087);
        assert_eq!(result, Err(Cr50SetBoardIDVerdict::AlreadySetError));
    }

    #[test]
    fn test_cr50_check_board_id_and_flag_board_id_flag_neq_new_flag() {
        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--any", "--board_id"],
            0,
            "Board ID space: 12345678:23456789:00001234",
            "",
        );

        let result = cr50_check_board_id_and_flag(&mut mock_ctx, 0x12345678, 0x4087);
        assert_eq!(
            result,
            Err(Cr50SetBoardIDVerdict::AlreadySetDifferentlyError)
        );
    }

    #[test]
    fn test_cr50_check_board_id_and_flag_else_case() {
        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--any", "--board_id"],
            0,
            "Board ID space: 12345678:23456789:00001234",
            "",
        );

        let result = cr50_check_board_id_and_flag(&mut mock_ctx, 0x12345678, 0x1234);
        assert_eq!(result, Err(Cr50SetBoardIDVerdict::AlreadySetError));
    }

    #[test]
    fn test_cr50_set_board_id_and_flag_ok() {
        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--any", "--board_id", "12345678:0000abcd"],
            0,
            "",
            "",
        );

        let result = cr50_set_board_id_and_flag(&mut mock_ctx, 0x12345678, 0xabcd);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_cr50_set_board_id_and_flag_failed() {
        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--any", "--board_id", "12345678:0000abcd"],
            1,
            "",
            "",
        );

        let result = cr50_set_board_id_and_flag(&mut mock_ctx, 0x12345678, 0xabcd);
        assert_eq!(result, Err(Cr50SetBoardIDVerdict::GeneralError));
    }

    // TODO (b/249410379): design more unit tests,
    // continue from testing cr50_set_board_id_and_flag
    #[test]
    fn test_check_cr50_support_ok() {
        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--any", "--fwver", "--machine"],
            0,
            "RW_FW_VER=1.0.0",
            "",
        );

        let result = check_cr50_support_partial_board_id(&mut mock_ctx);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_check_cr50_support_failed_to_get_version() {
        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--any", "--fwver", "--machine"],
            0,
            "",
            "",
        );

        let result = check_cr50_support_partial_board_id(&mut mock_ctx);
        assert_eq!(result, Err(Cr50SetBoardIDVerdict::GeneralError));
    }

    #[test]
    fn test_check_cr50_support_prod_version_too_old() {
        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--any", "--fwver", "--machine"],
            0,
            "RW_FW_VER=0.3.23",
            "",
        );

        let result = check_cr50_support_partial_board_id(&mut mock_ctx);
        assert_eq!(result, Err(Cr50SetBoardIDVerdict::GeneralError));
    }

    #[test]
    fn test_check_cr50_support_prepvt_version_too_old() {
        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--any", "--fwver", "--machine"],
            0,
            "RW_FW_VER=0.4.23",
            "",
        );

        let result = check_cr50_support_partial_board_id(&mut mock_ctx);
        assert_eq!(result, Err(Cr50SetBoardIDVerdict::GeneralError));
    }

    #[test]
    fn test_check_device_ok() {
        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_expectation(
            MockCommandInput::new("flashrom", vec!["-p", "host", "--wp-status"]),
            MockCommandOutput::new(0, "", ""),
        );
        mock_ctx.cmd_runner().add_expectation(
            MockCommandInput::new(
                "crossystem",
                vec![r"'mainfw_type?normal'", r"'cros_debug?0'"],
            ),
            MockCommandOutput::new(0, "", ""),
        );
        let result = check_device(&mut mock_ctx);
        assert_eq!(result, Err(Cr50SetBoardIDVerdict::Successful));
    }

    #[test]
    fn test_check_device_flashrom_error() {
        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_expectation(
            MockCommandInput::new("flashrom", vec!["-p", "host", "--wp-status"]),
            MockCommandOutput::new(1, "", ""),
        );
        let result = check_device(&mut mock_ctx);
        assert_eq!(result, Err(Cr50SetBoardIDVerdict::DeviceStateError));
    }

    #[test]
    fn test_check_device_not_running_normal_image() {
        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_expectation(
            MockCommandInput::new("flashrom", vec!["-p", "host", "--wp-status"]),
            MockCommandOutput::new(0, "", ""),
        );
        mock_ctx.cmd_runner().add_expectation(
            MockCommandInput::new(
                "crossystem",
                vec![r"'mainfw_type?normal'", r"'cros_debug?0'"],
            ),
            MockCommandOutput::new(1, "", ""),
        );
        let result = check_device(&mut mock_ctx);
        assert_eq!(result, Err(Cr50SetBoardIDVerdict::GeneralError));
    }

    #[test]
    fn test_check_device_write_protect_is_disabled() {
        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_expectation(
            MockCommandInput::new("flashrom", vec!["-p", "host", "--wp-status"]),
            MockCommandOutput::new(0, "write protect is disabled", ""),
        );
        mock_ctx.cmd_runner().add_expectation(
            MockCommandInput::new(
                "crossystem",
                vec![r"'mainfw_type?normal'", r"'cros_debug?0'"],
            ),
            MockCommandOutput::new(0, "", ""),
        );
        let result = check_device(&mut mock_ctx);
        assert_eq!(result, Err(Cr50SetBoardIDVerdict::DeviceStateError));
    }
}
