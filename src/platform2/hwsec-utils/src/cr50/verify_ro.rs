// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::path::Path;

use crate::context::Context;
use crate::cr50::get_value_from_gsctool_output;
use crate::cr50::parse_version;
use crate::cr50::run_gsctool_cmd;
use crate::cr50::Version;
use crate::error::HwsecError;

/// Retrieve Cr50 version running on the DUT. Reported in 'gsctool -afM' output
/// as RW_FW_VER=<epoch>.<major>.<minor>
fn retrieve_dut_firmware_rw_version(ctx: &mut impl Context) -> Result<Version, HwsecError> {
    let gsctool_output = run_gsctool_cmd(ctx, vec!["--fwver", "--machine"]).map_err(|e| {
        eprintln!("Failed to run gsctool.");
        e
    })?;

    if !gsctool_output.status.success() {
        eprintln!("Failed to get running Cr50 firmware versions.");
        return Err(HwsecError::GsctoolError(
            gsctool_output.status.code().unwrap(),
        ));
    }

    let output = std::str::from_utf8(&gsctool_output.stdout).map_err(|_| {
        eprintln!("Internal error occurred.");
        HwsecError::GsctoolResponseBadFormatError
    })?;

    let rw_version_str = get_value_from_gsctool_output(output, "RW_FW_VER")?;
    match parse_version(rw_version_str) {
        Some(version) => Ok(version),
        None => {
            eprintln!("Failed to parse {} into version", rw_version_str);
            Err(HwsecError::InternalError)
        }
    }
}

/// Retrieve RW Cr50 version of the supplied image file. Reported in 'gsctool
/// -Mb' output as
///
/// IMAGE_RO_FW_VER=<version>
/// IMAGE_RW_FW_VER=<version>
/// IMAGE_BID_STRING=<hex>
/// IMAGE_BID_MASK=<hex>
/// IMAGE_BID_FLAGS=<hex>
///
/// RW_A and RW_B versions are expected to match for the purposes of this
/// script.
fn retrieve_image_rw_version(
    ctx: &mut impl Context,
    image_path: &Path,
) -> Result<Version, HwsecError> {
    let gsctool_output = run_gsctool_cmd(
        ctx,
        vec!["--machine", "--binvers", image_path.to_str().unwrap()],
    )
    .map_err(|e| {
        eprintln!("ERROR: Failed to run gsctool.");
        e
    })?;

    if !gsctool_output.status.success() {
        eprintln!("Failed to get Cr50 image's RW and RO headers.");
        return Err(HwsecError::GsctoolError(
            gsctool_output.status.code().unwrap(),
        ));
    }

    let output = std::str::from_utf8(&gsctool_output.stdout).map_err(|_| {
        eprintln!("Internal error occurred.");
        HwsecError::GsctoolResponseBadFormatError
    })?;
    let image_version_str = get_value_from_gsctool_output(output, "IMAGE_RW_FW_VER")?;
    match parse_version(image_version_str) {
        Some(version) => Ok(version),
        None => {
            eprintln!("Failed to parse {} into version", image_version_str);
            Err(HwsecError::InternalError)
        }
    }
}

/// Retrieve board ID and flags values from the H1 on the DUT.
///
/// Output of 'gsctool -i' contains a line of the following format:
///
/// BID_TYPE=<hex board ID>
/// BID_TYPE_INV=~<hex board id>
/// BID_FLAGS=<hex flags>
/// BID_RLZ=<ascii rlz>
///
/// The <hex board ID> value is included twice, straight and inverted.
///
/// This function verifies that board ID value is valid and returns the
/// board ID and flags as u32.
fn retrieve_dut_board_id_values(ctx: &mut impl Context) -> Result<(u32, u32), HwsecError> {
    let gsctool_output = run_gsctool_cmd(ctx, vec!["--board_id", "--machine"]).map_err(|e| {
        eprintln!("ERROR: Failed to run gsctool.");
        e
    })?;

    if !gsctool_output.status.success() {
        eprintln!("Failed to get running Cr50 firmware versions.");
        return Err(HwsecError::GsctoolError(
            gsctool_output.status.code().unwrap(),
        ));
    }

    let output = std::str::from_utf8(&gsctool_output.stdout).map_err(|_| {
        eprintln!("Internal error occurred.");
        HwsecError::GsctoolResponseBadFormatError
    })?;

    let board_id_str = get_value_from_gsctool_output(output, "BID_TYPE")?;
    let board_id_invert_str = get_value_from_gsctool_output(output, "BID_TYPE_INV")?;
    let board_id_flags_str = get_value_from_gsctool_output(output, "BID_FLAGS")?;
    // let board_id_rlz = get_value_from_gsctool_output(output, "BID_RLZ=")?;

    let board_id = u32::from_str_radix(board_id_str, 16).map_err(|_| HwsecError::InternalError)?;
    let board_id_invert =
        u32::from_str_radix(board_id_invert_str, 16).map_err(|_| HwsecError::InternalError)?;

    if !board_id != board_id_invert {
        eprintln!(
            "Invalid chip board ID value bid {}, ~bid {}",
            board_id_str, board_id_invert_str
        );
        return Err(HwsecError::InternalError);
    }

    let board_id_flags =
        u32::from_str_radix(board_id_flags_str, 16).map_err(|_| HwsecError::InternalError)?;
    Ok((board_id, board_id_flags))
}

fn retrieve_dut_board_rlz(ctx: &mut impl Context) -> Result<String, HwsecError> {
    let gsctool_output = run_gsctool_cmd(ctx, vec!["--board_id", "--machine"]).map_err(|e| {
        eprintln!("ERROR: Failed to run gsctool.");
        e
    })?;

    if !gsctool_output.status.success() {
        eprintln!("Failed to get running Cr50 firmware versions.");
        return Err(HwsecError::GsctoolError(
            gsctool_output.status.code().unwrap(),
        ));
    }

    let output = std::str::from_utf8(&gsctool_output.stdout).map_err(|_| {
        eprintln!("Internal error occurred.");
        HwsecError::GsctoolResponseBadFormatError
    })?;

    let board_rlz = get_value_from_gsctool_output(output, "BID_RLZ")?;
    Ok(String::from(board_rlz))
}

/// Retrieve Cr50 binary's board ID and flags values.
///
/// Output of 'gsctool -b cr50.bin' contains a line of the following format:
///
/// ...
/// IMAGE_BID_STRING=<board ID>
/// IMAGE_BID_MASK=<hex board ID mask>
/// IMAGE_BID_FLAGS=<hex flags>
/// ...
///
/// This function returns the board ID, board ID
/// mask and flags as u32.
fn retrieve_image_board_id_values(
    ctx: &mut impl Context,
    image_path: &Path,
) -> Result<(u32, u32, u32), HwsecError> {
    let gsctool_output = run_gsctool_cmd(
        ctx,
        vec!["--machine", "--binvers", image_path.to_str().unwrap()],
    )
    .map_err(|e| {
        eprintln!("ERROR: Failed to run gsctool.");
        e
    })?;

    if !gsctool_output.status.success() {
        eprintln!("Failed to get Cr50 image's RW and RO headers.");
        return Err(HwsecError::GsctoolError(
            gsctool_output.status.code().unwrap(),
        ));
    }

    let output = std::str::from_utf8(&gsctool_output.stdout).map_err(|_| {
        eprintln!("Internal error occurred.");
        HwsecError::GsctoolResponseBadFormatError
    })?;
    let image_board_id_str = get_value_from_gsctool_output(output, "IMAGE_BID_STRING")?;
    let image_board_id_mask_str = get_value_from_gsctool_output(output, "IMAGE_BID_MASK")?;
    let image_board_id_flags_str = get_value_from_gsctool_output(output, "IMAGE_BID_FLAGS")?;

    let image_board_id =
        u32::from_str_radix(image_board_id_str, 16).map_err(|_| HwsecError::InternalError)?;
    let image_board_id_mask =
        u32::from_str_radix(image_board_id_mask_str, 16).map_err(|_| HwsecError::InternalError)?;
    let image_board_id_flags =
        u32::from_str_radix(image_board_id_flags_str, 16).map_err(|_| HwsecError::InternalError)?;
    Ok((image_board_id, image_board_id_mask, image_board_id_flags))
}

pub fn update_dut_if_needed(ctx: &mut impl Context, new_image: &Path) -> Result<(), HwsecError> {
    let dut_rw_version = retrieve_dut_firmware_rw_version(ctx).map_err(|e| {
        eprintln!(
            "Failed to retrieve DUT Cr50 version. Is DUT connected? \
        You may need to flip suzy-q cable if DUT is already attached."
        );
        e
    })?;
    let image_rw_version = retrieve_image_rw_version(ctx, new_image).map_err(|e| {
        eprintln!("Failed to retrieve image firmware version.");
        e
    })?;

    if dut_rw_version.to_ord() >= image_rw_version.to_ord() {
        // Don't need to update.
        return Ok(());
    }

    // Perform update if DUT version is lower than the supplied image version.
    println!(
        "Updating dut from {} to {}",
        dut_rw_version, image_rw_version
    );

    update_dut(ctx, new_image).map_err(|e| {
        eprintln!("Failed when trying to update DUT.");
        e
    })?;

    println!("Waiting for the DUT to restart");
    ctx.sleep(5); // Let it reboot.

    println!("Verifying that update succeeded");
    let dut_rw_version = retrieve_dut_firmware_rw_version(ctx)?;
    if dut_rw_version.to_ord() < image_rw_version.to_ord() {
        eprintln!("Failed to update DUT to version {}", image_rw_version);
        Err(HwsecError::InternalError)
    } else {
        Ok(())
    }
}

fn update_dut(ctx: &mut impl Context, image_path: &Path) -> Result<(), HwsecError> {
    // Retrieve board ID header fields of the image file.
    let (image_bid, image_mask, image_flags) = retrieve_image_board_id_values(ctx, image_path)?;
    // Retrieve board ID fields of the H1 on the DUT.
    let (chip_bid, chip_flags) = retrieve_dut_board_id_values(ctx)?;

    // Verify that board ID of the image is suitable for the chip.
    if (image_bid & image_mask) != (chip_bid & image_mask) {
        eprintln!("Image board ID and mask incompatible with chip board ID");
        return Err(HwsecError::InternalError);
    }

    // Verify that flags of the image are compatible with the chip.
    if (image_flags & chip_flags) != (image_flags) {
        eprintln!("Image flags incompatible with chip flags");
        return Err(HwsecError::InternalError);
    }

    run_gsctool_cmd(ctx, vec![image_path.to_str().unwrap()])?;
    Ok(())
}

pub fn cr50_verify_ro(ctx: &mut impl Context, ro_descriptions: &Path) -> Result<(), HwsecError> {
    let rlz = retrieve_dut_board_rlz(ctx)?;
    let desc_file_str = ro_descriptions.join(format!("verify_ro_{}.db", rlz));

    let gsctool_output =
        run_gsctool_cmd(ctx, vec!["--openbox_rma", desc_file_str.to_str().unwrap()]).map_err(
            |e| {
                eprintln!("ERROR: Failed to run gsctool.");
                e
            },
        )?;

    if !gsctool_output.status.success() {
        eprintln!("Hash verification failed.");
        return Err(HwsecError::GsctoolError(
            gsctool_output.status.code().unwrap(),
        ));
    }

    eprintln!("Hash verification succeed.");
    Ok(())
}
#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::retrieve_dut_board_id_values;
    use super::retrieve_dut_firmware_rw_version;
    use super::update_dut;
    use super::update_dut_if_needed;
    use crate::context::mock::MockContext;
    use crate::context::Context;
    use crate::cr50::Version;
    use crate::error::HwsecError;

    #[test]
    fn test_retrieve_dut_firmware_rw_version_ok() {
        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--fwver", "--machine"],
            0,
            "RO_FW_VER=0.0.0\nRW_FW_VER=1.2.3",
            "",
        );
        let result = retrieve_dut_firmware_rw_version(&mut mock_ctx);
        assert_eq!(
            result,
            Ok(Version {
                epoch: 1,
                major: 2,
                minor: 3,
            })
        );
    }

    #[test]
    fn test_retrieve_dut_firmware_rw_version_gsctool_outout_wrong_format_1() {
        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--fwver", "--machine"],
            0,
            "RO_FW_VER=1.2.3",
            "",
        );
        let result = retrieve_dut_firmware_rw_version(&mut mock_ctx);
        assert_eq!(result, Err(HwsecError::InternalError));
    }

    #[test]
    fn test_retrieve_dut_firmware_rw_version_gsctool_outout_wrong_format_2() {
        let mut mock_ctx = MockContext::new();
        mock_ctx
            .cmd_runner()
            .add_gsctool_interaction(vec!["--fwver", "--machine"], 0, "1.2.3", "");
        let result = retrieve_dut_firmware_rw_version(&mut mock_ctx);
        assert_eq!(result, Err(HwsecError::InternalError));
    }

    #[test]
    fn test_retrieve_dut_board_id_values_ok() {
        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--board_id", "--machine"],
            0,
            "BID_TYPE=5a5a4352\nBID_TYPE_INV=a5a5bcad\nBID_FLAGS=00007f7f\n",
            "",
        );
        let result = retrieve_dut_board_id_values(&mut mock_ctx);
        assert_eq!(
            result,
            Ok((
                u32::from_str_radix("5a5a4352", 16).unwrap(),
                u32::from_str_radix("00007f7f", 16).unwrap()
            ))
        )
    }

    #[test]
    fn test_retrieve_dut_board_id_values_invalid_bid_inv() {
        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--board_id", "--machine"],
            0,
            "BID_TYPE=5a5a4352\nBID_TYPE_INV=00000000\nBID_FLAGS=00007f7f\n",
            "",
        );
        let result = retrieve_dut_board_id_values(&mut mock_ctx);
        assert_eq!(result, Err(HwsecError::InternalError))
    }

    #[test]
    fn test_update_dut_ok() {
        let mut mock_ctx = MockContext::new();
        // mock interaction for retrieve_image_board_id_values
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--machine", "--binvers", "mock_image_path"],
            0,
            "IMAGE_BID_STRING=00000000\nIMAGE_BID_MASK=00000000\nIMAGE_BID_FLAGS=00000000\n",
            "",
        );
        // mock interaction for retrieve_dut_board_id_values
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--board_id", "--machine"],
            0,
            "BID_TYPE=00000000\nBID_TYPE_INV=ffffffff\nBID_FLAGS=00000000\n",
            "",
        );
        // mock interaction for updating firmware
        mock_ctx
            .cmd_runner()
            .add_gsctool_interaction(vec!["mock_image_path"], 0, "", "");
        let result = update_dut(&mut mock_ctx, Path::new("mock_image_path"));
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_update_dut_bid_incompatible() {
        // (image_bid & image_mask) != (chip_bid & image_mask)
        let mut mock_ctx = MockContext::new();
        // mock interaction for retrieve_image_board_id_values
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--machine", "--binvers", "mock_image_path"],
            0,
            "IMAGE_BID_STRING=00000000\nIMAGE_BID_MASK=00000000\nIMAGE_BID_FLAGS=00000000\n",
            "",
        );
        // mock interaction for retrieve_dut_board_id_values
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--board_id", "--machine"],
            0,
            "BID_TYPE=00000001\nBID_TYPE_INV=ffffffff\nBID_FLAGS=00000000\n",
            "",
        );
        let result = update_dut(&mut mock_ctx, Path::new("mock_image_path"));
        assert_eq!(result, Err(HwsecError::InternalError));
    }

    #[test]
    fn test_update_dut_image_flag_incompatible() {
        // (image_flags & chip_flags) != (image_flags)
        let mut mock_ctx = MockContext::new();
        // mock interaction for retrieve_image_board_id_values
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--machine", "--binvers", "mock_image_path"],
            0,
            "IMAGE_BID_STRING=00000000\nIMAGE_BID_MASK=00000000\nIMAGE_BID_FLAGS=00000001\n",
            "",
        );
        // mock interaction for retrieve_dut_board_id_values
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--board_id", "--machine"],
            0,
            "BID_TYPE=00000000\nBID_TYPE_INV=ffffffff\nBID_FLAGS=00000000\n",
            "",
        );
        let result = update_dut(&mut mock_ctx, Path::new("mock_image_path"));
        assert_eq!(result, Err(HwsecError::InternalError));
    }

    #[test]
    fn test_update_dut_if_needed_update_not_needed() {
        let mut mock_ctx = MockContext::new();
        // mock interaction for retrieve_dut_firmware_rw_version
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--fwver", "--machine"],
            0,
            "RW_FW_VER=1.2.3",
            "",
        );
        // mock interaction for retrieve_image_rw_version
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--machine", "--binvers", "mock_image_path"],
            0,
            "IMAGE_RW_FW_VER=1.2.3",
            "",
        );
        let result = update_dut_if_needed(&mut mock_ctx, Path::new("mock_image_path"));
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_update_dut_if_needed_successfully_update() {
        let mut mock_ctx = MockContext::new();
        // mock interaction for retrieve_dut_firmware_rw_version
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--fwver", "--machine"],
            0,
            "RW_FW_VER=1.2.3",
            "",
        );
        // mock interaction for retrieve_image_rw_version
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--machine", "--binvers", "mock_image_path"],
            0,
            "IMAGE_RW_FW_VER=1.2.4",
            "",
        );
        // mock interaction for retrieve_image_board_id_values
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--machine", "--binvers", "mock_image_path"],
            0,
            "IMAGE_BID_STRING=00000000\nIMAGE_BID_MASK=00000000\nIMAGE_BID_FLAGS=00000000\n",
            "",
        );
        // mock interaction for retrieve_dut_board_id_values
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--board_id", "--machine"],
            0,
            "BID_TYPE=00000000\nBID_TYPE_INV=ffffffff\nBID_FLAGS=00000000\n",
            "",
        );
        // mock interaction for updating firmware
        mock_ctx
            .cmd_runner()
            .add_gsctool_interaction(vec!["mock_image_path"], 0, "", "");
        // mock interaction for retrieve_dut_firmware_rw_version (after update)
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--fwver", "--machine"],
            0,
            "RW_FW_VER=1.2.4",
            "",
        );
        let result = update_dut_if_needed(&mut mock_ctx, Path::new("mock_image_path"));
        assert_eq!(result, Ok(()));
    }
}
