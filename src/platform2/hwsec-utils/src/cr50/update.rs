// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use log::error;
use log::info;

use crate::context::Context;
use crate::cr50::cr50_get_name;
use crate::cr50::gsctool_cmd_successful;
use crate::cr50::run_gsctool_cmd;
use crate::cr50::GSCTOOL_CMD_NAME;
use crate::error::HwsecError;

const MAX_RETRIES: u32 = 3;
const SLEEP_DURATION: u64 = 70;

// TODO (b/246863926)
pub fn cr50_update(ctx: &mut impl Context) -> Result<(), HwsecError> {
    info!("Starting");

    let options: Vec<&str>;
    // determine the best way to communicate with the Cr50.
    if gsctool_cmd_successful(ctx, vec!["--fwver", "--systemdev"]) {
        info!("Will use /dev/tpm0");
        options = vec!["--systemdev"];
    } else if gsctool_cmd_successful(ctx, vec!["--fwver", "--trunks_send"]) {
        info!("Will use trunks_send");
        options = vec!["--trunks_send"];
    } else {
        error!("Could not communicate with Cr50");
        return Err(HwsecError::GsctoolError(1));
    }

    let cr50_image = cr50_get_name(ctx, &options[..])?;

    if !ctx.path_exists(cr50_image.as_str()) {
        info!("{} not found, quitting.", cr50_image);
        return Err(HwsecError::GsctoolError(1));
    }

    let mut exit_status: i32 = 0;
    for retries in 0..MAX_RETRIES {
        if retries != 0 {
            // Need to sleep for at least a minute to get around cr50 update throttling:
            // it rejects repeat update attempts happening sooner than 60 seconds after
            // the previous one.
            ctx.sleep(SLEEP_DURATION);
        }

        let exe_result =
            run_gsctool_cmd(ctx, [&options[..], &["--upstart", &cr50_image]].concat())?;
        exit_status = exe_result.status.code().unwrap();

        // Exit status values 2 or below indicate successful update, nonzero
        // values mean that reboot is required for the new version to kick in.
        if exit_status <= 2 {
            // Callers of this script do not care about the details and consider any
            // non-zero value an error.
            info!("success ({})", exit_status);
            exit_status = 0;
            break;
        }

        info!(
            "{} (options: {:?}) attempt {} error {}",
            GSCTOOL_CMD_NAME,
            options,
            retries + 1,
            exit_status
        );

        let output = format!(
            "{}{}",
            std::str::from_utf8(&exe_result.stdout)
                .map_err(|_| HwsecError::GsctoolResponseBadFormatError)?,
            std::str::from_utf8(&exe_result.stderr)
                .map_err(|_| HwsecError::GsctoolResponseBadFormatError)?
        );

        // Log output text one line at a time, otherwise they are all concatenated
        // into a single long entry with messed up line breaks.
        for line in output.lines() {
            info!("{}", line);
        }
    }
    if exit_status == 0 {
        Ok(())
    } else {
        Err(HwsecError::GsctoolError(exit_status))
    }
}

#[cfg(test)]
mod tests {
    use crate::context::mock::MockContext;
    use crate::context::Context;
    use crate::cr50::cr50_update;
    use crate::cr50::update::MAX_RETRIES;
    use crate::cr50::GSC_IMAGE_BASE_NAME;
    use crate::error::HwsecError;

    #[test]
    fn test_cr50_update_could_not_communicate_with_cr50() {
        let mut mock_ctx = MockContext::new();
        mock_ctx
            .cmd_runner()
            .add_gsctool_interaction(vec!["--fwver", "--systemdev"], 1, "", "");
        mock_ctx
            .cmd_runner()
            .add_gsctool_interaction(vec!["--fwver", "--trunks_send"], 1, "", "");
        let result = cr50_update(&mut mock_ctx);
        assert_eq!(result, Err(HwsecError::GsctoolError(1)));
    }

    #[test]
    fn test_cr50_update_cr50_image_not_exist() {
        let mut mock_ctx = MockContext::new();
        mock_ctx
            .cmd_runner()
            .add_gsctool_interaction(vec!["--fwver", "--systemdev"], 0, "", "");
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--systemdev", "--board_id"],
            0,
            "Board ID space: 43425559:bcbdaaa6:00007f10",
            "",
        );
        let result = cr50_update(&mut mock_ctx);
        assert_eq!(result, Err(HwsecError::GsctoolError(1)));
    }

    #[test]
    fn test_cr50_update_ok() {
        let mut mock_ctx = MockContext::new();
        mock_ctx
            .cmd_runner()
            .add_gsctool_interaction(vec!["--fwver", "--systemdev"], 0, "", "");
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--systemdev", "--board_id"],
            0,
            "Board ID space: 43425559:bcbdaaa6:00007f10",
            "",
        );

        let path = String::from(GSC_IMAGE_BASE_NAME) + ".prepvt";
        mock_ctx.create_path(path.as_str());

        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--systemdev", "--upstart", path.as_str()],
            0,
            "",
            "",
        );

        let result = cr50_update(&mut mock_ctx);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_cr50_update_failed_exceed_max_retries() {
        let mut mock_ctx = MockContext::new();
        mock_ctx
            .cmd_runner()
            .add_gsctool_interaction(vec!["--fwver", "--systemdev"], 0, "", "");
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--systemdev", "--board_id"],
            0,
            "Board ID space: 43425559:bcbdaaa6:00007f10",
            "",
        );

        let path = String::from(GSC_IMAGE_BASE_NAME) + ".prepvt";
        mock_ctx.create_path(path.as_str());

        for _ in 0..MAX_RETRIES {
            mock_ctx.cmd_runner().add_gsctool_interaction(
                vec!["--systemdev", "--upstart", path.as_str()],
                3,
                "",
                "",
            );
        }

        let result = cr50_update(&mut mock_ctx);
        assert_eq!(result, Err(HwsecError::GsctoolError(3)));
    }
}
