// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;
use std::io::Write;
use std::path::Path;

use super::get_gbb_flags;
use super::set_gbb_flags;
use crate::command_runner::CommandRunner;
use crate::context::Context;
use crate::cr50::clear_terminal;
use crate::cr50::gsctool_cmd_successful;
use crate::cr50::run_gsctool_cmd;
use crate::error::HwsecError;

// RMA Reset Authorization parameters.
// - URL of Reset Authorization Server.
const RMA_SERVER: &str = "https://www.google.com/chromeos/partner/console/cr50reset";
// - Number of retries before giving up.
const MAX_RETRIES: i32 = 3;
// - RETRY_DELAY=10
const RETRY_DELAY: i32 = 10;
const FRECON_PID_FILE: &str = "/run/frecon/pid";

fn gbb_force_dev_mode(ctx: &mut impl Context) -> Result<u32, HwsecError> {
    // Disable SW WP and set GBB_FLAG_FORCE_DEV_SWITCH_ON (0x8) to force boot in
    // developer mode after RMA reset.

    // TODO: call flashrom with library instead of commands
    ctx.cmd_runner()
        .run(
            "flashrom",
            vec!["-p", "host", "--wp-disable", "--wp-range", "0,0"],
        )
        .map_err(|_| {
            eprintln!("Failed to run flashrom");
            HwsecError::CommandRunnerError
        })?;

    let flags: u32 = get_gbb_flags(ctx)?;
    let new_flags: u32 = flags | 0x8;
    set_gbb_flags(ctx, new_flags)?;
    Ok(new_flags)
}

fn get_crossystem_hwid(ctx: &mut impl Context) -> Result<String, HwsecError> {
    // Get HWID and replace whitespace with underscore.
    Ok(ctx
        .cmd_runner()
        .output("crossystem", vec!["hwid"])
        .map_err(|_| {
            eprintln!("Failed to get hwid.");
            HwsecError::CommandRunnerError
        })?
        .replace(' ', "_"))
}

/// Retrieve the challenge to perform Cr50 reset from 'gsctool -tr', which has raw response of the
/// following format:
///
/// Challenge:
///  AEDNM 6GCYN C7Q55 5HYS7 3SECR KRQRL ERXG7 HFSNF
///  CAZDM XWTDR HAWDE 36GWE UDMKP H7TSM RRTV5 CWS75
fn get_challenge_string_from_gsctool(ctx: &mut impl Context) -> Result<String, HwsecError> {
    let gsctool_output =
        run_gsctool_cmd(ctx, vec!["--trunks_send", "--rma_auth"]).map_err(|e| {
            eprintln!("Failed to run gsctool.");
            e
        })?;

    if !gsctool_output.status.success() {
        eprintln!("{}", std::str::from_utf8(&gsctool_output.stderr).unwrap());
        return Err(HwsecError::GsctoolError(
            gsctool_output.status.code().unwrap(),
        ));
    }

    let challenge_string = std::str::from_utf8(&gsctool_output.stdout)
        .map_err(|_| {
            eprintln!("Internal error occurred.");
            HwsecError::GsctoolResponseBadFormatError
        })?
        .replace("Challenge:", "");

    // Test if we have a challenge.
    if challenge_string.is_empty() {
        return Err(HwsecError::GsctoolResponseBadFormatError);
    }

    // result may contain whitespace and newline characters
    Ok(challenge_string)
}

/// This function returns the challenge url string, and prints output similarly as follows
/// in the terminal:
///
/// Challenge:
///
///  AEDNM 6GCYN C7Q55 5HYS7 3SECR KRQRL ERXG7 HFSNF
///  CAZDM XWTDR HAWDE 36GWE UDMKP H7TSM RRTV5 CWS75
///
/// URL: https://www.google.com/chromeos/partner/console/cr50reset?\
/// challenge=AEDNM6GCYNC7Q555HYS73SECRKRQRLERXG7HFSNFCAZDMXWTDRHAWDE36GWEUDMKPH7TSMRRTV5CWS75\
/// &hwid=VOLET_TEST_5042
fn generate_challenge_url_and_display_challenge(
    ctx: &mut impl Context,
) -> Result<String, HwsecError> {
    // Get HWID and replace whitespace with underscore.
    let hwid = get_crossystem_hwid(ctx)?;
    // Get challenge string and remove "Challenge:".
    let challenge_string = get_challenge_string_from_gsctool(ctx).map_err(|_| {
        eprintln!("Challenge wasn't generated. CR50 might need updating.");
        HwsecError::InternalError
    })?;

    // Preserve enough space to prevent terminal scrolling.
    clear_terminal();

    // Display the challenge.
    println!("Challenge:");
    println!("{}", challenge_string);

    // Remove whitespace and newline from challenge.
    let challenge_string = challenge_string.replace(['\n', ' '], "");

    // Calculate challenge URL and display it.
    let challenge_url = format!(
        "{}?challenge={}&hwid={}",
        RMA_SERVER, challenge_string, hwid
    );
    println!("URL: {}", challenge_url);
    Ok(challenge_url)
}

pub fn cr50_reset(ctx: &mut impl Context) -> Result<(), HwsecError> {
    const WAIT_TO_ENTER_RMA_SECS: u64 = 2;
    const SECS_IN_A_DAY: u64 = 86400;

    // Make sure frecon is running.
    let frecon_pid = ctx.read_file_to_string(FRECON_PID_FILE)?;

    // This is the path to the pre-chroot filesystem. Since frecon is started
    // before the chroot, all files that frecon accesses must be copied to
    // this path.
    let chg_str_path = format!("/proc/{}/root", frecon_pid);

    if !Path::new(&chg_str_path).exists() {
        eprintln!("frecon not running. Can't display qrcode.");
        return Err(HwsecError::FileError);
    }
    let challenge_url = generate_challenge_url_and_display_challenge(ctx)?;

    // Create qrcode and display it.
    // TODO: replace qrencode command with qrcode library like this
    //
    // let qrcode = QrCode::new(challenge_string).unwrap();
    // let image = qrcode.render::<Luma<u8>>().build();
    // image.save(format!("{chg_str_path}/chg.png")).unwrap();
    ctx.cmd_runner()
        .run(
            "qrencode",
            vec![
                "-s",
                "5",
                "-o",
                &format!("{}/chg.png", chg_str_path),
                &challenge_url,
            ],
        )
        .map_err(|_| {
            eprintln!("Failed to qrencode.");
            HwsecError::QrencodeError
        })?;
    ctx.write_contents_to_file("/run/frecon/vt0", b"\x1b]image:file=/chg.png\x1b\\")?;
    for _ in 0..MAX_RETRIES {
        // Read authorization code. Show input in uppercase letters.
        print!("\nEnter authorization code: ");
        // Flush stdout buffer. Here we ignore possible i/o error.
        io::stdout().flush().ok();
        let mut auth_code = String::new();
        while io::stdin().read_line(&mut auth_code).is_err() {
            println!("Please only enter ASCII characters.");
        }
        let auth_code = auth_code.to_uppercase();

        // Test authorization code.
        if gsctool_cmd_successful(ctx, vec!["--trunks_send", "--rma_auth", &auth_code]) {
            println!("The system will reboot shortly.");
            // Wait for cr50 to enter RMA mode.
            ctx.sleep(WAIT_TO_ENTER_RMA_SECS);

            // Force the next boot to be in developer mode so that we can boot to
            // RMA shim again.
            gbb_force_dev_mode(ctx).map_err(|e| {
                eprintln!("gbb_force_dev_mode failed.");
                e
            })?;

            // TODO: reboot with function call instead
            ctx.cmd_runner()
                .run("reboot", Vec::<&str>::new())
                .map_err(|_| {
                    eprintln!("Failed to reboot.");
                    HwsecError::SystemRebootError
                })?;

            // Sleep indefinitely to avoid continue.
            ctx.sleep(SECS_IN_A_DAY);
        }

        println!("Invalid authorization code. Please try again.\n");
    }

    println!("Number of retries exceeded. Another qrcode will generate in 10s.");

    for _ in 0..RETRY_DELAY {
        print!(".");
        // Flush stdout buffer. Here we ignore possible i/o error.
        io::stdout().flush().ok();
        ctx.sleep(1);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;

    use super::generate_challenge_url_and_display_challenge;
    use super::get_challenge_string_from_gsctool;
    use super::get_crossystem_hwid;
    use crate::command_runner::MockCommandInput;
    use crate::command_runner::MockCommandOutput;
    use crate::context::mock::MockContext;
    use crate::context::Context;
    use crate::cr50::reset::gbb_force_dev_mode;
    use crate::error::HwsecError;

    #[test]
    fn test_gbb_force_dev_mode_successful() {
        const NUM_TEST_CASES: u32 = 100;

        let mut mock_ctx = MockContext::new();
        for _ in 0..NUM_TEST_CASES {
            let old_flag = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .subsec_nanos();
            mock_ctx.cmd_runner().add_expectation(
                MockCommandInput::new(
                    "flashrom",
                    vec!["-p", "host", "--wp-disable", "--wp-range", "0,0"],
                ),
                MockCommandOutput::new(0, "", ""),
            );
            mock_ctx
                .cmd_runner()
                .add_successful_get_gbb_flags_interaction(old_flag);
            mock_ctx
                .cmd_runner()
                .add_successful_set_gbb_flags_interaction(old_flag | 0x8);

            let new_flag = gbb_force_dev_mode(&mut mock_ctx);
            assert_eq!(new_flag, Ok(old_flag | 0x8));
        }
    }
    #[test]
    fn test_gbb_force_dev_mode_failed_to_get_flag() {
        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_expectation(
            MockCommandInput::new(
                "flashrom",
                vec!["-p", "host", "--wp-disable", "--wp-range", "0,0"],
            ),
            MockCommandOutput::new(0, "", ""),
        );
        mock_ctx.cmd_runner().add_expectation(
            MockCommandInput::new("futility", vec!["gbb", "--get", "--flash", "--flags"]),
            MockCommandOutput::new(0, "Oops... no flag ><", ""),
        );

        let new_flag = gbb_force_dev_mode(&mut mock_ctx);
        assert_eq!(new_flag, Err(HwsecError::VbootScriptResponseBadFormatError));
    }

    #[test]
    fn test_get_crossystem_hwid() {
        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_expectation(
            MockCommandInput::new("crossystem", vec!["hwid"]),
            MockCommandOutput::new(0, "VOLET TEST 5042", ""),
        );
        let result = get_crossystem_hwid(&mut mock_ctx);
        assert_eq!(result, Ok(String::from("VOLET_TEST_5042")));
    }

    #[test]
    fn test_get_challenge_string_from_gsctool_ok() {
        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--trunks_send", "--rma_auth"],
            0,
            "Challenge:\nMOCK CHALLENGE\n",
            "",
        );
        let result = get_challenge_string_from_gsctool(&mut mock_ctx);
        assert_eq!(result, Ok(String::from("\nMOCK CHALLENGE\n")));
    }

    #[test]
    fn test_get_challenge_string_from_gsctool_failed_attempt() {
        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--trunks_send", "--rma_auth"],
            3,
            "",
            "error 4",
        );
        let result = get_challenge_string_from_gsctool(&mut mock_ctx);
        assert_eq!(result, Err(HwsecError::GsctoolError(3)));
    }
    #[test]
    fn test_get_challenge_string_from_gsctool_empty_challenge() {
        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--trunks_send", "--rma_auth"],
            0,
            "Challenge:",
            "",
        );
        let result = get_challenge_string_from_gsctool(&mut mock_ctx);
        assert_eq!(result, Err(HwsecError::GsctoolResponseBadFormatError));
    }

    // The follow test input/expected output is from a real result generated by running
    // cr50-reset.sh on DUT
    //
    // Challenge:
    //
    //  AEDNM 6GCYN C7Q55 5HYS7 3SECR KRQRL ERXG7 HFSNF
    //  CAZDM XWTDR HAWDE 36GWE UDMKP H7TSM RRTV5 CWS75
    //
    // URL: https://www.google.com/chromeos/partner/console/cr50reset?\
    // challenge=AEDNM6GCYNC7Q555HYS73SECRKRQRLERXG7HFSNFCAZDMXWTDRHAWDE36GWEUDMKPH7TSMRRTV5CWS75\
    // &hwid=VOLET_TEST_5042
    //
    // Enter authorization code:
    #[test]
    fn test_generate_challenge_url_and_display_challenge_ok() {
        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_expectation(
            MockCommandInput::new("crossystem", vec!["hwid"]),
            MockCommandOutput::new(0, "VOLET TEST 5042", ""),
        );
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--trunks_send", "--rma_auth"],
            0,
            include_str!(
                "../command_runner/expected_message/successfully_gsctool_rma_auth_response.txt"
            ),
            "",
        );
        let result = generate_challenge_url_and_display_challenge(&mut mock_ctx);
        let expected_url = "https://www.google.com/chromeos/partner/console/cr50reset?challenge=\
        AEDNM6GCYNC7Q555HYS73SECRKRQRLERXG7HFSNFCAZDMXWTDRHAWDE36GWEUDMKPH7TSMRRTV5CWS75&\
        hwid=VOLET_TEST_5042";
        assert_eq!(result, Ok(String::from(expected_url)));
    }

    #[test]
    fn test_generate_challenge_url_and_display_challenge_fail_challenge_not_generated() {
        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_expectation(
            MockCommandInput::new("crossystem", vec!["hwid"]),
            MockCommandOutput::new(0, "MOCK HWID", ""),
        );
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--trunks_send", "--rma_auth"],
            3,
            "",
            "error 4",
        );
        let result = generate_challenge_url_and_display_challenge(&mut mock_ctx);
        assert_eq!(result, Err(HwsecError::InternalError));
    }
}
