// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::str::SplitAsciiWhitespace;
use std::time::SystemTime;

use log::error;
use log::info;

use crate::context::Context;
use crate::cr50::run_gsctool_cmd;
use crate::cr50::run_metrics_client;
use crate::cr50::GSC_METRICS_PREFIX;
use crate::error::HwsecError;

const FE_LOG_NVMEM: u64 = 5;
const NVMEM_MALLOC: u64 = 200;

pub fn read_prev_timestamp_from_file(
    ctx: &mut impl Context,
    file_path: &str,
) -> Result<u64, HwsecError> {
    if !ctx.path_exists(file_path) {
        info!("{} not found, creating.", file_path);
        match ctx.write_contents_to_file(file_path, b"0") {
            Ok(_) => return Ok(0),
            Err(_) => return Err(HwsecError::FileError),
        }
    }

    let file_string = ctx.read_file_to_string(file_path)?;

    file_string
        .parse::<u64>()
        .map_err(|_| HwsecError::InternalError)
}

pub fn update_timestamp_file(
    ctx: &mut impl Context,
    new_stamp: u64,
    file_path: &str,
) -> Result<(), HwsecError> {
    ctx.write_contents_to_file(file_path, &new_stamp.to_ne_bytes())
}

pub fn set_cr50_log_file_time_base(ctx: &mut impl Context) -> Result<(), HwsecError> {
    let epoch_secs = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(epoch) => epoch.as_secs(),
        Err(_) => return Err(HwsecError::SystemTimeError),
    };

    let gsctool_result = run_gsctool_cmd(ctx, vec!["--any", "--tstamp", &epoch_secs.to_string()])?;
    if !gsctool_result.status.success() {
        error!("Failed to set Cr50 flash log time base to {}", epoch_secs);
        return Err(HwsecError::GsctoolError(
            gsctool_result.status.code().unwrap(),
        ));
    }
    info!("Set Cr50 flash log base time to {}", epoch_secs);
    Ok(())
}

fn get_next_u64_from_iterator(iter: &mut SplitAsciiWhitespace) -> Result<u64, HwsecError> {
    match iter.next() {
        None => {
            error!("Failed to parse gsctool log line");
            Err(HwsecError::InternalError)
        }
        Some(str) => str.parse::<u64>().map_err(|_| {
            error!("Failed to parse gsctool log line");
            HwsecError::InternalError
        }),
    }
}

// The output from "gsctool -a -M -L 0" may look as follows:
//         1:00
// 1623743076:09 00
// 1623743077:09 02
// 1623743085:09 00
// 1623743086:09 01
// 1666170902:09 00
// 1666170905:09 02
fn parse_timestamp_and_event_id_from_log_entry(line: &str) -> Result<(u64, u64), HwsecError> {
    let binding = line.trim().replace(':', " ");
    let mut parts = binding.split_ascii_whitespace();
    let stamp: u64 = get_next_u64_from_iterator(&mut parts)?;
    let mut event_id: u64 = get_next_u64_from_iterator(&mut parts)?;

    if event_id == FE_LOG_NVMEM {
        // If event_id is 05, which is FE_LOG_NVMEM, then adopt '200 + the first
        // byte of payload' as an new event_id, as defined as enum Cr50FlashLogs in
        // https://chromium.googlesource.com/chromium/src/+//main:tools/metrics/
        // histograms/enums.xml.

        // For example, event_id=05, payload[0]=00, then new event id is 200, which
        // is labeled as 'Nvmem Malloc'.
        let payload_0: u64 = get_next_u64_from_iterator(&mut parts)?;
        event_id = NVMEM_MALLOC + payload_0;
    }
    Ok((stamp, event_id))
}

pub fn cr50_flash_log(ctx: &mut impl Context, prev_stamp: u64) -> Result<u64, (HwsecError, u64)> {
    let Ok(gsctool_result) = run_gsctool_cmd(
        ctx,
        vec!["--any", "--machine", "--flog", &prev_stamp.to_string()]
    ) else {
        return Err((HwsecError::GsctoolError(1), 0))
    };

    if !gsctool_result.status.success() {
        error!("Failed to get flash log entries");
        return Err((
            HwsecError::GsctoolError(gsctool_result.status.code().unwrap()),
            0,
        ));
    }

    let Ok(content) = std::str::from_utf8(&gsctool_result.stdout) else {
        return Err((HwsecError::GsctoolResponseBadFormatError, 0))
    };

    let mut new_stamp: u64 = 0;
    for entry in content.lines() {
        let Ok((stamp, event_id)) = parse_timestamp_and_event_id_from_log_entry(entry) else {
            return Err((HwsecError::InternalError, new_stamp))
        };

        let Ok(metrics_client_result) = run_metrics_client(
            ctx,
            vec![
                "-s",
                &format!("{}.FlashLog", GSC_METRICS_PREFIX),
                &format!("0x{:02x}", event_id),
            ],
        ) else {
            return Err((HwsecError::MetricsClientFailureError, new_stamp))
        };

        if metrics_client_result.status.code().unwrap() == 0 {
            new_stamp = stamp;
        } else {
            error!(
                "Failed to log event {} at timestamp {}",
                event_id, new_stamp
            );
            return Err((HwsecError::InternalError, new_stamp));
        }
    }
    Ok(new_stamp)
}

#[cfg(test)]
mod tests {
    use super::parse_timestamp_and_event_id_from_log_entry;
    use crate::context::mock::MockContext;
    use crate::context::Context;
    use crate::cr50::cr50_flash_log;
    use crate::error::HwsecError;

    const PREV_STAMP: u64 = 0;

    #[test]
    fn test_parse_timestamp_and_event_id_from_log_entry_ok() {
        let line: &str = &format!("{:>10}:00", 1);
        let result = parse_timestamp_and_event_id_from_log_entry(line);
        assert_eq!(result, Ok((1, 0)));
    }

    #[test]
    fn test_parse_timestamp_and_event_id_from_log_entry_event_id_is_fe_log_nvmem() {
        use super::FE_LOG_NVMEM;
        use super::NVMEM_MALLOC;

        let line: &str = &format!("{:>10}:{:02x} 00", 1, FE_LOG_NVMEM);
        let result = parse_timestamp_and_event_id_from_log_entry(line);
        assert_eq!(result, Ok((1, NVMEM_MALLOC)));
    }

    #[test]
    fn test_parse_timestamp_and_event_id_from_log_entry_not_integer() {
        let line: &str = "TEST";
        let result = parse_timestamp_and_event_id_from_log_entry(line);
        assert_eq!(result, Err(HwsecError::InternalError));
    }

    #[test]
    fn test_parse_timestamp_and_event_id_from_log_entry_missing_event_id() {
        let line: &str = &format!("{:>10}", 1);
        let result = parse_timestamp_and_event_id_from_log_entry(line);
        assert_eq!(result, Err(HwsecError::InternalError));
    }

    #[test]
    fn test_parse_timestamp_and_event_id_from_log_entry_missing_payload_0() {
        use super::FE_LOG_NVMEM;

        let line: &str = &format!("{:>10}:{:02x}", 1, FE_LOG_NVMEM);
        let result = parse_timestamp_and_event_id_from_log_entry(line);
        assert_eq!(result, Err(HwsecError::InternalError));
    }

    #[test]
    fn test_cr50_flash_log_empty_flash_log() {
        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--any", "--machine", "--flog", "0"],
            0,
            "",
            "",
        );

        let result = cr50_flash_log(&mut mock_ctx, PREV_STAMP);
        assert_eq!(result, Ok(0));
    }

    #[test]
    fn test_cr50_flash_log_multiple_lines_flash_log() {
        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--any", "--machine", "--flog", "0"],
            0,
            &format!("{:>10}:00\n{:>10}:09 02\n{:>10}:09 02", 1, 2, 3),
            "",
        );

        mock_ctx.cmd_runner().add_metrics_client_expectation(0);
        for _ in 0..2 {
            mock_ctx.cmd_runner().add_metrics_client_expectation(9);
        }

        let result = cr50_flash_log(&mut mock_ctx, PREV_STAMP);
        assert_eq!(result, Ok(3));
    }

    #[test]
    fn test_cr50_flash_log_event_gsctool_error() {
        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--any", "--machine", "--flog", "0"],
            1,
            "",
            "",
        );

        let result = cr50_flash_log(&mut mock_ctx, PREV_STAMP);
        assert_eq!(result, Err((HwsecError::GsctoolError(1), 0)));
    }

    #[test]
    fn test_read_prev_timestamp_from_file_ok() {
        use super::read_prev_timestamp_from_file;
        let mut mock_ctx = MockContext::new();
        mock_ctx.create_path("mock_file_path");
        assert_eq!(
            mock_ctx.write_contents_to_file("mock_file_path", b"1"),
            Ok(())
        );
        let result = read_prev_timestamp_from_file(&mut mock_ctx, "mock_file_path");
        assert_eq!(result, Ok(1));
    }

    #[test]
    fn test_read_prev_timestamp_from_file_not_exist() {
        use super::read_prev_timestamp_from_file;
        let mut mock_ctx = MockContext::new();
        let result = read_prev_timestamp_from_file(&mut mock_ctx, "mock_file_path");
        assert_eq!(result, Ok(0));
    }

    #[test]
    fn test_read_prev_timestamp_from_file_multiple_lines() {
        use super::read_prev_timestamp_from_file;
        let mut mock_ctx = MockContext::new();
        mock_ctx.create_path("mock_file_path");
        assert_eq!(
            mock_ctx.write_contents_to_file("mock_file_path", b"1\n2"),
            Ok(())
        );
        let result = read_prev_timestamp_from_file(&mut mock_ctx, "mock_file_path");
        assert_eq!(result, Err(HwsecError::InternalError));
    }
    #[test]
    fn test_read_prev_timestamp_from_file_not_u64() {
        use super::read_prev_timestamp_from_file;
        let mut mock_ctx = MockContext::new();
        mock_ctx.create_path("mock_file_path");
        assert_eq!(
            mock_ctx.write_contents_to_file("mock_file_path", b"test"),
            Ok(())
        );
        let result = read_prev_timestamp_from_file(&mut mock_ctx, "mock_file_path");
        assert_eq!(result, Err(HwsecError::InternalError));
    }
}
