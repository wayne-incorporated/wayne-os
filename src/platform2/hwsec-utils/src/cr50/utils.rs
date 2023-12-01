// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt::Write;

use regex::Regex;

use super::Version;
use super::GSCTOOL_CMD_NAME;
use crate::command_runner::CommandRunner;
use crate::context::Context;
use crate::error::HwsecError;
use crate::output::HwsecOutput;
use crate::tpm2::BoardID;
use crate::tpm2::FactoryConfig;

/// Convert string version representation <epoch>.<major>.<minor> into Version struct.
pub fn parse_version(version_string: &str) -> Option<Version> {
    let mut parts = version_string.split('.');
    if parts.clone().count() != 3 {
        return None;
    }
    let epoch = parts.next().unwrap().parse::<u8>().ok()?;
    let major = parts.next().unwrap().parse::<u8>().ok()?;
    let minor = parts.next().unwrap().parse::<u8>().ok()?;

    Some(Version {
        epoch,
        major,
        minor,
    })
}

/// 'gsctool -M [options]' output has format
///
/// ...
/// <INDEX1>=<VALUE1>\n
/// <INDEX2>=<VALUE2>\n
/// ...
///
/// This function finds the line that starts with the given index, and outputs its value.
pub fn get_value_from_gsctool_output<'a>(
    gsctool_output: &'a str,
    index: &'a str,
) -> Result<&'a str, HwsecError> {
    let prefix = index.to_owned() + "=";
    let Some(line) = gsctool_output
    .lines()
    .find(|line| line.starts_with(&prefix)) else {
        eprintln!("Cannot find a line starts with {}", index);
        return Err(HwsecError::InternalError);
    };
    match line.split('=').nth(1) {
        Some(value) => Ok(value),
        None => {
            eprintln!("Failed when retrieving value after '='");
            Err(HwsecError::InternalError)
        }
    }
}

pub fn run_gsctool_cmd(
    ctx: &mut impl Context,
    mut options: Vec<&str>,
) -> Result<HwsecOutput, HwsecError> {
    if cfg!(feature = "ti50_onboard") {
        options.push("--dauntless");
    }

    ctx.cmd_runner()
        .run(GSCTOOL_CMD_NAME, options)
        .map_err(|_| HwsecError::CommandRunnerError)
}

pub fn run_metrics_client(
    ctx: &mut impl Context,
    options: Vec<&str>,
) -> Result<HwsecOutput, HwsecError> {
    ctx.cmd_runner()
        .run("metrics_client", options)
        .map_err(|_| HwsecError::CommandRunnerError)
}

pub fn gsctool_cmd_successful(ctx: &mut impl Context, options: Vec<&str>) -> bool {
    let output = run_gsctool_cmd(ctx, options);
    output.is_ok() && output.unwrap().status.success()
}

pub fn u8_slice_to_hex_string(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

/// This function finds the first occurrence of a board id representation
/// after the occurrence of the substring "Board ID".
///
/// If raw_response does not contain substring "Board ID"
/// or there is no board id occurring after the position of that of substring "Board ID",
/// this function returns Err(HwsecError::GsctoolResponseBadFormatError).
pub fn extract_board_id_from_gsctool_response(raw_response: &str) -> Result<BoardID, HwsecError> {
    let re: regex::Regex = Regex::new(r"[0-9a-fA-F]{8}:[0-9a-fA-F]{8}:[0-9a-fA-F]{8}").unwrap();
    if let Some(board_id_keyword_pos) = raw_response.find("Board ID") {
        let board_id_str = re
            .find(&raw_response[board_id_keyword_pos..])
            .ok_or(HwsecError::GsctoolResponseBadFormatError)?
            .as_str();
        Ok(BoardID {
            part_1: u32::from_str_radix(&board_id_str[0..8], 16)
                .map_err(|_| HwsecError::InternalError)?,
            part_2: u32::from_str_radix(&board_id_str[9..17], 16)
                .map_err(|_| HwsecError::InternalError)?,
            flag: u32::from_str_radix(&board_id_str[18..26], 16)
                .map_err(|_| HwsecError::InternalError)?,
        })
    } else {
        Err(HwsecError::GsctoolResponseBadFormatError)
    }
}

pub fn get_board_id_with_gsctool(ctx: &mut impl Context) -> Result<BoardID, HwsecError> {
    let gsctool_raw_response = run_gsctool_cmd(ctx, vec!["--any", "--board_id"])?;
    let board_id_output = std::str::from_utf8(&gsctool_raw_response.stdout)
        .map_err(|_| HwsecError::GsctoolResponseBadFormatError)?;
    extract_board_id_from_gsctool_response(board_id_output)
}

pub fn clear_terminal() {
    print!("{esc}[2J{esc}[1;1H", esc = 27 as char);
}

pub fn get_gbb_flags(ctx: &mut impl Context) -> Result<u32, HwsecError> {
    let raw_response = ctx
        .cmd_runner()
        .output("futility", vec!["gbb", "--get", "--flash", "--flags"])
        .map_err(|_| HwsecError::CommandRunnerError)?;
    let re: regex::Regex = Regex::new(r"0x[0-9a-fA-F]{8}").unwrap();
    if let Some(keyword_pos) = raw_response.find("flags:") {
        let key_str = re
            .find(&raw_response[keyword_pos..])
            .ok_or(HwsecError::VbootScriptResponseBadFormatError)?
            .as_str();
        Ok(u32::from_str_radix(&key_str[2..], 16)
            .map_err(|_| HwsecError::VbootScriptResponseBadFormatError)?)
    } else {
        Err(HwsecError::VbootScriptResponseBadFormatError)
    }
}

pub fn set_gbb_flags(ctx: &mut impl Context, new_flags: u32) -> Result<(), HwsecError> {
    ctx.cmd_runner()
        .run(
            "futility",
            vec![
                "gbb",
                "--set",
                "--flash",
                &format!("--flags=0x{:08x}", new_flags),
            ],
        )
        .map_err(|_| HwsecError::CommandRunnerError)
        .map(|_| ())
}

pub fn extract_factory_config_from_gsctool_response(
    raw_response: &str,
) -> Result<FactoryConfig, HwsecError> {
    let re: regex::Regex = Regex::new(r"[0-9a-fA-F]{16}").unwrap();
    if let Some(factory_config_keyword_pos) = raw_response.find("raw value:") {
        let factory_config_str = re
            .find(&raw_response[factory_config_keyword_pos..])
            .ok_or(HwsecError::GsctoolResponseBadFormatError)?
            .as_str();
        let raw = u64::from_str_radix(&factory_config_str[0..16], 16)
            .map_err(|_| HwsecError::InternalError)?;
        Ok(FactoryConfig(raw))
    } else {
        Err(HwsecError::GsctoolResponseBadFormatError)
    }
}

pub fn get_factory_config_with_gsctool(
    ctx: &mut impl Context,
) -> Result<FactoryConfig, HwsecError> {
    let gsctool_raw_response = run_gsctool_cmd(ctx, vec!["-a", "--factory_config"])?;
    let factory_config_output = std::str::from_utf8(&gsctool_raw_response.stdout)
        .map_err(|_| HwsecError::GsctoolResponseBadFormatError)?;
    extract_factory_config_from_gsctool_response(factory_config_output)
}

#[cfg(test)]
mod tests {
    use super::get_value_from_gsctool_output;
    use super::parse_version;
    use crate::cr50::Version;
    use crate::error::HwsecError;

    #[test]
    fn test_parse_version_ok() {
        let result = parse_version("1.2.3");
        assert_eq!(
            result,
            Some(Version {
                epoch: 1,
                major: 2,
                minor: 3,
            })
        );
    }

    #[test]
    fn test_parse_version_fail_1() {
        let result = parse_version("a.b.c");
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_version_fail_2() {
        let result = parse_version("1.23");
        assert_eq!(result, None);
    }

    #[test]
    fn test_get_value_from_gsctool_output_ok() {
        let result = get_value_from_gsctool_output("INDEX=VALUE", "INDEX");
        assert_eq!(result, Ok("VALUE"));
    }

    #[test]
    fn test_get_value_from_gsctool_output_ok_multiple_lines() {
        let result = get_value_from_gsctool_output("INDEX1=VALUE1\nINDEX2=VALUE2", "INDEX2");
        assert_eq!(result, Ok("VALUE2"));
    }

    #[test]
    fn test_get_value_from_gsctool_output_empty_value() {
        let result = get_value_from_gsctool_output("INDEX=", "INDEX");
        assert_eq!(result, Ok(""));
    }

    #[test]
    fn test_get_value_from_gsctool_output_fail_index_not_found() {
        let result = get_value_from_gsctool_output("ABC=", "INDEX");
        assert_eq!(result, Err(HwsecError::InternalError));
    }
}
