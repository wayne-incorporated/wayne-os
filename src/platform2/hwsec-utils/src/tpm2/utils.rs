// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::CommandArg;
use super::TpmCmdArg;
use super::TpmCmdResponse;
use super::TpmiStCommandTag;
use crate::command_runner::CommandRunner;
use crate::context::Context;
use crate::error::HwsecError;

// Check the field description here.
// Reference: https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part3_Commands_pub.pdf#page=406
pub fn gen_tpm_cmd(
    tag: TpmiStCommandTag,
    cmd_arg: CommandArg,
    index: u32,
) -> Result<Vec<u8>, HwsecError> {
    let mut ret = Vec::<u8>::new();
    ret.extend_from_slice(&tag.command_code());
    ret.extend_from_slice(&0x00000000_u32.to_be_bytes()); // size: will be overwritten later
    ret.extend_from_slice(&cmd_arg.command_code());
    ret.extend_from_slice(&index.to_be_bytes());
    ret.extend_from_slice(&index.to_be_bytes());
    let TpmiStCommandTag::TPM_ST_SESSIONS(session_option) = tag;
    ret.extend_from_slice(&session_option.command_code());
    match cmd_arg {
        CommandArg::TPM_CC_NV_Write(data) => {
            if data.len() > u16::MAX as usize {
                return Err(HwsecError::InvalidArgumentError);
            }
            ret.extend_from_slice(&(data.len() as u16).to_be_bytes());
            ret.extend_from_slice(&data);
            // offset, which is always 0x0000 in this scenario
            ret.extend_from_slice(&0x0000_u16.to_be_bytes());
        }
        CommandArg::TPM_CC_NV_WriteLock => {
            // empty cmd_param
        }
        CommandArg::TPM_CC_NV_Read(data_len) => {
            ret.extend_from_slice(&data_len.to_be_bytes());
            // offset, which is always 0x0000 in this scenario
            ret.extend_from_slice(&0x0000_u16.to_be_bytes());
        }
    };

    let cmd_size = (ret.len() as u32).to_be_bytes();
    ret[2..6].clone_from_slice(&cmd_size);
    Ok(ret)
}

fn trunksd_is_running(ctx: &mut impl Context) -> bool {
    if let Ok(o) = ctx.cmd_runner().run("status", vec!["trunksd"]) {
        std::str::from_utf8(&o.stdout)
            .unwrap_or("stopped")
            .contains("running")
    } else {
        false
    }
}

pub fn run_tpm_cmd(ctx: &mut impl Context, tpm_cmd: Vec<u8>) -> Result<TpmCmdResponse, HwsecError> {
    let trunksd_on: bool = trunksd_is_running(ctx);

    let send_util = if trunksd_on { "trunks_send" } else { "tpmc" };

    let flag: Vec<&str> = if trunksd_on {
        vec!["--raw"]
    } else {
        vec!["raw"]
    };

    let arg = TpmCmdArg::new(tpm_cmd);

    let output = ctx
        .cmd_runner()
        .run(
            send_util,
            [
                &flag[..],
                &arg.to_hex_tokens()
                    .iter()
                    .map(AsRef::as_ref)
                    .collect::<Vec<&str>>()[..],
            ]
            .concat(),
        )
        .map_err(|_| HwsecError::CommandRunnerError)?;
    if output.status.success() {
        Ok(TpmCmdResponse::from_send_util_output(output.stdout)?)
    } else {
        Err(HwsecError::CommandRunnerError)
    }
}

#[cfg(test)]
pub mod tests {
    pub fn split_into_hex_strtok(hex_code: &str) -> Vec<&str> {
        // e.g. "12 34 56 78" -> ["12", "34", "56", "78"]
        hex_code.split(' ').collect::<Vec<&str>>()
    }
}
