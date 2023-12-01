// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::num::ParseIntError;

use crate::error::HwsecError;

// Reference:
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf#page=61
#[allow(non_camel_case_types)]
pub enum TpmiStCommandTag {
    TPM_ST_SESSIONS(SessionOption),
}

impl TpmiStCommandTag {
    pub fn command_code(&self) -> [u8; 2] {
        match self {
            Self::TPM_ST_SESSIONS(_) => 0x8002_u16.to_be_bytes(),
        }
    }
}

// Reference:
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf#page=47
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf#page=48
#[allow(non_camel_case_types)]
#[allow(clippy::enum_variant_names)]
pub enum CommandArg {
    TPM_CC_NV_Write(Vec<u8>),
    TPM_CC_NV_WriteLock,
    TPM_CC_NV_Read(u16),
}

impl CommandArg {
    pub fn command_code(&self) -> [u8; 4] {
        match self {
            Self::TPM_CC_NV_Write(_) => 0x00000137_u32.to_be_bytes(),
            Self::TPM_CC_NV_WriteLock => 0x00000138_u32.to_be_bytes(),
            Self::TPM_CC_NV_Read(_) => 0x0000014e_u32.to_be_bytes(),
        }
    }
}

// Reference (the url is too long to pass the clippy check, split into 3 lines):
// https://source.corp.google.com/chromeos_internal/
// src/platform/ti50/common/applications/system_test/
// src/commands.rs;rcl=c37b4a7e7d9d69bba23712318e03749b2b325d16;l=675
pub enum SessionOption {
    EmptyPassword,
}

impl SessionOption {
    pub fn command_code(&self) -> Vec<u8> {
        match self {
            Self::EmptyPassword => vec![
                0x00, 0x00, 0x00, 0x09, // auth size
                0x40, 0x00, 0x00, 0x09, // session handle: TPM_RS_PW
                0x00, 0x00, // nonce: TPM2B
                0x00, // attributes:
                0x00, 0x00, // password: TPM2B
            ],
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct BoardID {
    pub part_1: u32,
    pub part_2: u32,
    pub flag: u32,
}

pub const ERASED_BOARD_ID: BoardID = BoardID {
    part_1: 0xffffffff,
    part_2: 0xffffffff,
    flag: 0xffffffff,
};

fn hex_decode(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

pub struct TpmCmdArg {
    pub bytes: Vec<u8>,
}

impl TpmCmdArg {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
    pub fn to_hex_tokens(&self) -> Vec<String> {
        let mut tokens = Vec::<String>::new();
        for byte in &self.bytes {
            tokens.push(format!("{:02x}", byte));
        }
        tokens
    }
}
pub struct TpmCmdResponse {
    return_code: u32,
    body: Vec<u8>,
}

impl TpmCmdResponse {
    pub fn from_send_util_output(raw_response: Vec<u8>) -> Result<Self, HwsecError> {
        // raw_response is output of exactly one of the following two send_util(s):
        // 1. trunks_send
        // 2. tpmc
        // For the first tool, the output format is a hex string in this format: "ABCDEF0123456789"
        // For the second tool, the output format is a series of hex pair in this format:
        // "0x12 0x34 0x56 0x78\n0x90 0xab 0xcd 0xef"
        // In either case, the raw_response is given as a Vec<u8>
        // with each entry specifying a character.
        //
        // Though presented in different format, they share quite similar meanings.
        // This is a function which can be used for both possible format
        // for converting raw_response to a more handy Vec<u8> structure.

        // Convert Vec<u8> to &str
        let s = std::str::from_utf8(&raw_response)
            .map_err(|_| HwsecError::Tpm2ResponseBadFormatError)?;

        // Replace, for the second case, unnecessary characters to unify the format
        let s = &s.replace("0x", "").replace([' ', '\n'], "");

        // decode the string reformatted
        let decoded_response = hex_decode(s).map_err(|_| HwsecError::Tpm2ResponseBadFormatError)?;

        // Check if the response contains basic information (i.e. tag(2) + size(4) + return_code(4))
        if decoded_response.len() < 2 + 4 + 4 {
            return Err(HwsecError::Tpm2ResponseBadFormatError);
        }

        // [2..6] stands for the length of the response
        // This can be checked from
        // https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part3_Commands_pub.pdf#page=385
        let length = u32::from_be_bytes(decoded_response[2..6].try_into().unwrap());

        // Check whether some necessary conditions for being a valid raw response are satisfied
        if length != decoded_response.len() as u32 {
            return Err(HwsecError::Tpm2ResponseBadFormatError);
        }

        // [6..10] stands for the return code
        // This can be checked from
        // https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part3_Commands_pub.pdf#page=385
        Ok(Self {
            return_code: u32::from_be_bytes(decoded_response[6..10].try_into().unwrap()),
            body: decoded_response[10..].to_vec(),
        })
    }
    pub fn return_code(&self) -> u32 {
        self.return_code
    }
    pub fn success(&self) -> bool {
        self.return_code() == 0
    }
    pub fn body(&self) -> &Vec<u8> {
        &self.body
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct FactoryConfig(pub u64);

impl FactoryConfig {
    pub fn new(x_branded: bool, compliance_version: u8) -> Option<Self> {
        if compliance_version & !0xF == 0 {
            let branded = if x_branded { 1 << 4 } else { 0 };
            Some(Self((branded | compliance_version).into()))
        } else {
            None
        }
    }
    pub fn is_set(&self) -> bool {
        self.0 != 0
    }
    pub fn x_branded(&self) -> bool {
        ((self.0 >> 4) & 1) != 0
    }
    pub fn compliance_version(&self) -> u8 {
        (self.0 & 0xF) as u8
    }
}
