// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt;
use std::fmt::Display;

#[derive(Debug, PartialEq, Eq)]
pub enum HwsecError {
    InvalidArgumentError,
    Tpm2Error(u32),
    Tpm2ResponseBadFormatError,
    GsctoolError(i32),
    GsctoolResponseBadFormatError,
    VbootScriptResponseBadFormatError,
    MetricsClientFailureError,
    QrencodeError,
    CommandRunnerError,
    SyslogError,
    FileError,
    GbbFlagOperationError,
    SystemRebootError,
    SystemTimeError,
    InternalError,
}

impl Display for HwsecError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HwsecError::InvalidArgumentError => write!(f, "InvalidArgumentError"),
            HwsecError::Tpm2Error(err_code) => write!(f, "Tpm2Error - Error code: {}", err_code),
            HwsecError::Tpm2ResponseBadFormatError => write!(f, "Tpm2ResponseBadFormatError"),
            HwsecError::GsctoolError(err_code) => {
                write!(f, "GsctoolError - Error code : {}", err_code)
            }
            HwsecError::GsctoolResponseBadFormatError => write!(f, "GsctoolResponseBadFormatError"),
            HwsecError::VbootScriptResponseBadFormatError => {
                write!(f, "VbootScriptResponseBadFormatError")
            }
            HwsecError::MetricsClientFailureError => write!(f, "MetricsClientFailureError"),
            HwsecError::QrencodeError => write!(f, "QrencodeError"),
            HwsecError::CommandRunnerError => write!(f, "CommandRunnerError"),
            HwsecError::SyslogError => write!(f, "SyslogError"),
            HwsecError::FileError => write!(f, "FileError"),
            HwsecError::GbbFlagOperationError => write!(f, "GbbFlagOperationError"),
            HwsecError::SystemTimeError => write!(f, "SystemTimeError"),
            HwsecError::SystemRebootError => write!(f, "SystemRebootError"),
            HwsecError::InternalError => write!(f, "InternalError"),
        }
    }
}
