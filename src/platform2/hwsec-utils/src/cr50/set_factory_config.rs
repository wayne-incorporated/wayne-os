// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt;
use std::fmt::Display;

use log::error;

use super::extract_factory_config_from_gsctool_response;
use super::run_gsctool_cmd;
use crate::context::Context;
use crate::tpm2::FactoryConfig;

#[derive(Debug, PartialEq, Eq)]
pub enum Cr50SetFactoryConfigVerdict {
    GeneralError = 1,
    AlreadySetError = 2,
    AlreadySetDifferentlyError = 3,
}

impl Display for Cr50SetFactoryConfigVerdict {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Cr50SetFactoryConfigVerdict::GeneralError => write!(f, "GeneralError"),
            Cr50SetFactoryConfigVerdict::AlreadySetError => write!(f, "AlreadySetError"),
            Cr50SetFactoryConfigVerdict::AlreadySetDifferentlyError => {
                write!(f, "AlreadySetDifferentlyError")
            }
        }
    }
}

impl From<Cr50SetFactoryConfigVerdict> for i32 {
    fn from(verdict: Cr50SetFactoryConfigVerdict) -> Self {
        match verdict {
            Cr50SetFactoryConfigVerdict::GeneralError => 1,
            Cr50SetFactoryConfigVerdict::AlreadySetError => 2,
            Cr50SetFactoryConfigVerdict::AlreadySetDifferentlyError => 3,
        }
    }
}

pub fn cr50_check_factory_config(
    ctx: &mut impl Context,
    cfg: FactoryConfig,
) -> Result<(), Cr50SetFactoryConfigVerdict> {
    let factory_config_output = {
        let gsctool_raw_response =
            run_gsctool_cmd(ctx, vec!["-a", "--factory_config"]).map_err(|_| {
                error!("Failed to run gsctool.");
                Cr50SetFactoryConfigVerdict::GeneralError
            })?;
        let factory_config_output = std::str::from_utf8(&gsctool_raw_response.stdout)
            .map_err(|_| Cr50SetFactoryConfigVerdict::GeneralError)?;
        extract_factory_config_from_gsctool_response(factory_config_output)
    };
    let factory_config = factory_config_output.map_err(|e| {
        error!(
            "Failed to execute gsctool or failed to read factory config - {}",
            e
        );
        Cr50SetFactoryConfigVerdict::GeneralError
    })?;

    if factory_config.is_set() {
        if cfg == factory_config {
            Err(Cr50SetFactoryConfigVerdict::AlreadySetError)
        } else {
            Err(Cr50SetFactoryConfigVerdict::AlreadySetDifferentlyError)
        }
    } else {
        Ok(())
    }
}

pub fn cr50_set_factory_config(
    ctx: &mut impl Context,
    x_branded: bool,
    compliance_version: u8,
) -> Result<(), Cr50SetFactoryConfigVerdict> {
    let cfg = FactoryConfig::new(x_branded, compliance_version)
        .ok_or(Cr50SetFactoryConfigVerdict::GeneralError)?;
    cr50_check_factory_config(ctx, cfg)?;
    let val = format!("{:x}", cfg.0);
    run_gsctool_cmd(ctx, vec!["-a", "--factory_config", &val]).map_err(|_| {
        error!("Failed to run gsctool.");
        Cr50SetFactoryConfigVerdict::GeneralError
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::mock::MockContext;
    use crate::context::Context;
    use crate::cr50::Cr50SetFactoryConfigVerdict;

    #[test]
    fn test_cr50_check_factory_config_unset() {
        let cfg = FactoryConfig::new(false, 0).unwrap();
        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["-a", "--factory_config"],
            0,
            "raw value: 0000000000000000",
            "",
        );

        let result = cr50_check_factory_config(&mut mock_ctx, cfg);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_cr50_check_factory_config() {
        let cfg = FactoryConfig::new(true, 0x3).unwrap();
        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["-a", "--factory_config"],
            0,
            "raw value: 0000000000000013",
            "",
        );

        let result = cr50_check_factory_config(&mut mock_ctx, cfg);
        assert_eq!(result, Err(Cr50SetFactoryConfigVerdict::AlreadySetError));
    }

    #[test]
    fn test_cr50_set_factory_config() {
        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["-a", "--factory_config"],
            0,
            "raw value: 0000000000000000",
            "",
        );
        let cfg = FactoryConfig::new(true, 0x3).unwrap();
        let val = format!("{:x}", cfg.0);
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["-a", "--factory_config", &val],
            0,
            "",
            "",
        );

        let result =
            cr50_set_factory_config(&mut mock_ctx, cfg.x_branded(), cfg.compliance_version());
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_cr50_set_factory_config_already_set() {
        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["-a", "--factory_config"],
            0,
            "raw value: 0000000000000013",
            "",
        );
        let cfg = FactoryConfig::new(true, 0x3).unwrap();
        let result =
            cr50_set_factory_config(&mut mock_ctx, cfg.x_branded(), cfg.compliance_version());
        assert_eq!(result, Err(Cr50SetFactoryConfigVerdict::AlreadySetError));
    }

    #[test]
    fn test_cr50_set_factory_config_already_set_different() {
        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["-a", "--factory_config"],
            0,
            "raw value: 0000000000000014",
            "",
        );
        let cfg = FactoryConfig::new(true, 0x3).unwrap();
        let result =
            cr50_set_factory_config(&mut mock_ctx, cfg.x_branded(), cfg.compliance_version());
        assert_eq!(
            result,
            Err(Cr50SetFactoryConfigVerdict::AlreadySetDifferentlyError)
        );
    }

    #[test]
    fn test_cr50_set_factory_config_invalid() {
        let mut mock_ctx = MockContext::new();
        let result = cr50_set_factory_config(&mut mock_ctx, false, 0xFF);
        assert_eq!(result, Err(Cr50SetFactoryConfigVerdict::GeneralError));
    }
}
