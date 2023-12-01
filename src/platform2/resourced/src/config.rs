// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::DirEntry;
use std::path::Path;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};

use crate::common::read_file_to_u64;

const RESOURCED_CONFIG_PATH: &str = "run/chromeos-config/v1/resource/";

pub trait ConfigProvider {
    fn read_power_preferences(
        &self,
        power_source_type: PowerSourceType,
        power_preference_type: PowerPreferencesType,
    ) -> Result<Option<PowerPreferences>>;
}

pub trait FromDir {
    // The return type is Result<Option<Self>> so parse_config_from_path() don't have to
    // parse the result.
    fn from_dir(dir: DirEntry) -> Result<Option<Self>>
    where
        Self: Sized;
}

/* TODO: Can we use `rust-protobuf` to generate all the structs? */

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Governor {
    Conservative,
    Ondemand {
        powersave_bias: u32,
        sampling_rate: Option<u32>,
    },
    Performance,
    Powersave,
    Schedutil,
    Userspace,
}

impl Governor {
    pub fn to_name(self) -> &'static str {
        match self {
            Governor::Conservative => "conservative",
            Governor::Ondemand {
                powersave_bias: _,
                sampling_rate: _,
            } => "ondemand",
            Governor::Performance => "performance",
            Governor::Powersave => "powersave",
            Governor::Schedutil => "schedutil",
            Governor::Userspace => "userspace",
        }
    }
}

impl FromDir for Governor {
    fn from_dir(dir: DirEntry) -> Result<Option<Governor>> {
        match dir.file_name().to_str() {
            Some("conservative") => Ok(Some(Governor::Conservative)),
            Some("ondemand") => Ok(Some(parse_ondemand_governor(&dir.path())?)),
            Some("performance") => Ok(Some(Governor::Performance)),
            Some("powersave") => Ok(Some(Governor::Powersave)),
            Some("schedutil") => Ok(Some(Governor::Schedutil)),
            Some("userspace") => Ok(Some(Governor::Userspace)),
            _ => bail!("Unknown governor {:?}!", dir.file_name()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnergyPerformancePreference {
    Default,
    Performance,
    BalancePerformance,
    BalancePower,
    Power,
}

impl EnergyPerformancePreference {
    pub fn to_name(self) -> &'static str {
        match self {
            EnergyPerformancePreference::Default => "default",
            EnergyPerformancePreference::Performance => "performance",
            EnergyPerformancePreference::BalancePerformance => "balance_performance",
            EnergyPerformancePreference::BalancePower => "balance_power",
            EnergyPerformancePreference::Power => "power",
        }
    }
}

impl FromDir for EnergyPerformancePreference {
    fn from_dir(dir: DirEntry) -> Result<Option<EnergyPerformancePreference>> {
        match dir.file_name().to_str() {
            Some("default") => Ok(Some(EnergyPerformancePreference::Default)),
            Some("performance") => Ok(Some(EnergyPerformancePreference::Performance)),
            Some("balance_performance") => {
                Ok(Some(EnergyPerformancePreference::BalancePerformance))
            }
            Some("balance_power") => Ok(Some(EnergyPerformancePreference::BalancePower)),
            Some("power") => Ok(Some(EnergyPerformancePreference::Power)),
            _ => bail!("Unknown epp {:?}!", dir.file_name()),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PowerPreferences {
    pub governor: Option<Governor>,
    pub epp: Option<EnergyPerformancePreference>,
}

#[derive(Copy, Clone)]
pub enum PowerPreferencesType {
    Default,
    WebRTC,
    Fullscreen,
    VmBoot,
    BorealisGaming,
    ArcvmGaming,
}

impl PowerPreferencesType {
    fn to_name(self) -> &'static str {
        match self {
            PowerPreferencesType::Default => "default-power-preferences",
            PowerPreferencesType::WebRTC => "web-rtc-power-preferences",
            PowerPreferencesType::Fullscreen => "fullscreen-power-preferences",
            PowerPreferencesType::VmBoot => "vm-boot-power-preferences",
            PowerPreferencesType::BorealisGaming => "borealis-gaming-power-preferences",
            PowerPreferencesType::ArcvmGaming => "arcvm-gaming-power-preferences",
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PowerSourceType {
    AC,
    DC,
}

impl PowerSourceType {
    fn to_name(self) -> &'static str {
        match self {
            PowerSourceType::AC => "ac",
            PowerSourceType::DC => "dc",
        }
    }
}

fn parse_ondemand_governor(path: &Path) -> Result<Governor> {
    let powersave_bias_path = path.join("powersave-bias");

    let powersave_bias = read_file_to_u64(&powersave_bias_path).with_context(|| {
        format!(
            "Error reading powersave-bias from {}",
            powersave_bias_path.display()
        )
    })? as u32;

    let sampling_rate_path = path.join("sampling-rate-ms");

    // The sampling-rate config is optional in the config
    let sampling_rate = if sampling_rate_path.exists() {
        let sampling_rate_ms = read_file_to_u64(&sampling_rate_path).with_context(|| {
            format!(
                "Error reading sampling-rate-ms from {}",
                sampling_rate_path.display()
            )
        })? as u32;

        // We treat the default value of 0 as unset. We do this because the kernel treats
        // a sampling rate of 0 as invalid.
        if sampling_rate_ms == 0 {
            None
        } else {
            // We convert from ms to uS to match what the kernel expects
            Some(sampling_rate_ms * 1000)
        }
    } else {
        None
    };

    Ok(Governor::Ondemand {
        powersave_bias,
        sampling_rate,
    })
}

// Returns Ok(None) when there is no sub directory in path.
// Returns error when there are multiple sub directories in path or when the
// sub directory name is not a supported governor.
fn parse_config_from_path<T: FromDir>(path: &Path) -> Result<Option<T>> {
    let mut dirs = path
        .read_dir()
        .with_context(|| format!("Failed to read governors from {}", path.display()))?;

    let first_dir = match dirs.next() {
        None => return Ok(None),
        Some(dir) => dir?,
    };

    if dirs.next().is_some() {
        bail!("Multiple governors detected in {}", path.display());
    }

    T::from_dir(first_dir)
}

/* Expects to find a directory tree as follows:
 * * {root}/run/chromeos-config/v1/resource/
 *   * {ac,dc}
 *     * web-rtc-power-preferences/governor/
 *       * ondemand/
 *         * powersave-bias
 *     * fullscreen-power-preferences/governor/
 *       * schedutil/
 *     * vm-boot-power-preferences/governor/..
 *     * borealis-gaming-power-preferences/governor/..
 *     * arcvm-gaming-power-preferences/governor/..
 *     * default-power-preferences/governor/..
 */
#[derive(Clone, Debug)]
pub struct DirectoryConfigProvider {
    pub root: PathBuf,
}

impl ConfigProvider for DirectoryConfigProvider {
    fn read_power_preferences(
        &self,
        power_source_type: PowerSourceType,
        power_preference_type: PowerPreferencesType,
    ) -> Result<Option<PowerPreferences>> {
        let path = self
            .root
            .join(RESOURCED_CONFIG_PATH)
            .join(power_source_type.to_name())
            .join(power_preference_type.to_name());

        if !path.exists() {
            return Ok(None);
        }

        let mut preferences: PowerPreferences = PowerPreferences {
            governor: None,
            epp: None,
        };

        let governor_path = path.join("governor");
        if governor_path.exists() {
            preferences.governor = parse_config_from_path::<Governor>(&governor_path)?;
        }

        let epp_path = path.join("epp");
        if epp_path.exists() {
            preferences.epp = parse_config_from_path::<EnergyPerformancePreference>(&epp_path)?;
        }

        Ok(Some(preferences))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_config_provider_empty_root() -> Result<()> {
        let root = tempdir()?;
        let provider = DirectoryConfigProvider {
            root: root.path().to_path_buf(),
        };

        let preference =
            provider.read_power_preferences(PowerSourceType::AC, PowerPreferencesType::Default)?;

        assert!(preference.is_none());

        let preference =
            provider.read_power_preferences(PowerSourceType::DC, PowerPreferencesType::Default)?;

        assert!(preference.is_none());

        Ok(())
    }

    #[test]
    fn test_config_provider_empty_dir() -> Result<()> {
        let root = tempdir()?;
        let path = root.path().join(RESOURCED_CONFIG_PATH);
        fs::create_dir_all(path).unwrap();

        let provider = DirectoryConfigProvider {
            root: root.path().to_path_buf(),
        };

        let preference =
            provider.read_power_preferences(PowerSourceType::AC, PowerPreferencesType::Default)?;

        assert!(preference.is_none());

        let preference =
            provider.read_power_preferences(PowerSourceType::DC, PowerPreferencesType::Default)?;

        assert!(preference.is_none());

        Ok(())
    }

    #[test]
    fn test_config_provider_epp() -> Result<()> {
        let power_source = (PowerSourceType::AC, "ac");
        let preference = (PowerPreferencesType::WebRTC, "web-rtc-power-preferences");
        let root = tempdir()?;
        let ondemand_path = root
            .path()
            .join(RESOURCED_CONFIG_PATH)
            .join(power_source.1)
            .join(preference.1)
            .join("epp")
            .join("balance_performance");
        fs::create_dir_all(ondemand_path)?;

        let provider = DirectoryConfigProvider {
            root: root.path().to_path_buf(),
        };

        let actual = provider.read_power_preferences(power_source.0, preference.0)?;

        let expected = PowerPreferences {
            governor: None,
            epp: Some(EnergyPerformancePreference::BalancePerformance),
        };

        assert_eq!(expected, actual.unwrap());

        Ok(())
    }

    #[test]
    fn test_config_provider_ondemand_all_types() -> Result<()> {
        let power_source_params = [(PowerSourceType::AC, "ac"), (PowerSourceType::DC, "dc")];

        let preference_params = [
            (PowerPreferencesType::Default, "default-power-preferences"),
            (PowerPreferencesType::WebRTC, "web-rtc-power-preferences"),
            (
                PowerPreferencesType::Fullscreen,
                "fullscreen-power-preferences",
            ),
            (PowerPreferencesType::VmBoot, "vm-boot-power-preferences"),
            (
                PowerPreferencesType::BorealisGaming,
                "borealis-gaming-power-preferences",
            ),
            (
                PowerPreferencesType::ArcvmGaming,
                "arcvm-gaming-power-preferences",
            ),
        ];

        for (power_source, power_source_path) in power_source_params {
            for (preference, preference_path) in preference_params {
                let root = tempdir()?;
                let ondemand_path = root
                    .path()
                    .join(RESOURCED_CONFIG_PATH)
                    .join(power_source_path)
                    .join(preference_path)
                    .join("governor")
                    .join("ondemand");
                fs::create_dir_all(&ondemand_path)?;

                let powersave_bias_path = ondemand_path.join("powersave-bias");
                fs::write(powersave_bias_path, b"340")?;

                let provider = DirectoryConfigProvider {
                    root: root.path().to_path_buf(),
                };

                let actual = provider.read_power_preferences(power_source, preference)?;

                let expected = PowerPreferences {
                    governor: Some(Governor::Ondemand {
                        powersave_bias: 340,
                        sampling_rate: None,
                    }),
                    epp: None,
                };

                assert_eq!(expected, actual.unwrap());

                // Now try with a sampling_rate 0 (unset)

                let powersave_bias_path = ondemand_path.join("sampling-rate-ms");
                fs::write(powersave_bias_path, b"0")?;

                let actual = provider.read_power_preferences(power_source, preference)?;

                let expected = PowerPreferences {
                    governor: Some(Governor::Ondemand {
                        powersave_bias: 340,
                        sampling_rate: None,
                    }),
                    epp: None,
                };

                assert_eq!(expected, actual.unwrap());

                // Now try with a sampling_rate 16

                let powersave_bias_path = ondemand_path.join("sampling-rate-ms");
                fs::write(powersave_bias_path, b"16")?;

                let actual = provider.read_power_preferences(power_source, preference)?;

                let expected = PowerPreferences {
                    governor: Some(Governor::Ondemand {
                        powersave_bias: 340,
                        sampling_rate: Some(16000),
                    }),
                    epp: None,
                };

                assert_eq!(expected, actual.unwrap());
            }
        }

        Ok(())
    }
}
