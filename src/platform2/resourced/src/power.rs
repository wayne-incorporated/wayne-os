// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::read_to_string;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{bail, Context, Result};
use glob::glob;
use libchromeos::sys::{error, info};

use crate::common;
use crate::common::{BatterySaverMode, FullscreenVideo, GameMode, RTCAudioActive, VmBootMode};
use crate::config;

const POWER_SUPPLY_PATH: &str = "sys/class/power_supply";
const POWER_SUPPLY_ONLINE: &str = "online";
const POWER_SUPPLY_STATUS: &str = "status";
const GLOBAL_ONDEMAND_PATH: &str = "sys/devices/system/cpu/cpufreq/ondemand";

pub trait PowerSourceProvider {
    /// Returns the current power source of the system.
    fn get_power_source(&self) -> Result<config::PowerSourceType>;
}

/// See the `POWER_SUPPLY_STATUS_` enum in the linux kernel.
/// These values are intended to describe the battery status. They are also used
/// to describe the charger status, which adds a little bit of confusion. A
/// charger will only return `Charging` or `NotCharging`.
#[derive(Copy, Clone, Debug, PartialEq)]
enum PowerSupplyStatus {
    Unknown,
    Charging,
    Discharging,
    NotCharging,
    Full,
}

impl FromStr for PowerSupplyStatus {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim_end();

        match s {
            "Unknown" => Ok(PowerSupplyStatus::Unknown),
            "Charging" => Ok(PowerSupplyStatus::Charging),
            "Discharging" => Ok(PowerSupplyStatus::Discharging),
            "Not charging" => Ok(PowerSupplyStatus::NotCharging),
            "Full" => Ok(PowerSupplyStatus::Full),
            _ => anyhow::bail!("Unknown Power Supply Status: '{}'", s),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DirectoryPowerSourceProvider {
    pub root: PathBuf,
}

impl PowerSourceProvider for DirectoryPowerSourceProvider {
    /// Iterates through all the power supplies in sysfs and looks for the `online` property.
    /// This indicates an external power source is connected (AC), but it doesn't necessarily
    /// mean it's powering the system. Tests will sometimes disable the charger to get power
    /// measurements. In order to determine if the charger is powering the system we need to
    /// look at the `status` property. If there is no charger connected and powering the system
    /// then we assume we are running off a battery (DC).
    fn get_power_source(&self) -> Result<config::PowerSourceType> {
        let path = self.root.join(POWER_SUPPLY_PATH);

        if !path.exists() {
            return Ok(config::PowerSourceType::DC);
        }

        let dirs = path
            .read_dir()
            .with_context(|| format!("Failed to enumerate power supplies in {}", path.display()))?;

        for result in dirs {
            let charger_path = result?;

            let online_path = charger_path.path().join(POWER_SUPPLY_ONLINE);

            if !online_path.exists() {
                continue;
            }

            let online = common::read_file_to_u64(&online_path)
                .with_context(|| format!("Error reading online from {}", online_path.display()))?
                as u32;

            if online != 1 {
                continue;
            }

            let status_path = charger_path.path().join(POWER_SUPPLY_STATUS);

            if !status_path.exists() {
                continue;
            }

            let status_string = read_to_string(&status_path)
                .with_context(|| format!("Error reading status from {}", status_path.display()))?;

            let status_result = PowerSupplyStatus::from_str(&status_string);

            let status = match status_result {
                Err(_) => {
                    info!(
                        "Failure parsing '{}' from {}",
                        status_string,
                        status_path.display()
                    );
                    continue;
                }
                Ok(status) => status,
            };

            if status != PowerSupplyStatus::Charging {
                continue;
            }

            return Ok(config::PowerSourceType::AC);
        }

        Ok(config::PowerSourceType::DC)
    }
}

pub trait PowerPreferencesManager {
    /// Chooses a [power preference](config::PowerPreferences) using the parameters and the
    /// system's current power source. It then applies it to the system.
    ///
    /// If more then one activity is active, the following priority list is used
    /// to determine which [power preference](config::PowerPreferences) to apply. If there is no
    /// power preference defined for an activity, the next activity in the list will be tried.
    ///
    /// 1) [Borealis Gaming](config::PowerPreferencesType::BorealisGaming)
    /// 2) [ARCVM Gaming](config::PowerPreferencesType::ArcvmGaming)
    /// 3) [WebRTC](config::PowerPreferencesType::WebRTC)
    /// 4) [Fullscreen Video](config::PowerPreferencesType::Fullscreen)
    /// 5) [VM boot Mode] (config::PowerPreferencesType::VmBoot)
    ///
    /// The [default](config::PowerPreferencesType::Default) preference will be applied when no
    /// activity is active.
    fn update_power_preferences(
        &self,
        rtc: common::RTCAudioActive,
        fullscreen: common::FullscreenVideo,
        game: common::GameMode,
        vmboot: common::VmBootMode,
        batterysaver: common::BatterySaverMode,
    ) -> Result<()>;
}

fn write_to_cpu_policy_patterns(pattern: &str, new_value: &str) -> Result<()> {
    let mut applied: bool = false;
    let entries: Vec<_> = glob(pattern)?.collect();

    if entries.is_empty() {
        applied = true;
    }

    for entry in entries {
        let path = entry?;
        // Allow read fail due to CPU may be offlined.
        if let Ok(current_value) = read_to_string(&path) {
            if current_value.trim_end_matches('\n') != new_value {
                std::fs::write(&path, new_value).with_context(|| {
                    format!(
                        "Failed to set attribute to {}, new value: {}",
                        path.display(),
                        new_value
                    )
                })?;
            }
            applied = true;
        }
    }

    // Fail if there are entries in the pattern but nothing is applied
    if !applied {
        bail!("Failed to read any of the pattern {}", pattern);
    }

    Ok(())
}

#[derive(Clone, Debug)]
/// Applies [power preferences](config::PowerPreferences) to the system by writing to
/// the system's sysfs nodes.
///
/// This struct is using generics for the [ConfigProvider](config::ConfigProvider) and
/// [PowerSourceProvider] to make unit testing easier.
pub struct DirectoryPowerPreferencesManager<C: config::ConfigProvider, P: PowerSourceProvider> {
    pub root: PathBuf,
    pub config_provider: C,
    pub power_source_provider: P,
}

impl<C: config::ConfigProvider, P: PowerSourceProvider> DirectoryPowerPreferencesManager<C, P> {
    // The global ondemand parameters are in /sys/devices/system/cpu/cpufreq/ondemand/.
    fn set_global_ondemand_governor_value(&self, attr: &str, value: u32) -> Result<()> {
        let path = self.root.join(GLOBAL_ONDEMAND_PATH).join(attr);

        let current_value_str = read_to_string(&path)
            .with_context(|| format!("Error reading ondemand parameter from {}", path.display()))?;
        let current_value = current_value_str.trim_end_matches('\n').parse::<u32>()?;

        // Check current value before writing to avoid permission error when the new value and
        // current value are the same but resourced didn't own the parameter file.
        if current_value != value {
            std::fs::write(&path, value.to_string()).with_context(|| {
                format!("Error writing {} {} to {}", attr, value, path.display())
            })?;

            info!("Updating ondemand {} to {}", attr, value);
        }

        Ok(())
    }

    // The per-policy ondemand parameters are in /sys/devices/system/cpu/cpufreq/policy*/ondemand/.
    fn set_per_policy_ondemand_governor_value(&self, attr: &str, value: u32) -> Result<()> {
        const ONDEMAND_PATTERN: &str = "sys/devices/system/cpu/cpufreq/policy*/ondemand";
        let pattern = self
            .root
            .join(ONDEMAND_PATTERN)
            .join(attr)
            .to_str()
            .context("Cannot convert ondemand path to string")?
            .to_owned();
        write_to_cpu_policy_patterns(&pattern, &value.to_string())
    }

    fn set_scaling_governor(&self, new_governor: &str) -> Result<()> {
        const GOVERNOR_PATTERN: &str = "sys/devices/system/cpu/cpufreq/policy*/scaling_governor";
        let pattern = self
            .root
            .join(GOVERNOR_PATTERN)
            .to_str()
            .context("Cannot convert scaling_governor path to string")?
            .to_owned();

        write_to_cpu_policy_patterns(&pattern, new_governor)
    }

    fn apply_governor_preferences(&self, governor: config::Governor) -> Result<()> {
        self.set_scaling_governor(governor.to_name())?;

        if let config::Governor::Ondemand {
            powersave_bias,
            sampling_rate,
        } = governor
        {
            let global_path = self.root.join(GLOBAL_ONDEMAND_PATH);

            // There are 2 use cases now:
            // 1. on guybrush, the scaling_governor is always ondemand, the ondemand directory is
            //    chowned to resourced so resourced can set the ondemand parameters.
            // 2. on herobrine, resourced only changes the scaling_governor, so the permission of
            //    the new governor's sysfs nodes doesn't matter.
            // TODO: support changing both the scaling_governor and the governor's parameters.

            // The ondemand tunable could be global (system-wide) or per-policy, depending on the
            // scaling driver in use [1]. The global ondemand tunable is in
            // /sys/devices/system/cpu/cpufreq/ondemand. The per-policy ondemand tunable is in
            // /sys/devices/system/cpu/cpufreq/policy*/ondemand.
            //
            // [1]: https://www.kernel.org/doc/html/latest/admin-guide/pm/cpufreq.html
            if global_path.exists() {
                self.set_global_ondemand_governor_value("powersave_bias", powersave_bias)?;

                if let Some(sampling_rate) = sampling_rate {
                    self.set_global_ondemand_governor_value("sampling_rate", sampling_rate)?;
                }
            } else {
                self.set_per_policy_ondemand_governor_value("powersave_bias", powersave_bias)?;
                if let Some(sampling_rate) = sampling_rate {
                    self.set_per_policy_ondemand_governor_value("sampling_rate", sampling_rate)?;
                }
            }
        }

        Ok(())
    }

    fn has_epp(&self) -> Result<bool> {
        const CPU0_EPP_PATH: &str =
            "sys/devices/system/cpu/cpufreq/policy0/energy_performance_preference";
        let pattern = self
            .root
            .join(CPU0_EPP_PATH)
            .to_str()
            .context("Cannot convert cpu0 epp path to string")?
            .to_owned();
        Ok(Path::new(&pattern).exists())
    }

    fn set_epp(&self, epp: config::EnergyPerformancePreference) -> Result<()> {
        const EPP_PATTERN: &str =
            "sys/devices/system/cpu/cpufreq/policy*/energy_performance_preference";
        let pattern = self
            .root
            .join(EPP_PATTERN)
            .to_str()
            .context("Cannot convert epp path to string")?
            .to_owned();
        write_to_cpu_policy_patterns(&pattern, epp.to_name())
    }

    fn apply_power_preferences(&self, preferences: config::PowerPreferences) -> Result<()> {
        if let Some(epp) = preferences.epp {
            self.set_epp(epp)?
        }
        if let Some(governor) = preferences.governor {
            self.apply_governor_preferences(governor)?
        }

        Ok(())
    }
}

impl<C: config::ConfigProvider, P: PowerSourceProvider> PowerPreferencesManager
    for DirectoryPowerPreferencesManager<C, P>
{
    fn update_power_preferences(
        &self,
        rtc: RTCAudioActive,
        fullscreen: FullscreenVideo,
        game: GameMode,
        vmboot: VmBootMode,
        batterysaver: BatterySaverMode,
    ) -> Result<()> {
        let mut preferences: Option<config::PowerPreferences> = None;

        let power_source = self.power_source_provider.get_power_source()?;

        info!("Power source {:?}", power_source);

        if batterysaver == BatterySaverMode::Active {
            preferences = if self.has_epp()? {
                Some(config::PowerPreferences {
                    governor: None,
                    epp: Some(config::EnergyPerformancePreference::BalancePower),
                })
            } else {
                Some(config::PowerPreferences {
                    governor: Some(config::Governor::Conservative),
                    epp: None,
                })
            };
        } else if game == GameMode::Borealis {
            preferences = self.config_provider.read_power_preferences(
                power_source,
                config::PowerPreferencesType::BorealisGaming,
            )?;
        } else if game == GameMode::Arc {
            preferences = self
                .config_provider
                .read_power_preferences(power_source, config::PowerPreferencesType::ArcvmGaming)?;
        }

        if preferences.is_none() && rtc == RTCAudioActive::Active {
            preferences = self
                .config_provider
                .read_power_preferences(power_source, config::PowerPreferencesType::WebRTC)?;
        }

        if preferences.is_none() && fullscreen == FullscreenVideo::Active {
            preferences = self
                .config_provider
                .read_power_preferences(power_source, config::PowerPreferencesType::Fullscreen)?;
        }

        if preferences.is_none() && vmboot == VmBootMode::Active {
            preferences = self
                .config_provider
                .read_power_preferences(power_source, config::PowerPreferencesType::VmBoot)?;
        }

        if preferences.is_none() {
            preferences = self
                .config_provider
                .read_power_preferences(power_source, config::PowerPreferencesType::Default)?;
        }

        if let Some(preferences) = preferences {
            self.apply_power_preferences(preferences)?
        }

        if batterysaver == BatterySaverMode::Active {
            return Ok(());
        } else if power_source == config::PowerSourceType::DC
            && (rtc == RTCAudioActive::Active || fullscreen == FullscreenVideo::Active)
        {
            if let Err(err) = self.set_epp(config::EnergyPerformancePreference::BalancePower) {
                error!("Failed to set energy performance preference: {:#}", err);
            }
        } else {
            self.set_epp(config::EnergyPerformancePreference::BalancePerformance)?;
            // Default EPP
        }

        Ok(())
    }
}

pub fn new_directory_power_preferences_manager(
    root: &Path,
) -> DirectoryPowerPreferencesManager<config::DirectoryConfigProvider, DirectoryPowerSourceProvider>
{
    DirectoryPowerPreferencesManager {
        root: root.to_path_buf(),
        config_provider: config::DirectoryConfigProvider {
            root: root.to_path_buf(),
        },
        power_source_provider: DirectoryPowerSourceProvider {
            root: root.to_path_buf(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::bail;
    use std::fs;
    use std::path::Path;
    use tempfile::tempdir;

    #[test]
    fn test_parse_power_supply_status() -> anyhow::Result<()> {
        assert_eq!(
            PowerSupplyStatus::from_str("Unknown\n")?,
            PowerSupplyStatus::Unknown
        );
        assert_eq!(
            PowerSupplyStatus::from_str("Charging\n")?,
            PowerSupplyStatus::Charging
        );
        assert_eq!(
            PowerSupplyStatus::from_str("Discharging\n")?,
            PowerSupplyStatus::Discharging
        );
        assert_eq!(
            PowerSupplyStatus::from_str("Not charging\n")?,
            PowerSupplyStatus::NotCharging
        );
        assert_eq!(
            PowerSupplyStatus::from_str("Full\n")?,
            PowerSupplyStatus::Full
        );

        assert!(PowerSupplyStatus::from_str("").is_err());
        assert!(PowerSupplyStatus::from_str("abc").is_err());

        Ok(())
    }

    #[test]
    fn test_power_source_provider_empty_root() -> Result<()> {
        let root = tempdir()?;

        let provider = DirectoryPowerSourceProvider {
            root: root.path().to_path_buf(),
        };

        let power_source = provider.get_power_source()?;

        assert_eq!(power_source, config::PowerSourceType::DC);

        Ok(())
    }

    const POWER_SUPPLY_PATH: &str = "sys/class/power_supply";

    #[test]
    fn test_power_source_provider_empty_path() -> Result<()> {
        let root = tempdir()?;

        let path = root.path().join(POWER_SUPPLY_PATH);
        fs::create_dir_all(path)?;

        let provider = DirectoryPowerSourceProvider {
            root: root.path().to_path_buf(),
        };

        let power_source = provider.get_power_source()?;

        assert_eq!(power_source, config::PowerSourceType::DC);

        Ok(())
    }

    /// Tests that the `DirectoryPowerSourceProvider` can parse the charger sysfs
    /// `online` and `status` attributes.
    #[test]
    fn test_power_source_provider_disconnected_then_connected() -> Result<()> {
        let root = tempdir()?;

        let path = root.path().join(POWER_SUPPLY_PATH);
        fs::create_dir_all(&path)?;

        let provider = DirectoryPowerSourceProvider {
            root: root.path().to_path_buf(),
        };

        let charger = path.join("charger-1");
        fs::create_dir_all(&charger)?;
        let online = charger.join("online");

        fs::write(&online, b"0")?;
        let power_source = provider.get_power_source()?;
        assert_eq!(power_source, config::PowerSourceType::DC);

        let status = charger.join("status");
        fs::write(&online, b"1")?;
        fs::write(&status, b"Charging\n")?;
        let power_source = provider.get_power_source()?;
        assert_eq!(power_source, config::PowerSourceType::AC);

        fs::write(&online, b"1")?;
        fs::write(&status, b"Not Charging\n")?;
        let power_source = provider.get_power_source()?;
        assert_eq!(power_source, config::PowerSourceType::DC);

        Ok(())
    }

    struct FakeConfigProvider {
        default_power_preferences:
            fn(config::PowerSourceType) -> Result<Option<config::PowerPreferences>>,
        web_rtc_power_preferences:
            fn(config::PowerSourceType) -> Result<Option<config::PowerPreferences>>,
        fullscreen_power_preferences:
            fn(config::PowerSourceType) -> Result<Option<config::PowerPreferences>>,
        vm_boot_power_preferences:
            fn(config::PowerSourceType) -> Result<Option<config::PowerPreferences>>,
        borealis_gaming_power_preferences:
            fn(config::PowerSourceType) -> Result<Option<config::PowerPreferences>>,
        arcvm_gaming_power_preferences:
            fn(config::PowerSourceType) -> Result<Option<config::PowerPreferences>>,
    }

    impl Default for FakeConfigProvider {
        fn default() -> FakeConfigProvider {
            FakeConfigProvider {
                // We bail on default to ensure the tests correctly setup a default power
                // preference.
                default_power_preferences: |_| bail!("Default not Implemented"),
                web_rtc_power_preferences: |_| bail!("WebRTC not Implemented"),
                fullscreen_power_preferences: |_| bail!("Fullscreen not Implemented"),
                vm_boot_power_preferences: |_| bail!("VM boot mode not Implemented"),
                borealis_gaming_power_preferences: |_| bail!("Borealis gaming not Implemented"),
                arcvm_gaming_power_preferences: |_| bail!("ARCVM gaming not Implemented"),
            }
        }
    }

    impl config::ConfigProvider for FakeConfigProvider {
        fn read_power_preferences(
            &self,
            power_source_type: config::PowerSourceType,
            power_preference_type: config::PowerPreferencesType,
        ) -> Result<Option<config::PowerPreferences>> {
            match power_preference_type {
                config::PowerPreferencesType::Default => {
                    (self.default_power_preferences)(power_source_type)
                }
                config::PowerPreferencesType::WebRTC => {
                    (self.web_rtc_power_preferences)(power_source_type)
                }
                config::PowerPreferencesType::Fullscreen => {
                    (self.fullscreen_power_preferences)(power_source_type)
                }
                config::PowerPreferencesType::VmBoot => {
                    (self.vm_boot_power_preferences)(power_source_type)
                }
                config::PowerPreferencesType::BorealisGaming => {
                    (self.borealis_gaming_power_preferences)(power_source_type)
                }
                config::PowerPreferencesType::ArcvmGaming => {
                    (self.arcvm_gaming_power_preferences)(power_source_type)
                }
            }
        }
    }

    struct FakePowerSourceProvider {
        power_source: config::PowerSourceType,
    }

    impl PowerSourceProvider for FakePowerSourceProvider {
        fn get_power_source(&self) -> Result<config::PowerSourceType> {
            Ok(self.power_source)
        }
    }

    fn write_global_powersave_bias(root: &Path, value: u32) -> Result<()> {
        let ondemand_path = root.join("sys/devices/system/cpu/cpufreq/ondemand");
        fs::create_dir_all(&ondemand_path)?;

        std::fs::write(
            ondemand_path.join("powersave_bias"),
            value.to_string() + "\n",
        )?;

        Ok(())
    }

    fn read_global_powersave_bias(root: &Path) -> Result<String> {
        let powersave_bias_path = root
            .join("sys/devices/system/cpu/cpufreq/ondemand")
            .join("powersave_bias");

        let mut powersave_bias = std::fs::read_to_string(powersave_bias_path)?;
        if powersave_bias.ends_with('\n') {
            powersave_bias.pop();
        }

        Ok(powersave_bias)
    }

    fn write_global_sampling_rate(root: &Path, value: u32) -> Result<()> {
        let ondemand_path = root.join("sys/devices/system/cpu/cpufreq/ondemand");
        fs::create_dir_all(&ondemand_path)?;

        std::fs::write(ondemand_path.join("sampling_rate"), value.to_string())?;

        Ok(())
    }

    fn read_global_sampling_rate(root: &Path) -> Result<String> {
        let sampling_rate_path = root
            .join("sys/devices/system/cpu/cpufreq/ondemand")
            .join("sampling_rate");

        let mut sampling_rate = std::fs::read_to_string(sampling_rate_path)?;
        if sampling_rate.ends_with('\n') {
            sampling_rate.pop();
        }

        Ok(sampling_rate)
    }

    // In the following per policy access functions, there are 2 cpufreq policies: policy0 and
    // policy1.

    const TEST_CPUFREQ_POLICIES: &[&str] = &[
        "sys/devices/system/cpu/cpufreq/policy0",
        "sys/devices/system/cpu/cpufreq/policy1",
    ];
    const SCALING_GOVERNOR_FILENAME: &str = "scaling_governor";
    const ONDEMAND_DIRECTORY: &str = "ondemand";
    const POWERSAVE_BIAS_FILENAME: &str = "powersave_bias";
    const SAMPLING_RATE_FILENAME: &str = "sampling_rate";

    // Instead of returning an error, crash/assert immediately in a test utility function makes it
    // easier to debug an unittest.
    fn write_per_policy_scaling_governor(root: &Path, governor: config::Governor) {
        for policy in TEST_CPUFREQ_POLICIES {
            let policy_path = root.join(policy);
            fs::create_dir_all(&policy_path).unwrap();
            std::fs::write(
                policy_path.join(SCALING_GOVERNOR_FILENAME),
                governor.to_name().to_string() + "\n",
            )
            .unwrap();
        }
    }

    fn check_per_policy_scaling_governor(root: &Path, expected: config::Governor) {
        for policy in TEST_CPUFREQ_POLICIES {
            let governor_path = root.join(policy).join(SCALING_GOVERNOR_FILENAME);
            let scaling_governor = std::fs::read_to_string(governor_path).unwrap();
            assert_eq!(scaling_governor.trim_end_matches('\n'), expected.to_name());
        }
    }

    fn write_per_policy_powersave_bias(root: &Path, value: u32) {
        for policy in TEST_CPUFREQ_POLICIES {
            let ondemand_path = root.join(policy).join(ONDEMAND_DIRECTORY);
            println!("ondemand_path: {}", ondemand_path.display());
            fs::create_dir_all(&ondemand_path).unwrap();
            std::fs::write(
                ondemand_path.join(POWERSAVE_BIAS_FILENAME),
                value.to_string() + "\n",
            )
            .unwrap();
        }
    }

    fn check_per_policy_powersave_bias(root: &Path, expected: u32) {
        for policy in TEST_CPUFREQ_POLICIES {
            let powersave_bias_path = root
                .join(policy)
                .join(ONDEMAND_DIRECTORY)
                .join(POWERSAVE_BIAS_FILENAME);
            let powersave_bias = std::fs::read_to_string(powersave_bias_path).unwrap();
            assert_eq!(powersave_bias.trim_end_matches('\n'), expected.to_string());
        }
    }

    fn write_per_policy_sampling_rate(root: &Path, value: u32) {
        for policy in TEST_CPUFREQ_POLICIES {
            let ondemand_path = root.join(policy).join(ONDEMAND_DIRECTORY);
            fs::create_dir_all(&ondemand_path).unwrap();
            std::fs::write(
                ondemand_path.join(SAMPLING_RATE_FILENAME),
                value.to_string(),
            )
            .unwrap();
        }
    }

    fn check_per_policy_sampling_rate(root: &Path, expected: u32) {
        for policy in TEST_CPUFREQ_POLICIES {
            let sampling_rate_path = root
                .join(policy)
                .join(ONDEMAND_DIRECTORY)
                .join(SAMPLING_RATE_FILENAME);
            let sampling_rate = std::fs::read_to_string(sampling_rate_path).unwrap();
            assert_eq!(sampling_rate, expected.to_string());
        }
    }

    fn write_epp(root: &Path, value: &str) -> Result<()> {
        let policy_path = root.join("sys/devices/system/cpu/cpufreq/policy0");
        fs::create_dir_all(&policy_path)?;

        std::fs::write(policy_path.join("energy_performance_preference"), value)?;

        Ok(())
    }

    fn read_epp(root: &Path) -> Result<String> {
        let epp_path = root
            .join("sys/devices/system/cpu/cpufreq/policy0/")
            .join("energy_performance_preference");

        let epp = std::fs::read_to_string(epp_path)?;

        Ok(epp)
    }

    #[test]
    fn test_power_update_power_preferences_wrong_governor() -> Result<()> {
        let root = tempdir()?;

        let power_source_provider = FakePowerSourceProvider {
            power_source: config::PowerSourceType::AC,
        };

        let config_provider = FakeConfigProvider {
            default_power_preferences: |_| {
                Ok(Some(config::PowerPreferences {
                    governor: Some(config::Governor::Ondemand {
                        powersave_bias: 200,
                        sampling_rate: None,
                    }),
                    epp: None,
                }))
            },
            ..Default::default()
        };

        let manager = DirectoryPowerPreferencesManager {
            root: root.path().to_path_buf(),
            config_provider,
            power_source_provider,
        };

        manager.update_power_preferences(
            common::RTCAudioActive::Inactive,
            common::FullscreenVideo::Inactive,
            common::GameMode::Off,
            common::VmBootMode::Inactive,
            common::BatterySaverMode::Inactive,
        )?;

        // We shouldn't have written anything.
        let powersave_bias = read_global_powersave_bias(root.path());
        assert!(powersave_bias.is_err());

        Ok(())
    }

    #[test]
    fn test_power_update_power_preferences_none() -> Result<()> {
        let root = tempdir()?;

        write_global_powersave_bias(root.path(), 0)?;
        write_global_sampling_rate(root.path(), 2000)?;

        let power_source_provider = FakePowerSourceProvider {
            power_source: config::PowerSourceType::AC,
        };

        let config_provider = FakeConfigProvider {
            default_power_preferences: |_| Ok(None),
            ..Default::default()
        };

        let manager = DirectoryPowerPreferencesManager {
            root: root.path().to_path_buf(),
            config_provider,
            power_source_provider,
        };

        manager.update_power_preferences(
            common::RTCAudioActive::Inactive,
            common::FullscreenVideo::Inactive,
            common::GameMode::Off,
            common::VmBootMode::Inactive,
            common::BatterySaverMode::Inactive,
        )?;

        let powersave_bias = read_global_powersave_bias(root.path())?;
        assert_eq!(powersave_bias, "0");

        let sampling_rate = read_global_sampling_rate(root.path())?;
        assert_eq!(sampling_rate, "2000");

        Ok(())
    }

    #[test]
    fn test_power_update_power_preferences_default_ac() -> Result<()> {
        let root = tempdir()?;

        write_global_powersave_bias(root.path(), 0)?;
        write_global_sampling_rate(root.path(), 2000)?;

        let power_source_provider = FakePowerSourceProvider {
            power_source: config::PowerSourceType::AC,
        };

        let config_provider = FakeConfigProvider {
            default_power_preferences: |power_source| {
                assert_eq!(power_source, config::PowerSourceType::AC);

                Ok(Some(config::PowerPreferences {
                    governor: Some(config::Governor::Ondemand {
                        powersave_bias: 200,
                        sampling_rate: Some(16000),
                    }),
                    epp: None,
                }))
            },
            ..Default::default()
        };

        let manager = DirectoryPowerPreferencesManager {
            root: root.path().to_path_buf(),
            config_provider,
            power_source_provider,
        };

        manager.update_power_preferences(
            common::RTCAudioActive::Inactive,
            common::FullscreenVideo::Inactive,
            common::GameMode::Off,
            common::VmBootMode::Inactive,
            common::BatterySaverMode::Inactive,
        )?;

        let powersave_bias = read_global_powersave_bias(root.path())?;
        assert_eq!(powersave_bias, "200");

        let sampling_rate = read_global_sampling_rate(root.path())?;
        assert_eq!(sampling_rate, "16000");

        Ok(())
    }

    #[test]
    fn test_power_update_power_preferences_default_dc() -> Result<()> {
        let root = tempdir()?;

        write_global_powersave_bias(root.path(), 0)?;
        write_global_sampling_rate(root.path(), 2000)?;

        let power_source_provider = FakePowerSourceProvider {
            power_source: config::PowerSourceType::DC,
        };

        let config_provider = FakeConfigProvider {
            default_power_preferences: |power_source| {
                assert_eq!(power_source, config::PowerSourceType::DC);

                Ok(Some(config::PowerPreferences {
                    governor: Some(config::Governor::Ondemand {
                        powersave_bias: 200,
                        sampling_rate: None,
                    }),
                    epp: None,
                }))
            },
            ..Default::default()
        };

        let manager = DirectoryPowerPreferencesManager {
            root: root.path().to_path_buf(),
            config_provider,
            power_source_provider,
        };

        manager.update_power_preferences(
            common::RTCAudioActive::Inactive,
            common::FullscreenVideo::Inactive,
            common::GameMode::Off,
            common::VmBootMode::Inactive,
            common::BatterySaverMode::Inactive,
        )?;

        let powersave_bias = read_global_powersave_bias(root.path())?;
        assert_eq!(powersave_bias, "200");

        let sampling_rate = read_global_sampling_rate(root.path())?;
        assert_eq!(sampling_rate, "2000");

        Ok(())
    }

    #[test]
    fn test_power_update_power_preferences_default_rtc_active() -> Result<()> {
        let root = tempdir()?;

        write_global_powersave_bias(root.path(), 0)?;
        write_global_sampling_rate(root.path(), 2000)?;

        let power_source_provider = FakePowerSourceProvider {
            power_source: config::PowerSourceType::AC,
        };

        let config_provider = FakeConfigProvider {
            default_power_preferences: |_| {
                Ok(Some(config::PowerPreferences {
                    governor: Some(config::Governor::Ondemand {
                        powersave_bias: 200,
                        sampling_rate: Some(4000),
                    }),
                    epp: None,
                }))
            },
            web_rtc_power_preferences: |_| Ok(None),
            ..Default::default()
        };

        let manager = DirectoryPowerPreferencesManager {
            root: root.path().to_path_buf(),
            config_provider,
            power_source_provider,
        };

        manager.update_power_preferences(
            common::RTCAudioActive::Active,
            common::FullscreenVideo::Inactive,
            common::GameMode::Off,
            common::VmBootMode::Inactive,
            common::BatterySaverMode::Inactive,
        )?;

        let powersave_bias = read_global_powersave_bias(root.path())?;
        assert_eq!(powersave_bias, "200");

        let sampling_rate = read_global_sampling_rate(root.path())?;
        assert_eq!(sampling_rate, "4000");

        Ok(())
    }

    #[test]
    fn test_power_update_power_preferences_rtc_active() -> Result<()> {
        let root = tempdir()?;

        write_global_powersave_bias(root.path(), 0)?;
        write_global_sampling_rate(root.path(), 2000)?;

        let power_source_provider = FakePowerSourceProvider {
            power_source: config::PowerSourceType::AC,
        };

        let config_provider = FakeConfigProvider {
            web_rtc_power_preferences: |_| {
                Ok(Some(config::PowerPreferences {
                    governor: Some(config::Governor::Ondemand {
                        powersave_bias: 200,
                        sampling_rate: Some(16000),
                    }),
                    epp: None,
                }))
            },
            ..Default::default()
        };

        let manager = DirectoryPowerPreferencesManager {
            root: root.path().to_path_buf(),
            config_provider,
            power_source_provider,
        };

        manager.update_power_preferences(
            common::RTCAudioActive::Active,
            common::FullscreenVideo::Inactive,
            common::GameMode::Off,
            common::VmBootMode::Inactive,
            common::BatterySaverMode::Inactive,
        )?;

        let powersave_bias = read_global_powersave_bias(root.path())?;
        assert_eq!(powersave_bias, "200");

        let sampling_rate = read_global_sampling_rate(root.path())?;
        assert_eq!(sampling_rate, "16000");

        Ok(())
    }

    #[test]
    /// Tests default battery saver mode
    fn test_power_update_power_preferences_battery_saver_active() -> Result<()> {
        let temp_dir = tempdir()?;
        let root = temp_dir.path();

        let power_source_provider = FakePowerSourceProvider {
            power_source: config::PowerSourceType::AC,
        };

        let config_provider = FakeConfigProvider {
            arcvm_gaming_power_preferences: |_| {
                Ok(Some(config::PowerPreferences {
                    governor: Some(config::Governor::Schedutil),
                    epp: None,
                }))
            },
            ..Default::default()
        };

        let manager = DirectoryPowerPreferencesManager {
            root: root.to_path_buf(),
            config_provider,
            power_source_provider,
        };

        let tests = [
            (
                BatterySaverMode::Active,
                "balance_power",
                config::Governor::Conservative,
            ),
            (
                BatterySaverMode::Inactive,
                "balance_performance",
                config::Governor::Schedutil,
            ),
        ];

        // Test device without EPP path
        write_per_policy_scaling_governor(root, config::Governor::Performance);
        for test in tests {
            manager.update_power_preferences(
                common::RTCAudioActive::Inactive,
                common::FullscreenVideo::Inactive,
                common::GameMode::Arc,
                common::VmBootMode::Inactive,
                test.0,
            )?;

            check_per_policy_scaling_governor(root, test.2);
        }

        // Test device with EPP path
        write_epp(root, "balance_performance")?;
        for test in tests {
            manager.update_power_preferences(
                common::RTCAudioActive::Inactive,
                common::FullscreenVideo::Inactive,
                common::GameMode::Arc,
                common::VmBootMode::Inactive,
                test.0,
            )?;

            let epp = read_epp(root)?;
            assert_eq!(epp, test.1);
        }

        Ok(())
    }

    #[test]
    /// Tests the various EPP permutations
    fn test_power_update_power_preferences_epp() -> Result<()> {
        let root = tempdir()?;

        write_epp(root.path(), "balance_performance")?;

        let tests = [
            (
                FakePowerSourceProvider {
                    power_source: config::PowerSourceType::DC,
                },
                RTCAudioActive::Active,
                FullscreenVideo::Inactive,
                "balance_power",
            ),
            (
                FakePowerSourceProvider {
                    power_source: config::PowerSourceType::DC,
                },
                RTCAudioActive::Inactive,
                FullscreenVideo::Active,
                "balance_power",
            ),
            (
                FakePowerSourceProvider {
                    power_source: config::PowerSourceType::DC,
                },
                RTCAudioActive::Active,
                FullscreenVideo::Active,
                "balance_power",
            ),
            (
                FakePowerSourceProvider {
                    power_source: config::PowerSourceType::DC,
                },
                RTCAudioActive::Inactive,
                FullscreenVideo::Inactive,
                "balance_performance",
            ),
            (
                FakePowerSourceProvider {
                    power_source: config::PowerSourceType::AC,
                },
                RTCAudioActive::Inactive,
                FullscreenVideo::Active,
                "balance_performance",
            ),
            (
                FakePowerSourceProvider {
                    power_source: config::PowerSourceType::AC,
                },
                RTCAudioActive::Active,
                FullscreenVideo::Active,
                "balance_performance",
            ),
            (
                FakePowerSourceProvider {
                    power_source: config::PowerSourceType::AC,
                },
                RTCAudioActive::Active,
                FullscreenVideo::Inactive,
                "balance_performance",
            ),
        ];

        for test in tests {
            // Let's assume we have no config
            let config_provider = FakeConfigProvider {
                default_power_preferences: |_| Ok(None),
                web_rtc_power_preferences: |_| Ok(None),
                fullscreen_power_preferences: |_| Ok(None),
                ..Default::default()
            };

            let manager = DirectoryPowerPreferencesManager {
                root: root.path().to_path_buf(),
                config_provider,
                power_source_provider: test.0,
            };

            manager.update_power_preferences(
                test.1,
                test.2,
                common::GameMode::Off,
                common::VmBootMode::Inactive,
                common::BatterySaverMode::Inactive,
            )?;

            let epp = read_epp(root.path())?;

            assert_eq!(epp, test.3);
        }

        Ok(())
    }

    #[test]
    fn test_power_update_power_preferences_fullscreen_active() -> Result<()> {
        let root = tempdir()?;

        write_global_powersave_bias(root.path(), 0)?;
        write_global_sampling_rate(root.path(), 2000)?;

        let power_source_provider = FakePowerSourceProvider {
            power_source: config::PowerSourceType::AC,
        };

        let config_provider = FakeConfigProvider {
            fullscreen_power_preferences: |_| {
                Ok(Some(config::PowerPreferences {
                    governor: Some(config::Governor::Ondemand {
                        powersave_bias: 200,
                        sampling_rate: Some(16000),
                    }),
                    epp: None,
                }))
            },
            ..Default::default()
        };

        let manager = DirectoryPowerPreferencesManager {
            root: root.path().to_path_buf(),
            config_provider,
            power_source_provider,
        };

        manager.update_power_preferences(
            common::RTCAudioActive::Inactive,
            common::FullscreenVideo::Active,
            common::GameMode::Off,
            common::VmBootMode::Inactive,
            common::BatterySaverMode::Inactive,
        )?;

        let powersave_bias = read_global_powersave_bias(root.path())?;
        assert_eq!(powersave_bias, "200");

        let sampling_rate = read_global_sampling_rate(root.path())?;
        assert_eq!(sampling_rate, "16000");

        Ok(())
    }

    #[test]
    fn test_power_update_power_preferences_borealis_gaming_active() -> Result<()> {
        let root = tempdir()?;

        write_global_powersave_bias(root.path(), 0)?;
        write_global_sampling_rate(root.path(), 2000)?;

        let power_source_provider = FakePowerSourceProvider {
            power_source: config::PowerSourceType::AC,
        };

        let config_provider = FakeConfigProvider {
            borealis_gaming_power_preferences: |_| {
                Ok(Some(config::PowerPreferences {
                    governor: Some(config::Governor::Ondemand {
                        powersave_bias: 200,
                        sampling_rate: Some(16000),
                    }),
                    epp: None,
                }))
            },
            ..Default::default()
        };

        let manager = DirectoryPowerPreferencesManager {
            root: root.path().to_path_buf(),
            config_provider,
            power_source_provider,
        };

        manager.update_power_preferences(
            common::RTCAudioActive::Inactive,
            common::FullscreenVideo::Inactive,
            common::GameMode::Borealis,
            common::VmBootMode::Inactive,
            common::BatterySaverMode::Inactive,
        )?;

        let powersave_bias = read_global_powersave_bias(root.path())?;
        assert_eq!(powersave_bias, "200");

        let sampling_rate = read_global_sampling_rate(root.path())?;
        assert_eq!(sampling_rate, "16000");

        Ok(())
    }

    #[test]
    fn test_power_update_power_preferences_arcvm_gaming_active() -> Result<()> {
        let root = tempdir()?;

        write_global_powersave_bias(root.path(), 0)?;
        write_global_sampling_rate(root.path(), 2000)?;

        let power_source_provider = FakePowerSourceProvider {
            power_source: config::PowerSourceType::AC,
        };

        let config_provider = FakeConfigProvider {
            arcvm_gaming_power_preferences: |_| {
                Ok(Some(config::PowerPreferences {
                    governor: Some(config::Governor::Ondemand {
                        powersave_bias: 200,
                        sampling_rate: Some(16000),
                    }),
                    epp: None,
                }))
            },
            ..Default::default()
        };

        let manager = DirectoryPowerPreferencesManager {
            root: root.path().to_path_buf(),
            config_provider,
            power_source_provider,
        };

        manager.update_power_preferences(
            common::RTCAudioActive::Inactive,
            common::FullscreenVideo::Inactive,
            common::GameMode::Arc,
            common::VmBootMode::Inactive,
            common::BatterySaverMode::Inactive,
        )?;

        let powersave_bias = read_global_powersave_bias(root.path())?;
        assert_eq!(powersave_bias, "200");

        let sampling_rate = read_global_sampling_rate(root.path())?;
        assert_eq!(sampling_rate, "16000");

        Ok(())
    }

    #[test]
    fn test_per_policy_ondemand_governor() -> Result<()> {
        let temp_dir = tempdir()?;
        let root = temp_dir.path();

        const INIT_POWERSAVE_BIAS: u32 = 0;
        const INIT_SAMPLING_RATE: u32 = 2000;
        const CONFIG_POWERSAVE_BIAS: u32 = 200;
        const CONFIG_SAMPLING_RATE: u32 = 16000;

        let ondemand = config::Governor::Ondemand {
            powersave_bias: INIT_POWERSAVE_BIAS,
            sampling_rate: Some(INIT_SAMPLING_RATE),
        };
        write_per_policy_scaling_governor(root, ondemand);
        write_per_policy_powersave_bias(root, INIT_POWERSAVE_BIAS);
        write_per_policy_sampling_rate(root, INIT_SAMPLING_RATE);

        let power_source_provider = FakePowerSourceProvider {
            power_source: config::PowerSourceType::AC,
        };

        let config_provider = FakeConfigProvider {
            arcvm_gaming_power_preferences: |_| {
                Ok(Some(config::PowerPreferences {
                    governor: Some(config::Governor::Ondemand {
                        powersave_bias: CONFIG_POWERSAVE_BIAS,
                        sampling_rate: Some(CONFIG_SAMPLING_RATE),
                    }),
                    epp: None,
                }))
            },
            ..Default::default()
        };

        let manager = DirectoryPowerPreferencesManager {
            root: root.to_path_buf(),
            config_provider,
            power_source_provider,
        };

        manager.update_power_preferences(
            common::RTCAudioActive::Inactive,
            common::FullscreenVideo::Inactive,
            common::GameMode::Arc,
            common::VmBootMode::Inactive,
            common::BatterySaverMode::Inactive,
        )?;
        check_per_policy_scaling_governor(root, ondemand);
        check_per_policy_powersave_bias(root, CONFIG_POWERSAVE_BIAS);
        check_per_policy_sampling_rate(root, CONFIG_SAMPLING_RATE);
        Ok(())
    }

    struct ArcvmGamingConfigProvider {
        arcvm_gaming_power_preferences: config::PowerPreferences,
    }

    impl config::ConfigProvider for ArcvmGamingConfigProvider {
        fn read_power_preferences(
            &self,
            _power_source_type: config::PowerSourceType,
            power_preference_type: config::PowerPreferencesType,
        ) -> Result<Option<config::PowerPreferences>> {
            match power_preference_type {
                config::PowerPreferencesType::ArcvmGaming => {
                    Ok(Some(self.arcvm_gaming_power_preferences))
                }
                _ => bail!("Unexpected power preference type"),
            }
        }
    }

    #[test]
    fn test_scaling_governors() -> Result<()> {
        let temp_dir = tempdir()?;
        let root = temp_dir.path();

        const INIT_POWERSAVE_BIAS: u32 = 0;
        const INIT_SAMPLING_RATE: u32 = 2000;

        let ondemand = config::Governor::Ondemand {
            powersave_bias: INIT_POWERSAVE_BIAS,
            sampling_rate: Some(INIT_SAMPLING_RATE),
        };
        write_per_policy_scaling_governor(root, ondemand);

        let governors = [
            config::Governor::Conservative,
            config::Governor::Performance,
            config::Governor::Powersave,
            config::Governor::Schedutil,
            config::Governor::Userspace,
        ];

        for governor in governors {
            let power_source_provider = FakePowerSourceProvider {
                power_source: config::PowerSourceType::AC,
            };
            // The governor is a variable that we cannot use FakeConfigProvider.
            // Got the following error when using FakeConfigProvider:
            // closures can only be coerced to `fn` types if they do not capture any variables
            let config_provider = ArcvmGamingConfigProvider {
                arcvm_gaming_power_preferences: config::PowerPreferences {
                    governor: Some(governor),
                    epp: None,
                },
            };
            let manager = DirectoryPowerPreferencesManager {
                root: root.to_path_buf(),
                config_provider,
                power_source_provider,
            };

            manager.update_power_preferences(
                common::RTCAudioActive::Inactive,
                common::FullscreenVideo::Inactive,
                common::GameMode::Arc,
                common::VmBootMode::Inactive,
                common::BatterySaverMode::Inactive,
            )?;

            check_per_policy_scaling_governor(root, governor);
        }

        Ok(())
    }
}
