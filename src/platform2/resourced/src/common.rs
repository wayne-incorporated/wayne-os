// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::TryFrom;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{bail, Context, Result};
use libchromeos::sys::{error, warn};
use once_cell::sync::Lazy;

use crate::config;
use crate::power;
use crate::power::PowerSourceProvider;

#[cfg(target_arch = "x86_64")]
use crate::cpu_scaling::{double_min_freq, intel_i7_or_above, set_min_cpu_freq};

#[cfg(target_arch = "x86_64")]
use crate::gpu_freq_scaling::intel_device;

#[cfg(target_arch = "x86_64")]
use crate::cgroup_x86_64::{media_dynamic_cgroup, MediaDynamicCgroupAction};

use crate::cpu_utils::{hotplug_cpus, HotplugCpuAction};

// Extract the parsing function for unittest.
fn parse_file_to_u64<R: BufRead>(reader: R) -> Result<u64> {
    let first_line = reader.lines().next().context("No content in buffer")??;
    first_line
        .parse()
        .with_context(|| format!("Couldn't parse \"{}\" as u64", first_line))
}

/// Get the first line in a file and parse as u64.
pub fn read_file_to_u64<P: AsRef<Path>>(filename: P) -> Result<u64> {
    let reader = File::open(filename).map(BufReader::new)?;
    parse_file_to_u64(reader)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GameMode {
    // Game mode is off.
    Off = 0,
    // Game mode is on, borealis is the foreground subsystem.
    Borealis = 1,
    // Game mode for ARC is on, which means we shouldn't evict Android apps that
    // are foreground or perceptible.
    Arc = 2,
}

impl TryFrom<u8> for GameMode {
    type Error = anyhow::Error;

    fn try_from(mode_raw: u8) -> Result<GameMode> {
        Ok(match mode_raw {
            0 => GameMode::Off,
            1 => GameMode::Borealis,
            2 => GameMode::Arc,
            _ => bail!("Unsupported game mode value"),
        })
    }
}

static GAME_MODE: Lazy<Mutex<GameMode>> = Lazy::new(|| Mutex::new(GameMode::Off));

#[cfg(target_arch = "x86_64")]
const GPU_TUNING_POLLING_INTERVAL_MS: u64 = 1000;

pub struct TuneSwappiness {
    pub swappiness: u32,
}

// Returns a TuneSwappiness object when swappiness needs to be tuned after setting game mode.
pub fn set_game_mode(
    power_preference_manager: &dyn power::PowerPreferencesManager,
    mode: GameMode,
    root: PathBuf,
) -> Result<Option<TuneSwappiness>> {
    let old_mode = match GAME_MODE.lock() {
        Ok(mut data) => {
            let old_data = *data;
            *data = mode;
            old_data
        }
        Err(_) => bail!("Failed to set game mode"),
    };

    // Don't fail game mode settings if EPP can't be changed.
    if let Err(e) = update_power_preferences(power_preference_manager) {
        warn!(
            "Unable to set EPP {:?}.  Continue setting other game mode options.",
            e
        );
    }

    const TUNED_SWAPPINESS_VALUE: u32 = 30;
    const DEFAULT_SWAPPINESS_VALUE: u32 = 60;
    #[cfg(target_arch = "x86_64")]
    if old_mode != GameMode::Borealis && mode == GameMode::Borealis {
        match intel_device::run_active_gpu_tuning(GPU_TUNING_POLLING_INTERVAL_MS) {
            Ok(_) => log::info!("Active GPU tuning running."),
            Err(e) => log::warn!("Active GPU tuning not set. {:?}", e),
        }

        let power_manager = power::new_directory_power_preferences_manager(Path::new(&root));

        match intel_i7_or_above(Path::new(&root)) {
            Ok(res) => {
                if res
                    && power_manager.power_source_provider.get_power_source()?
                        == config::PowerSourceType::AC
                    && double_min_freq(Path::new(&root)).is_err()
                {
                    warn! {"Failed to double scaling min freq"};
                }
            }
            Err(_) => {
                warn! {"Failed to check if device is Intel i7 or above"};
            }
        }
        return Ok(Some(TuneSwappiness {
            swappiness: TUNED_SWAPPINESS_VALUE,
        }));
    } else if old_mode == GameMode::Borealis && mode != GameMode::Borealis {
        match intel_i7_or_above(Path::new(&root)) {
            Ok(res) => {
                if res {
                    if set_min_cpu_freq(Path::new(&root)).is_err() {
                        warn! {"Failed to set cpu min back to default values"};
                    }
                }
            }
            Err(_) => {
                warn! {"Failed to check if device is Intel i7 or above"};
            }
        }
        return Ok(Some(TuneSwappiness {
            swappiness: DEFAULT_SWAPPINESS_VALUE,
        }));
    }
    Ok(None)
}

pub fn get_game_mode() -> Result<GameMode> {
    match GAME_MODE.lock() {
        Ok(data) => Ok(*data),
        Err(_) => bail!("Failed to get game mode"),
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RTCAudioActive {
    // RTC is not active.
    Inactive = 0,
    // RTC is active, RTC audio is playing and recording.
    Active = 1,
}
static RTC_AUDIO_ACTIVE: Lazy<Mutex<RTCAudioActive>> =
    Lazy::new(|| Mutex::new(RTCAudioActive::Inactive));

impl TryFrom<u8> for RTCAudioActive {
    type Error = anyhow::Error;

    fn try_from(active_raw: u8) -> Result<RTCAudioActive> {
        Ok(match active_raw {
            0 => RTCAudioActive::Inactive,
            1 => RTCAudioActive::Active,
            _ => bail!("Unsupported RTC audio active value"),
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FullscreenVideo {
    // Full screen video is not active.
    Inactive = 0,
    // Full screen video is active.
    Active = 1,
}
static FULLSCREEN_VIDEO: Lazy<Mutex<FullscreenVideo>> =
    Lazy::new(|| Mutex::new(FullscreenVideo::Inactive));

impl TryFrom<u8> for FullscreenVideo {
    type Error = anyhow::Error;

    fn try_from(mode_raw: u8) -> Result<FullscreenVideo> {
        Ok(match mode_raw {
            0 => FullscreenVideo::Inactive,
            1 => FullscreenVideo::Active,
            _ => bail!("Unsupported fullscreen video mode"),
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VmBootMode {
    // VM boot mode is not active.
    Inactive = 0,
    // VM boot mode active.
    Active = 1,
}
static VMBOOT_MODE: Lazy<Mutex<VmBootMode>> = Lazy::new(|| Mutex::new(VmBootMode::Inactive));

impl TryFrom<u8> for VmBootMode {
    type Error = anyhow::Error;

    fn try_from(mode_raw: u8) -> Result<VmBootMode> {
        Ok(match mode_raw {
            0 => VmBootMode::Inactive,
            1 => VmBootMode::Active,
            _ => bail!("Unsupported VM boot mode"),
        })
    }
}

pub fn is_vm_boot_mode_enabled() -> bool {
    // Since this vm_boot_mode has no performance impact on lower end x86_64
    // devices and may hit thermal throttole on high end x86_64 ddevices,
    // this feature is disabled on x86_64.
    #[cfg(not(target_arch = "x86_64"))]
    return true;
    #[cfg(target_arch = "x86_64")]
    return false;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BatterySaverMode {
    // Battery saver mode is not active.
    Inactive = 0,
    // Battery saver mode is active.
    Active = 1,
}
static BATTERY_SAVER_MODE: Lazy<Mutex<BatterySaverMode>> =
    Lazy::new(|| Mutex::new(BatterySaverMode::Inactive));

impl TryFrom<u8> for BatterySaverMode {
    type Error = anyhow::Error;

    fn try_from(active_raw: u8) -> Result<BatterySaverMode> {
        Ok(match active_raw {
            0 => BatterySaverMode::Inactive,
            1 => BatterySaverMode::Active,
            _ => bail!("Unsupported battery saver mode value"),
        })
    }
}

pub fn update_power_preferences(
    power_preference_manager: &dyn power::PowerPreferencesManager,
) -> Result<()> {
    // We need to ensure that any function that locks more than one lock does it
    // in the same order to avoid any dead locks.
    match RTC_AUDIO_ACTIVE.lock() {
        Ok(rtc_data) => match FULLSCREEN_VIDEO.lock() {
            Ok(fsv_data) => match GAME_MODE.lock() {
                Ok(game_data) => match VMBOOT_MODE.lock() {
                    Ok(boot_data) => match BATTERY_SAVER_MODE.lock() {
                        Ok(bsm_data) => power_preference_manager.update_power_preferences(
                            *rtc_data, *fsv_data, *game_data, *boot_data, *bsm_data,
                        )?,
                        Err(_) => bail!("Failed to get battery saver mode"),
                    },
                    Err(_) => bail!("Failed to get VM boot mode"),
                },
                Err(_) => bail!("Failed to get game mode"),
            },
            Err(_) => bail!("Failed to get fullscreen mode!"),
        },
        Err(_) => bail!("Failed to get rtd audio mode!"),
    }
    Ok(())
}

pub fn set_rtc_audio_active(
    power_preference_manager: &dyn power::PowerPreferencesManager,
    mode: RTCAudioActive,
) -> Result<()> {
    match RTC_AUDIO_ACTIVE.lock() {
        Ok(mut data) => {
            *data = mode;
            /* TODO(b/226646450): set_gt_boost_freq_mhz fails on non-Intel platforms. */
            if let Err(err) = set_gt_boost_freq_mhz(mode) {
                error!("Failed to set boost freq: {:#}", err)
            }
        }
        Err(_) => bail!("Failed to set RTC audio activity"),
    }

    update_power_preferences(power_preference_manager)?;
    Ok(())
}

pub fn get_rtc_audio_active() -> Result<RTCAudioActive> {
    match RTC_AUDIO_ACTIVE.lock() {
        Ok(data) => Ok(*data),
        Err(_) => bail!("Failed to get status of RTC audio activity"),
    }
}

pub fn set_fullscreen_video(
    power_preference_manager: &dyn power::PowerPreferencesManager,
    mode: FullscreenVideo,
) -> Result<()> {
    match FULLSCREEN_VIDEO.lock() {
        Ok(mut data) => {
            *data = mode;
        }
        Err(_) => bail!("Failed to set full screen video activity"),
    }

    update_power_preferences(power_preference_manager)?;

    #[cfg(target_arch = "x86_64")]
    match mode {
        FullscreenVideo::Active => media_dynamic_cgroup(MediaDynamicCgroupAction::Start)?,
        FullscreenVideo::Inactive => media_dynamic_cgroup(MediaDynamicCgroupAction::Stop)?,
    }

    Ok(())
}

pub fn get_fullscreen_video() -> Result<FullscreenVideo> {
    match FULLSCREEN_VIDEO.lock() {
        Ok(data) => Ok(*data),
        Err(_) => bail!("Failed to get full screen video activity"),
    }
}

pub fn on_battery_saver_mode_change(
    power_preference_manager: &dyn power::PowerPreferencesManager,
    mode: BatterySaverMode,
) -> Result<()> {
    match BATTERY_SAVER_MODE.lock() {
        Ok(mut data) => {
            *data = mode;
        }
        Err(_) => bail!("Failed to set Battery saver mode activity"),
    }

    if mode == BatterySaverMode::Inactive {
        hotplug_cpus(HotplugCpuAction::OnlineAll)?;
    } else {
        hotplug_cpus(HotplugCpuAction::OfflineHalf)?;
    }

    // Governor/EPP setting
    update_power_preferences(power_preference_manager)?;

    Ok(())
}

pub fn set_vm_boot_mode(
    power_preference_manager: &dyn power::PowerPreferencesManager,
    mode: VmBootMode,
) -> Result<()> {
    if !is_vm_boot_mode_enabled() {
        bail!("VM boot mode is not enabled");
    }
    match VMBOOT_MODE.lock() {
        Ok(mut data) => {
            *data = mode;
        }
        Err(_) => bail!("Failed to set VM boot mode activity"),
    }

    update_power_preferences(power_preference_manager)?;

    Ok(())
}

fn set_gt_boost_freq_mhz(mode: RTCAudioActive) -> Result<()> {
    set_gt_boost_freq_mhz_impl(Path::new("/"), mode)
}

// Extract the impl function for unittest.
fn set_gt_boost_freq_mhz_impl(root: &Path, mode: RTCAudioActive) -> Result<()> {
    const SYSFS_BASE: &str = "sys/class/drm";
    const BOOST_PATH: &str = "gt_boost_freq_mhz";
    const MIN_PATH: &str = "gt_min_freq_mhz";
    const MAX_PATH: &str = "gt_max_freq_mhz";

    let drm_card_glob = root.join(SYSFS_BASE).join("card*").join(BOOST_PATH);
    let drm_card_glob_str = drm_card_glob
        .to_str()
        .with_context(|| format!("cannot convert path to str: {}", drm_card_glob.display()))?;
    let first_glob_result = match glob::glob(drm_card_glob_str)?.next() {
        Some(result) => result?,
        None => return Ok(()), // Skip when there is no gt_boost_freq_mhz file.
    };
    let card_path = first_glob_result
        .parent()
        .with_context(|| format!("cannot get parent: {}", first_glob_result.display()))?
        .to_path_buf();

    let gt_boost_freq_mhz_content = std::fs::read_to_string(card_path.join(BOOST_PATH))?;
    // When gt_boost_freq_mhz is 0, it cannot be changed.
    if gt_boost_freq_mhz_content == "0\n" {
        return Ok(());
    }

    let gt_boost_freq_mhz = if mode == RTCAudioActive::Active {
        std::fs::read_to_string(card_path.join(MIN_PATH))?
    } else {
        std::fs::read_to_string(card_path.join(MAX_PATH))?
    };

    std::fs::write(card_path.join(BOOST_PATH), gt_boost_freq_mhz)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::test_utils::tests::MockPowerPreferencesManager;
    use crate::test_utils::tests::{setup_mock_cpu_dev_dirs, setup_mock_cpu_files};

    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_parse_file_to_u64() {
        assert_eq!(
            parse_file_to_u64("123".to_string().as_bytes()).unwrap(),
            123
        );
        assert_eq!(
            parse_file_to_u64("456\n789".to_string().as_bytes()).unwrap(),
            456
        );
        assert!(parse_file_to_u64("".to_string().as_bytes()).is_err());
        assert!(parse_file_to_u64("abc".to_string().as_bytes()).is_err());
    }

    fn write_i32_to_file(path: &Path, value: i32) {
        fs::create_dir_all(
            path.parent()
                .with_context(|| format!("cannot get parent: {}", path.display()))
                .unwrap(),
        )
        .unwrap();

        std::fs::write(path, value.to_string()).unwrap();
    }

    #[test]
    fn test_set_gt_boost_freq_mhz() {
        const GT_BOOST_FREQ_MHZ_PATH: &str = "sys/class/drm/card0/gt_boost_freq_mhz";
        const GT_MAX_FREQ_MHZ_PATH: &str = "sys/class/drm/card0/gt_max_freq_mhz";
        const GT_MIN_FREQ_MHZ_PATH: &str = "sys/class/drm/card0/gt_min_freq_mhz";

        let root = tempdir().unwrap();
        let root_path = root.path();
        let gt_boost_freq_mhz_path = root_path.join(GT_BOOST_FREQ_MHZ_PATH);
        let gt_max_freq_mhz_path = root_path.join(GT_MAX_FREQ_MHZ_PATH);
        let gt_min_freq_mhz_path = root_path.join(GT_MIN_FREQ_MHZ_PATH);
        write_i32_to_file(&gt_boost_freq_mhz_path, 500);
        write_i32_to_file(&gt_max_freq_mhz_path, 1100);
        write_i32_to_file(&gt_min_freq_mhz_path, 300);

        set_gt_boost_freq_mhz_impl(root_path, RTCAudioActive::Active).unwrap();

        assert_eq!(read_file_to_u64(&gt_boost_freq_mhz_path).unwrap(), 300);

        set_gt_boost_freq_mhz_impl(root_path, RTCAudioActive::Inactive).unwrap();

        assert_eq!(read_file_to_u64(&gt_boost_freq_mhz_path).unwrap(), 1100);
    }

    #[test]
    fn test_get_set_game_mode() {
        let tmp_root = tempdir().unwrap();
        let root = tmp_root.path();
        setup_mock_cpu_dev_dirs(root).unwrap();
        setup_mock_cpu_files(root).unwrap();
        let power_manager = MockPowerPreferencesManager {};
        assert_eq!(get_game_mode().unwrap(), GameMode::Off);
        set_game_mode(&power_manager, GameMode::Borealis, root.to_path_buf()).unwrap();
        assert_eq!(get_game_mode().unwrap(), GameMode::Borealis);
        set_game_mode(&power_manager, GameMode::Arc, root.to_path_buf()).unwrap();
        assert_eq!(get_game_mode().unwrap(), GameMode::Arc);
    }

    #[test]
    fn test_get_set_rtc_audio_active() {
        let power_manager = MockPowerPreferencesManager {};

        assert_eq!(get_rtc_audio_active().unwrap(), RTCAudioActive::Inactive);
        set_rtc_audio_active(&power_manager, RTCAudioActive::Active).unwrap();
        assert_eq!(get_rtc_audio_active().unwrap(), RTCAudioActive::Active);
    }

    #[test]
    fn test_get_set_fullscreen_video() {
        let power_manager = MockPowerPreferencesManager {};

        assert_eq!(get_fullscreen_video().unwrap(), FullscreenVideo::Inactive);
        set_fullscreen_video(&power_manager, FullscreenVideo::Active).unwrap();
        assert_eq!(get_fullscreen_video().unwrap(), FullscreenVideo::Active);
    }
}
