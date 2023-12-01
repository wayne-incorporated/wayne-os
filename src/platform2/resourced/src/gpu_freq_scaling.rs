// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::gpu_freq_scaling::amd_device::{
    amd_sustained_mode_cleanup, amd_sustained_mode_init, create_amd_device_config,
};
use anyhow::{bail, Result};
use once_cell::sync::Lazy;
use std::sync::Mutex;

static VC_MODE: Lazy<Mutex<bool>> = Lazy::new(|| Mutex::new(false));

pub fn disable_vc_mode() -> Result<()> {
    match VC_MODE.lock() {
        Ok(mut vc_mode) => {
            if *vc_mode {
                if let Ok(dev) = create_amd_device_config() {
                    match amd_sustained_mode_cleanup(&dev) {
                        Ok(_) => *vc_mode = false,
                        Err(_) => bail!("failed to clean amd sustained mode"),
                    }
                }
            }
        }
        Err(_) => bail!("failed to vc mutex"),
    }
    Ok(())
}

pub fn enable_vc_mode() -> Result<()> {
    match VC_MODE.lock() {
        Ok(mut vc_mode) => {
            if !*vc_mode {
                if let Ok(dev) = create_amd_device_config() {
                    match amd_sustained_mode_init(&dev) {
                        Ok(_) => *vc_mode = true,
                        Err(_) => bail!("failed to init amd sustained mode"),
                    }
                    dev.set_min_frequency(1600)?;
                }
            }
        }
        Err(_) => bail!("failed to vc mutex"),
    }
    Ok(())
}

pub mod intel_device {
    use crate::{
        common::{self, GameMode},
        cpu_scaling::DeviceCpuStatus,
    };
    use anyhow::{bail, Context, Result};
    use log::{info, warn};
    use regex::Regex;
    use std::{
        fs::{self, File},
        io::{BufRead, BufReader},
        path::PathBuf,
        sync::Mutex,
        thread,
        time::Duration,
    };

    // Device path for cpuinfo.
    const CPUINFO_PATH: &str = "proc/cpuinfo";

    // Device path for GPU card.
    const GPU0_DEVICE_PATH: &str = "sys/class/drm/card0";

    // Expected GPU freq for cometlake.  Used for filtering check.
    const EXPECTED_GPU_MAX_FREQ: u64 = 1000;

    // Guard range when reclocking.  max > min + guard.
    const GPU_FREQUENCY_GUARD_BUFFER_MHZ: u64 = 200;

    pub struct IntelGpuDeviceConfig {
        min_freq_path: PathBuf,

        max_freq_path: PathBuf,

        turbo_freq_path: PathBuf,

        // pub(crate) for sanity unit testing
        /// `power_liit_thr` is a table of tuple containing a power_limit_0 value and
        /// a max_gpu_freq.  Any power_limit that falls within index i and i+1
        /// gets mapped to max_gpu_freq i.  If power limit exceeds index 0, gpu_max_freq
        /// gets mapped to index 0.  Any power_limit below the defined table min will be
        /// mapped to the lowest max_gpu_freq.
        pub(crate) power_limit_thr: Vec<(u64, u64)>,

        polling_interval_ms: u64,
    }

    struct GpuStats {
        min_freq: u64,

        max_freq: u64,

        // Turbo freq is not manually controlled.  MAX == TURBO initially.
        _turbo_freq: u64,
    }

    /// Function to check if device has Intel cpu.
    ///
    /// # Return
    ///
    /// Boolean denoting if device has Intel CPU.
    pub fn is_intel_device(root: PathBuf) -> bool {
        if let Ok(reader) = File::open(root.join(CPUINFO_PATH))
            .map(BufReader::new)
            .context("Couldn't read cpuinfo")
        {
            for line in reader.lines().flatten() {
                // Only check CPU0 and fail early.
                // TODO: integrate with `crgoup_x86_64.rs`
                if line.starts_with("vendor_id") {
                    return line.ends_with("GenuineIntel");
                }
            }
        }
        false
    }

    /// Creates a thread that periodically checks for changes in power_limit and adjusts
    /// the GPU frequency accordingly.
    ///
    /// # Arguments
    ///
    /// * `polling_interval_ms` - How often to check if tuning should be re-adjusted
    pub fn run_active_gpu_tuning(polling_interval_ms: u64) -> Result<()> {
        run_active_gpu_tuning_impl(PathBuf::from("/"), polling_interval_ms)
    }

    /// TODO: remove pub. Separate amd and intel unit tests into their own module so
    /// they have access to private functions.  Leave this `pub` for now.
    pub(crate) fn run_active_gpu_tuning_impl(
        root: PathBuf,
        polling_interval_ms: u64,
    ) -> Result<()> {
        static TUNING_RUNNING: Mutex<bool> = Mutex::new(false);

        if let Ok(mut running) = TUNING_RUNNING.lock() {
            if *running {
                // Not an error case since set_game_mode called periodically.
                // Prevent new thread from spawning.
                info!("Tuning thread already running, ignoring new request");
            } else {
                let gpu_dev = IntelGpuDeviceConfig::new(root.to_owned(), polling_interval_ms)?;
                let cpu_dev = DeviceCpuStatus::new(root)?;

                *running = true;

                thread::spawn(move || {
                    info!("Created GPU tuning thread with {polling_interval_ms}ms interval");
                    match gpu_dev.adjust_gpu_frequency(&cpu_dev) {
                        Ok(_) => info!("GPU tuning thread ended successfully"),
                        Err(e) => {
                            warn!("GPU tuning thread ended prematurely: {:?}", e);
                        }
                    }

                    if gpu_dev.tuning_cleanup().is_err() {
                        warn!("GPU tuning thread cleanup failed");
                    }

                    if let Ok(mut running) = TUNING_RUNNING.lock() {
                        *running = false;
                    } else {
                        warn!("GPU Tuning thread Mutex poisoned, unable to reset flag");
                    }
                });
            }
        } else {
            warn!("GPU Tuning thread Mutex poisoned, ignoring run request");
        }

        Ok(())
    }

    impl IntelGpuDeviceConfig {
        /// Create a new Intel GPU device object which can be used to set system tuning parameters.
        ///
        /// # Arguments
        ///
        /// * `root` - root path of device.  Used for using relative paths for testing.  Should
        /// always be '/' for device.
        ///
        /// * `polling_interval_ms` - How often to check if tuning should be re-adjusted.
        ///
        /// # Return
        ///
        /// New Intel GPU device object.
        pub fn new(root: PathBuf, polling_interval_ms: u64) -> Result<IntelGpuDeviceConfig> {
            if !is_intel_device(root.to_owned())
                || !IntelGpuDeviceConfig::is_supported_device(root.to_owned())
            {
                bail!("Not a supported intel device");
            }

            let gpu_dev = IntelGpuDeviceConfig {
                min_freq_path: root.join(GPU0_DEVICE_PATH).join("gt_min_freq_mhz"),
                max_freq_path: root.join(GPU0_DEVICE_PATH).join("gt_max_freq_mhz"),
                turbo_freq_path: root.join(GPU0_DEVICE_PATH).join("gt_boost_freq_mhz"),
                power_limit_thr: vec![
                    (15000000, EXPECTED_GPU_MAX_FREQ),
                    (14500000, 900),
                    (13500000, 800),
                    (12500000, 700),
                    (10000000, 650),
                ],
                polling_interval_ms,
            };

            // Don't attempt to tune if tuning table isn't calibrated for device or another
            // process has already modified the max_freq.
            if gpu_dev.get_gpu_stats()?.max_freq != EXPECTED_GPU_MAX_FREQ {
                bail!("Expected GPU max frequency does not match.  Aborting dynamic tuning.");
            }

            Ok(gpu_dev)
        }

        // This function will only filter in 10th gen (Cometlake CPUs).  The current tuning
        // table is only valid for Intel cometlake deives using a core i3/i5/i7 processors.
        fn is_supported_device(root: PathBuf) -> bool {
            if let Ok(reader) = File::open(root.join(CPUINFO_PATH))
                .map(BufReader::new)
                .context("Couldn't read cpuinfo")
            {
                for line in reader.lines().flatten() {
                    // Only check CPU0 and fail early.
                    if line.starts_with(r"model name") {
                        // Regex will only match 10th gen intel i3, i5, i7
                        // Intel CPU naming convention can be found here:
                        // `https://www.intel.com/content/www/us/en/processors/processor-numbers.html`
                        if let Ok(re) = Regex::new(r".*Intel.* i(3|5|7)-10.*") {
                            return re.is_match(&line);
                        };
                        return false;
                    }
                }
            }
            false
        }

        fn get_gpu_stats(&self) -> Result<GpuStats> {
            Ok(GpuStats {
                min_freq: common::read_file_to_u64(&self.min_freq_path)?,
                max_freq: common::read_file_to_u64(&self.max_freq_path)?,
                _turbo_freq: common::read_file_to_u64(&self.turbo_freq_path)?,
            })
        }

        fn set_gpu_max_freq(&self, val: u64) -> Result<()> {
            Ok(fs::write(&self.max_freq_path, val.to_string())?)
        }

        fn set_gpu_turbo_freq(&self, val: u64) -> Result<()> {
            Ok(fs::write(&self.turbo_freq_path, val.to_string())?)
        }

        /// Function to check the power limit and adjust GPU frequency range.
        /// Function will first check if there any power_limit changes since
        /// the last poll.  If there are changes, it then checks if the power_limit range
        /// has moved to a new bucket, which would require adjusting the GPU
        /// max and turbo frequency.  Buckets are ranges of power_limit values
        /// that map to a specific max_gpu_freq.
        ///
        /// # Arguments
        ///
        /// * `cpu_dev` - CpuDevice object for reading power limit.
        fn adjust_gpu_frequency(&self, cpu_dev: &DeviceCpuStatus) -> Result<()> {
            let mut last_pl_val = cpu_dev.get_pl0_curr()?;
            let mut prev_bucket_index = self.get_pl_bucket_index(last_pl_val);

            while common::get_game_mode()? == GameMode::Borealis {
                thread::sleep(Duration::from_millis(self.polling_interval_ms));

                let current_pl = cpu_dev.get_pl0_curr()?;
                if current_pl == last_pl_val {
                    // No change in powerlimit since last check, no action needed.
                    continue;
                }

                let current_bucket_index = self.get_pl_bucket_index(current_pl);

                // Only change GPU freq if PL0 changed and we moved to a new bucket.
                if current_bucket_index != prev_bucket_index {
                    info!("power_limit_0 changed: {} -> {}", last_pl_val, current_pl);
                    info!(
                        "pl0 bucket changed {} -> {}",
                        prev_bucket_index, current_bucket_index
                    );
                    if let Some(requested_bucket) = self.power_limit_thr.get(current_bucket_index) {
                        let gpu_stats = self.get_gpu_stats()?;
                        let requested_gpu_freq = requested_bucket.1;

                        // This block will assign a new GPU max if needed.  Leave a 200MHz buffer
                        if requested_gpu_freq
                            > (gpu_stats.min_freq + GPU_FREQUENCY_GUARD_BUFFER_MHZ)
                            && requested_gpu_freq != gpu_stats.max_freq
                        {
                            info!("Setting GPU max to {}", requested_gpu_freq);
                            // For the initial version, gpu_max = turbo.
                            self.set_gpu_max_freq(requested_gpu_freq)?;
                            self.set_gpu_turbo_freq(requested_gpu_freq)?;
                        } else {
                            warn!("Did not change GPU frequency to {requested_gpu_freq}");
                        }
                    }
                }
                last_pl_val = current_pl;
                prev_bucket_index = current_bucket_index;
            }

            Ok(())
        }

        // This function returns the index of the vector power_limit_thr where this given
        // power_limit (pl0_val) falls.
        fn get_pl_bucket_index(&self, pl0_val: u64) -> usize {
            for (i, &(pl_thr, _)) in self.power_limit_thr.iter().enumerate() {
                if i == 0 && pl0_val >= pl_thr {
                    // Requested pl0 is bigger than max supported. Use max.
                    return 0;
                } else if i == self.power_limit_thr.len() - 1 {
                    // Didn't fall into any previous bucket.  Use min.
                    return self.power_limit_thr.len() - 1;
                } else if i > 0 && pl0_val > pl_thr {
                    return i;
                }
            }

            // Default is unthrottled (error case)
            0
        }

        pub fn tuning_cleanup(&self) -> Result<()> {
            info!("Active Gpu Tuning STOP requested");

            // Swallow any potential errors when resetting.
            let gpu_max_default = self.power_limit_thr.first().unwrap_or(&(1000, 1000)).1;
            self.set_gpu_max_freq(gpu_max_default)?;
            self.set_gpu_turbo_freq(gpu_max_default)?;

            Ok(())
        }
    }
}

/// Mod for util functions to handle AMD devices.
pub mod amd_device {

    // TODO: removeme once other todos addressed.
    #![allow(dead_code)]

    use anyhow::{bail, Context, Result};
    use glob::glob;
    use libchromeos::sys::{error, info};
    use std::fs;
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::path::{Path, PathBuf};

    pub struct AmdDeviceConfig {
        /// Device path gpu mode control (auto/manual).
        gpu_mode_path: PathBuf,

        /// Device path for setting system clock.
        sclk_mode_path: PathBuf,

        /// Device path for setting min and max clock.
        clk_voltage_path: PathBuf,
    }

    /// Device path for cpuinfo.
    const CPUINFO_PATH: &str = "/proc/cpuinfo";

    // Device node to manage GPU frequency range.
    const AMDGPU_DPM_FORCE_PERFORMANCE_LEVEL: &str = "power_dpm_force_performance_level";
    const AMDGPU_PP_DPM_SCLK: &str = "pp_dpm_sclk";
    const AMDGPU_PP_OD_CLK_VOLTAGE: &str = "pp_od_clk_voltage";

    #[derive(Clone, Copy, PartialEq)]
    enum AmdGpuMode {
        /// Auto mode ignores any system clock values.
        Auto,

        /// Manual mode will use any selected system clock value.  If a system clock wasn't explicitly selected, the system will use the last selected value or boot time default.
        Manual,
    }

    impl AmdDeviceConfig {
        /// Creates a new AMD device object which can be used to set system tuning parameters.
        ///
        /// # Arguments
        ///
        /// * `gpu_mode_path` - sysfs path for setting auto/manual control of AMD gpu.
        ///   This will typically be at
        ///   _/sys/class/drm/card0/device/power_dpm_force_performance_level_.
        ///
        /// * `sclk_mode_path` - sysfs path for setting system clock options of AMD gpu.
        ///   This will typically be at _/sys/class/drm/card0/device/pp_dpm_sclk_.
        ///
        /// * `clk_voltage_path` - sysfs path for setting system clock range of AMD gpu.
        ///   This will typically be at _/sys/class/drm/card0/device/pp_od_clvk_voltage_.
        ///
        /// # Return
        ///
        /// New AMD device object.
        pub fn new(
            gpu_mode_path: &str,
            sclk_mode_path: &str,
            clk_voltage_path: &str,
        ) -> AmdDeviceConfig {
            AmdDeviceConfig {
                gpu_mode_path: PathBuf::from(gpu_mode_path),
                sclk_mode_path: PathBuf::from(sclk_mode_path),
                clk_voltage_path: PathBuf::from(clk_voltage_path),
            }
        }

        /// Static function to check if device has a supported AMD GPU.
        ///
        /// # Return
        ///
        /// Boolean denoting if device has a supported AMD GPU.
        pub fn is_amd_device(&self) -> bool {
            return Path::new(&self.gpu_mode_path).exists()
                && Path::new(&self.sclk_mode_path).exists()
                && Path::new(&self.clk_voltage_path).exists();
        }

        /// Returns array of available sclk modes and the current selection.
        ///
        /// # Return
        ///
        /// Tuple with (`Vector of available system clks`, `currently selected system clk`).
        fn get_sclk_modes(&self) -> Result<(Vec<u32>, u32)> {
            let reader = File::open(PathBuf::from(&self.sclk_mode_path))
                .map(BufReader::new)
                .context("Couldn't read sclk config")?;

            self.parse_sclk(reader)
        }

        // Processing split out for unit testing.
        pub fn parse_sclk<R: BufRead>(&self, reader: R) -> Result<(Vec<u32>, u32)> {
            let mut sclks: Vec<u32> = vec![];
            let mut selected = 0;

            // Sample sclk file:
            // 0: 200Mhz
            // 1: 700Mhz *
            // 2: 1400Mhz
            for line in reader.lines() {
                let line = line?;
                let tokens: Vec<&str> = line.split_whitespace().collect();

                if tokens.len() > 1 {
                    if tokens[1].ends_with("Mhz") {
                        sclks.push(tokens[1].trim_end_matches("Mhz").parse::<u32>()?);
                    } else {
                        bail!("Could not parse sclk.");
                    }
                }

                // Selected frequency is denoted by '*', which adds a 3rd token
                if tokens.len() == 3 && tokens[2] == "*" {
                    selected = tokens[0].trim_end_matches(':').parse::<u32>()?;
                }
            }

            if sclks.is_empty() {
                bail!("No sys clk options found.");
            }

            Ok((sclks, selected))
        }

        /// Sets GPU mode on device (auto or manual).
        fn set_gpu_mode(&self, mode: AmdGpuMode) -> Result<()> {
            let mode_str = if mode == AmdGpuMode::Auto {
                "auto"
            } else {
                "manual"
            };
            fs::write(&self.gpu_mode_path, mode_str)?;
            Ok(())
        }

        /// Sets system clock to requested mode and changes GPU control to manual.
        ///
        /// # Arguments
        ///
        /// * `req_mode` - requested GPU system clock.  This will be an integer mapping to available sclk options.
        fn set_sclk_mode(&self, req_mode: u32) -> Result<()> {
            // Bounds check before trying to set sclk
            let (sclk_modes, selected) = self.get_sclk_modes()?;

            if req_mode < sclk_modes.len() as u32 && req_mode != selected {
                fs::write(&self.sclk_mode_path, req_mode.to_string())?;
            }
            Ok(())
        }

        fn set_clk_voltage_mode(&self, min: u32, max: u32) -> Result<()> {
            let min_str = format!("s 0 {}\n", min);
            let max_str = format!("s 1 {}\n", max);
            // setting the minimum frequency
            fs::write(&self.clk_voltage_path, min_str)?;
            // setting the maximum frequency
            fs::write(&self.clk_voltage_path, max_str)?;
            // committing the changes
            fs::write(&self.clk_voltage_path, "c\n")?;

            Ok(())
        }

        pub fn set_min_frequency(&self, val: u32) -> Result<()> {
            let (sclk_modes, _) = self.get_sclk_modes()?;

            let min = sclk_modes[0];
            let max = sclk_modes[sclk_modes.len() - 1];
            if val < min {
                error!("Invalid minimum clk voltage");
            }
            let min_freq = if val > max { max } else { val };

            self.set_clk_voltage_mode(min_freq, max)
        }
    }

    fn find_amd_dev_dir() -> Option<PathBuf> {
        let entries = match glob("/sys/class/drm/card*/device/power_dpm_force_performance_level") {
            Ok(entries) => entries,
            Err(_) => return None,
        };
        for entry in entries.flatten() {
            if let Some(dir) = entry.parent() {
                return Some(dir.to_path_buf());
            }
        }
        None
    }

    /// Function to create device
    ///
    /// # Return
    ///
    /// an AMD Device object that can be used to interface with the device.
    pub fn create_amd_device_config() -> Result<AmdDeviceConfig> {
        // TODO: add support for multi-GPU.

        let amd_dev_dir = find_amd_dev_dir().context("No AMD device detected")?;

        let concat_and_get_string = |file_name: &str| {
            return amd_dev_dir.join(file_name).display().to_string();
        };

        let gpu_mode_str = concat_and_get_string(AMDGPU_DPM_FORCE_PERFORMANCE_LEVEL);
        let sclk_mode_str = concat_and_get_string(AMDGPU_PP_DPM_SCLK);
        let clk_voltage_str = concat_and_get_string(AMDGPU_PP_OD_CLK_VOLTAGE);

        Ok(AmdDeviceConfig::new(
            &gpu_mode_str,
            &sclk_mode_str,
            &clk_voltage_str,
        ))
    }

    /// Init function to setup device, perform validity check, and set GPU
    /// control to manual if applicable.
    ///
    /// # Arguments
    ///
    /// * `dev` - AMD Device object.
    pub fn amd_sustained_mode_init(dev: &AmdDeviceConfig) -> Result<()> {
        if AmdDeviceConfig::is_amd_device(dev) {
            info!("Setting sclk for supported AMD device");
            dev.set_gpu_mode(AmdGpuMode::Manual)?;
            dev.set_sclk_mode(1)?;
        } else {
            info!("not amd device");
        }
        Ok(())
    }

    /// Cleanup function to return GPU to _auto_ mode if applicable.  Will force to auto sclk regardless of initial state or intermediate changes.
    ///
    /// # Arguments
    ///
    /// * `dev` - AMD Device object.
    pub fn amd_sustained_mode_cleanup(dev: &AmdDeviceConfig) -> Result<()> {
        if AmdDeviceConfig::is_amd_device(dev) {
            info!("Resetting GPU mode to `AUTO`");
            dev.set_gpu_mode(AmdGpuMode::Auto)?;
        } else {
            info!("not amd device");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use std::{path::PathBuf, thread, time::Duration};
    use tempfile::tempdir;

    use super::{intel_device::IntelGpuDeviceConfig, *};

    use crate::test_utils::tests::*;
    use crate::{
        common, cpu_scaling::DeviceCpuStatus, gpu_freq_scaling::amd_device::AmdDeviceConfig,
    };

    #[test]
    fn test_intel_malformed_root() {
        let _ = IntelGpuDeviceConfig::new(PathBuf::from("/bad_root"), 100).is_err();
    }

    #[test]
    fn test_intel_device_filter() {
        let tmp_root = tempdir().unwrap();
        let root = tmp_root.path();

        setup_mock_intel_gpu_dev_dirs(root);
        setup_mock_intel_gpu_files(root);

        // Wrong CPU
        write_mock_cpuinfo(
            root,
            "filter_out",
            "Intel(R) Core(TM) i3-10110U CPU @ 2.10GHz",
        );
        assert!(IntelGpuDeviceConfig::new(PathBuf::from(root), 100).is_err());

        // Wrong model
        write_mock_cpuinfo(
            root,
            "GenuineIntel",
            "Intel(R) Core(TM) i3-11110U CPU @ 2.10GHz",
        );
        assert!(IntelGpuDeviceConfig::new(PathBuf::from(root), 100).is_err());

        // Supported model
        write_mock_cpuinfo(
            root,
            "GenuineIntel",
            "Intel(R) Core(TM) i3-10110U CPU @ 2.10GHz",
        );
        assert!(IntelGpuDeviceConfig::new(PathBuf::from(root), 100).is_ok());
    }

    #[test]
    fn test_intel_tuning_table_ordering() {
        let tmp_root = tempdir().unwrap();
        let root = tmp_root.path();

        setup_mock_intel_gpu_dev_dirs(root);
        setup_mock_intel_gpu_files(root);
        write_mock_cpuinfo(
            root,
            "GenuineIntel",
            "Intel(R) Core(TM) i3-10110U CPU @ 2.10GHz",
        );

        let mock_gpu = IntelGpuDeviceConfig::new(PathBuf::from(root), 100).unwrap();

        let mut last_pl_thr: u64 = 0;
        for (i, &(pl_thr, _)) in mock_gpu.power_limit_thr.iter().enumerate() {
            if i == 0 {
                last_pl_thr = pl_thr;
                continue;
            }

            assert!(last_pl_thr > pl_thr);
            last_pl_thr = pl_thr;
        }
    }

    /// TODO: static atomicBool for thread duplication is persisting
    /// in unit test.  Fix before re-enabling
    #[test]
    #[ignore]
    fn test_intel_dynamic_gpu_adjust() {
        const POLLING_DELAY_MS: u64 = 4;
        const OP_LATCH_DELAY_MS: u64 = POLLING_DELAY_MS + 1;
        let tmp_root = tempdir().unwrap();
        let root = tmp_root.path();
        let power_manager = MockPowerPreferencesManager {};
        assert!(common::get_game_mode().unwrap() == common::GameMode::Off);
        common::set_game_mode(
            &power_manager,
            common::GameMode::Borealis,
            root.to_path_buf(),
        )
        .unwrap();
        assert!(common::get_game_mode().unwrap() == common::GameMode::Borealis);

        setup_mock_intel_gpu_dev_dirs(root);
        setup_mock_intel_gpu_files(root);
        write_mock_cpuinfo(
            root,
            "GenuineIntel",
            "Intel(R) Core(TM) i3-10110U CPU @ 2.10GHz",
        );

        assert!(IntelGpuDeviceConfig::new(PathBuf::from(root), POLLING_DELAY_MS).is_ok());
        assert!(get_intel_gpu_max(root) == 1000);
        assert!(get_intel_gpu_boost(root) == 1000);

        setup_mock_cpu_dev_dirs(root).unwrap();
        setup_mock_cpu_files(root).unwrap();
        write_mock_pl0(root, 15000000).unwrap();

        // Sanitize CPU object creation (used internally in GPU object)
        let mock_cpu_dev_res = DeviceCpuStatus::new(PathBuf::from(root));
        assert!(mock_cpu_dev_res.is_ok());

        intel_device::run_active_gpu_tuning_impl(root.to_path_buf(), POLLING_DELAY_MS).unwrap();
        // Initial sleep to latch init values
        thread::sleep(Duration::from_millis(OP_LATCH_DELAY_MS));

        // Check GPU clock down
        write_mock_pl0(root, 12000000).unwrap();
        thread::sleep(Duration::from_millis(OP_LATCH_DELAY_MS));
        assert!(get_intel_gpu_max(root) == 650);
        assert!(get_intel_gpu_boost(root) == 650);

        // Check same bucket, pl0 change
        write_mock_pl0(root, 11000000).unwrap();
        thread::sleep(Duration::from_millis(OP_LATCH_DELAY_MS));
        assert!(get_intel_gpu_max(root) == 650);
        assert!(get_intel_gpu_boost(root) == 650);

        // Check PL0 out of range (high)
        write_mock_pl0(root, 18000000).unwrap();
        thread::sleep(Duration::from_millis(OP_LATCH_DELAY_MS));
        assert!(get_intel_gpu_max(root) == 1000);
        assert!(get_intel_gpu_boost(root) == 1000);

        // Check PL0 out of range (low)
        write_mock_pl0(root, 8000000).unwrap();
        thread::sleep(Duration::from_millis(OP_LATCH_DELAY_MS));
        assert!(get_intel_gpu_max(root) == 650);
        assert!(get_intel_gpu_boost(root) == 650);

        // Check GPU clock up
        write_mock_pl0(root, 14000000).unwrap();
        thread::sleep(Duration::from_millis(OP_LATCH_DELAY_MS));
        assert!(get_intel_gpu_max(root) == 800);
        assert!(get_intel_gpu_boost(root) == 800);

        // Check frequency reset on game mode off
        common::set_game_mode(&power_manager, common::GameMode::Off, root.to_path_buf()).unwrap();
        thread::sleep(Duration::from_millis(OP_LATCH_DELAY_MS));
        assert!(get_intel_gpu_max(root) == 1000);
        assert!(get_intel_gpu_boost(root) == 1000);
    }

    #[test]
    fn test_amd_parse_sclk_valid() {
        let dev: AmdDeviceConfig = AmdDeviceConfig::new("mock_file", "mock_sclk", "mock_voltage");

        // trailing space is intentional, reflects sysfs output.
        let mock_sclk = r#"
0: 200Mhz
1: 700Mhz *
2: 1400Mhz "#;

        let (sclk, sel) = dev.parse_sclk(mock_sclk.as_bytes()).unwrap();
        assert_eq!(1, sel);
        assert_eq!(3, sclk.len());
        assert_eq!(200, sclk[0]);
        assert_eq!(700, sclk[1]);
        assert_eq!(1400, sclk[2]);
    }

    #[test]
    fn test_amd_parse_sclk_invalid() {
        let dev: AmdDeviceConfig = AmdDeviceConfig::new("mock_file", "mock_sclk", "mock_voltage");

        // trailing space is intentional, reflects sysfs output.
        let mock_sclk = r#"
0: nonint
1: 700Mhz *
2: 1400Mhz "#;
        assert!(dev.parse_sclk(mock_sclk.as_bytes()).is_err());
        assert!(dev.parse_sclk("nonint".to_string().as_bytes()).is_err());
        assert!(dev.parse_sclk("0: 1400 ".to_string().as_bytes()).is_err());
        assert!(dev.parse_sclk("0: 1400 *".to_string().as_bytes()).is_err());
        assert!(dev
            .parse_sclk("x: nonint *".to_string().as_bytes())
            .is_err());
    }
}
