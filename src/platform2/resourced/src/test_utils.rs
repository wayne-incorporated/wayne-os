// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(test)]
pub(crate) mod tests {
    use anyhow::Result;
    use std::fs;
    use std::path::Path;
    use std::path::PathBuf;
    use std::str;

    use crate::common::{BatterySaverMode, FullscreenVideo, GameMode, RTCAudioActive, VmBootMode};
    use crate::power;

    const MOCK_NUM_CPU: i32 = 16;

    pub const CPUINFO_PATH: &str = "proc/cpuinfo";
    /// Base path for power_limit relative to rootdir.
    pub const DEVICE_POWER_LIMIT_PATH: &str = "sys/class/powercap/intel-rapl:0";

    /// Base path for cpufreq relative to rootdir.
    pub const DEVICE_CPUFREQ_PATH: &str = "sys/devices/system/cpu/cpufreq";

    // Device path for GPU card.
    pub const GPU0_DEVICE_PATH: &str = "sys/class/drm/card0";

    pub struct MockPowerPreferencesManager {}
    impl power::PowerPreferencesManager for MockPowerPreferencesManager {
        fn update_power_preferences(
            &self,
            _rtc: RTCAudioActive,
            _fullscreen: FullscreenVideo,
            _game: GameMode,
            _vmboot: VmBootMode,
            _batterysaver: BatterySaverMode,
        ) -> Result<()> {
            Ok(())
        }
    }

    pub fn test_create_parent_dir(path: &Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    }

    pub fn test_write_ui_use_flags(root: &Path, use_flags: &str) {
        let use_flags_path = root.join("etc/ui_use_flags.txt");
        test_create_parent_dir(&use_flags_path);
        std::fs::write(use_flags_path, use_flags).unwrap();
    }

    pub fn test_write_cpuset_root_cpus(root: &Path, cpus: &str) {
        let root_cpuset_cpus = root.join("sys/fs/cgroup/cpuset/cpus");
        test_create_parent_dir(&root_cpuset_cpus);
        std::fs::write(root_cpuset_cpus, cpus).unwrap();
    }

    pub fn test_write_cpu_max_freq(root: &Path, cpu_num: u32, max_freq: u32) {
        let cpu_max_path = root.join(format!(
            "sys/bus/cpu/devices/cpu{}/cpufreq/cpuinfo_max_freq",
            cpu_num
        ));
        test_create_parent_dir(&cpu_max_path);
        std::fs::write(cpu_max_path, max_freq.to_string()).unwrap();
    }

    pub fn write_mock_pl0(root: &Path, value: u64) -> Result<()> {
        std::fs::write(
            root.join(DEVICE_POWER_LIMIT_PATH)
                .join("constraint_0_power_limit_uw"),
            value.to_string(),
        )?;

        Ok(())
    }

    pub fn write_mock_cpu(
        root: &Path,
        cpu_num: i32,
        baseline_max: u64,
        curr_max: u64,
        baseline_min: u64,
        curr_min: u64,
    ) -> Result<()> {
        let policy_path = root
            .join(DEVICE_CPUFREQ_PATH)
            .join(format!("policy{cpu_num}"));
        std::fs::write(
            policy_path.join("cpuinfo_max_freq"),
            baseline_max.to_string(),
        )
        .expect("Failed to write to file!");
        std::fs::write(
            policy_path.join("cpuinfo_min_freq"),
            baseline_min.to_string(),
        )
        .expect("Failed to write to file!");

        std::fs::write(policy_path.join("scaling_max_freq"), curr_max.to_string())?;
        std::fs::write(policy_path.join("scaling_min_freq"), curr_min.to_string())?;
        Ok(())
    }

    pub fn setup_mock_cpu_dev_dirs(root: &Path) -> anyhow::Result<()> {
        fs::create_dir_all(root.join(DEVICE_POWER_LIMIT_PATH))?;
        for i in 0..MOCK_NUM_CPU {
            fs::create_dir_all(root.join(DEVICE_CPUFREQ_PATH).join(format!("policy{i}")))?;
        }
        Ok(())
    }

    pub fn get_cpu0_freq_max(root: &Path) -> i32 {
        let policy_path = root.join(DEVICE_CPUFREQ_PATH).join("policy0");
        let read_val = std::fs::read(policy_path.join("scaling_max_freq")).unwrap();

        std::str::from_utf8(&read_val)
            .unwrap()
            .parse::<i32>()
            .unwrap()
    }

    pub fn get_cpu0_freq_min(root: &Path) -> i32 {
        let policy_path = root.join(DEVICE_CPUFREQ_PATH).join("policy0");
        let read_val = std::fs::read(policy_path.join("scaling_min_freq")).unwrap();

        str::from_utf8(&read_val).unwrap().parse::<i32>().unwrap()
    }

    pub fn setup_mock_cpu_files(root: &Path) -> Result<()> {
        let pl_files: Vec<&str> = vec![
            "constraint_0_power_limit_uw",
            "constraint_0_max_power_uw",
            "constraint_1_power_limit_uw",
            "constraint_1_max_power_uw",
            "energy_uj",
            "max_energy_range_uj",
        ];

        let cpufreq_files: Vec<(&str, &str)> = vec![
            ("scaling_max_freq", "4100000"),
            ("cpuinfo_max_freq", "4100000"),
            ("scaling_min_freq", "400000"),
            ("cpuinfo_min_freq", "400000"),
            ("base_frequency", "2100000"),
        ];

        for pl_file in &pl_files {
            std::fs::write(
                root.join(DEVICE_POWER_LIMIT_PATH)
                    .join(PathBuf::from(pl_file)),
                "0",
            )?;
        }

        for i in 0..MOCK_NUM_CPU {
            let policy_path = root.join(DEVICE_CPUFREQ_PATH).join(format!("policy{i}"));

            for cpufreq_file in &cpufreq_files {
                std::fs::write(policy_path.join(cpufreq_file.0), cpufreq_file.1)?;
            }
        }

        Ok(())
    }

    pub fn construct_poc_cpuinfo_snippet(vendor: &str, model_name: &str) -> String {
        format!(
            r#"
processor       : 0
vendor_id       : {vendor}
cpu family      : 23
model           : 24
model name      : {model_name}
stepping        : 1
microcode       : 0x8108109

processor       : 1
vendor_id       : {vendor}
cpu family      : 25
model           : 24
model name      : {model_name}"#
        )
    }

    pub fn write_mock_cpuinfo(root: &Path, vendor: &str, model_name: &str) {
        fs::write(
            root.join(CPUINFO_PATH),
            construct_poc_cpuinfo_snippet(vendor, model_name),
        )
        .unwrap();
    }

    pub fn setup_mock_intel_gpu_dev_dirs(root: &Path) {
        fs::create_dir_all(root.join(CPUINFO_PATH).parent().unwrap()).unwrap();
        fs::create_dir_all(root.join(GPU0_DEVICE_PATH)).unwrap();
    }

    pub fn setup_mock_intel_gpu_files(root: &Path) {
        let gpu_files = vec![
            ("gt_min_freq_mhz", 200),
            ("gt_max_freq_mhz", 1000),
            ("gt_boost_freq_mhz", 1000),
        ];

        for (gpu_file, default_freq) in &gpu_files {
            fs::write(
                root.join(GPU0_DEVICE_PATH).join(PathBuf::from(gpu_file)),
                default_freq.to_string(),
            )
            .unwrap();
        }
    }

    pub fn get_intel_gpu_max(root: &Path) -> i32 {
        let gpu_max_path = root.join(GPU0_DEVICE_PATH).join("gt_max_freq_mhz");
        let read_val = std::fs::read(gpu_max_path).unwrap();
        str::from_utf8(&read_val).unwrap().parse::<i32>().unwrap()
    }

    pub fn get_intel_gpu_boost(root: &Path) -> i32 {
        let gpu_max_path = root.join(GPU0_DEVICE_PATH).join("gt_boost_freq_mhz");
        let read_val = std::fs::read(gpu_max_path).unwrap();
        str::from_utf8(&read_val).unwrap().parse::<i32>().unwrap()
    }
}
