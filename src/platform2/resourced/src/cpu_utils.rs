// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::{Context, Result};
use glob::glob;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::common;

#[derive(PartialEq, Eq)]
pub enum HotplugCpuAction {
    // Set all CPUs to online.
    OnlineAll,
    // Offline small CPUs if the device has big/little clusters. Otherwise
    // offline half of the CPUs if the device has >= 4 CPUs.
    OfflineHalf,
}

// Returns cpus string containing cpus with the minimal value of the property.
// The properties are read from /sys/bus/cpu/devices/cpu*/{property name}.
// E.g., this function returns "0,1" for the following cpu properties.
// | cpu # | property value |
// |-------|----------------|
// |   0   |       512      |
// |   1   |       512      |
// |   2   |      1024      |
// |   3   |      1024      |
fn get_cpus_with_min_property(root: &Path, property: &str) -> Result<String> {
    let cpu_pattern = root
        .join("sys/bus/cpu/devices/cpu*")
        .to_str()
        .context("Failed to construct cpu pattern string")?
        .to_owned();
    let cpu_pattern_prefix = root
        .join("sys/bus/cpu/devices/cpu")
        .to_str()
        .context("Failed to construct cpu path prefix")?
        .to_owned();

    let cpu_properties = glob(&cpu_pattern)?
        .map(|cpu_dir| {
            let cpu_dir = cpu_dir?;
            let cpu_number: u64 = cpu_dir
                .to_str()
                .context("Failed to convert cpu path to string")?
                .strip_prefix(&cpu_pattern_prefix)
                .context("Failed to strip prefix")?
                .parse()?;
            let property_path = Path::new(&cpu_dir).join(property);
            Ok((cpu_number, common::read_file_to_u64(property_path)?))
        })
        .collect::<Result<Vec<(u64, u64)>, anyhow::Error>>()?;
    let min_property = cpu_properties
        .iter()
        .map(|(_, prop)| prop)
        .min()
        .context("cpu properties vector is empty")?;
    let cpus = cpu_properties
        .iter()
        .filter(|(_, prop)| prop == min_property)
        .map(|(cpu, _)| cpu.to_string())
        .collect::<Vec<String>>()
        .join(",");
    Ok(cpus)
}

pub fn get_little_cores(root: &Path) -> Result<String> {
    if !is_big_little_supported(root)? {
        return get_cpuset_all_cpus(root);
    }

    let cpu0_capacity = root.join("sys/bus/cpu/devices/cpu0/cpu_capacity");

    if cpu0_capacity.exists() {
        // If cpu0/cpu_capacity exists, all cpus should have the cpu_capacity file.
        get_cpus_with_min_property(root, "cpu_capacity")
    } else {
        get_cpus_with_min_property(root, "cpufreq/cpuinfo_max_freq")
    }
}

pub fn is_big_little_supported(root: &Path) -> Result<bool> {
    const UI_USE_FLAGS_PATH: &str = "etc/ui_use_flags.txt";
    let reader = BufReader::new(std::fs::File::open(root.join(UI_USE_FLAGS_PATH))?);
    for line in reader.lines() {
        if line? == "big_little" {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn get_cpuset_all_cpus(root: &Path) -> Result<String> {
    const ROOT_CPUSET_CPUS: &str = "sys/fs/cgroup/cpuset/cpus";
    let root_cpuset_cpus = root.join(ROOT_CPUSET_CPUS);
    std::fs::read_to_string(root_cpuset_cpus).context("Failed to get root cpuset cpus")
}

// Change a group of CPU online status through sysfs.
// * `cpus_fmt` -  The format string of the target CPUs in either of the format:
//   1. a list separated by comma (,). e.g. 0,1,2,3 to set CPU 0,1,2,3
//   2. a range represented by hyphen (-). e.g. 0-3 to set CPU 0,1,2,3
// * `online` - Set true to online CUPs. Set false to offline CPUs.
fn update_cpu_online_status(root: &Path, cpus_fmt: &str, online: bool) -> Result<()> {
    let online_value = if online { "1" } else { "0" };
    let range_parts: Vec<&str> = cpus_fmt.split('-').collect();
    let mut cpus = Vec::new();
    if range_parts.len() == 2 {
        if let (Ok(start), Ok(end)) = (range_parts[0].trim().parse(), range_parts[1].trim().parse())
        {
            cpus = (start..=end).collect();
        }
    } else {
        cpus = cpus_fmt
            .split(',')
            .map(|value| value.trim().parse::<i32>())
            .filter_map(Result::ok)
            .collect();
    }

    for cpu in cpus {
        let pattern = format!("sys/devices/system/cpu/cpu{}/online", cpu);
        let cpu_path = root.join(pattern);

        if cpu_path.exists() {
            std::fs::write(cpu_path, online_value.as_bytes())?;
        }
    }

    Ok(())
}

fn hotplug_cpus_impl(root: &Path, action: HotplugCpuAction) -> Result<()> {
    match action {
        HotplugCpuAction::OnlineAll => {
            let all_cores: String = get_cpuset_all_cpus(root)?;
            update_cpu_online_status(root, &all_cores, true)?;
        }
        HotplugCpuAction::OfflineHalf => {
            if is_big_little_supported(root)? {
                let little_cores: String = get_little_cores(root)?;
                update_cpu_online_status(root, &little_cores, false)?;
            } else {
                let num_cores: i32 = get_cpuset_all_cpus(root)?
                    .split('-')
                    .last()
                    .context("can't get number of cores")?
                    .trim()
                    .parse()?;
                if num_cores >= 3 {
                    update_cpu_online_status(
                        root,
                        &format!("{}-{}", (num_cores / 2) + 1, num_cores),
                        false,
                    )?;
                }
            }
        }
    }

    Ok(())
}

pub fn hotplug_cpus(action: HotplugCpuAction) -> Result<()> {
    let root = Path::new("/");
    hotplug_cpus_impl(root, action)
}

#[cfg(test)]
mod tests {
    use crate::test_utils::tests::*;
    use tempfile::TempDir;

    use super::*;

    fn test_write_online_cpu(root: &Path, cpu: u32, value: &str) {
        let root_online_cpu = root.join(format!("sys/devices/system/cpu/cpu{}/online", cpu));
        test_create_parent_dir(&root_online_cpu);
        std::fs::write(root_online_cpu, value).unwrap();
        println!("create {}", cpu)
    }

    fn test_check_online_cpu(root: &Path, cpu: u32, expected: &str) {
        let root_online_cpu = root.join(format!("sys/devices/system/cpu/cpu{}/online", cpu));
        test_create_parent_dir(&root_online_cpu);
        let value = std::fs::read_to_string(root_online_cpu).unwrap();
        assert_eq!(value, expected);
    }

    #[test]
    fn test_hotplug_cpus() {
        // Setup.
        let root = TempDir::new().unwrap();
        test_write_cpuset_root_cpus(root.path(), "0-11");
        test_write_ui_use_flags(root.path(), "big_little");
        for i in 0..8 {
            test_write_online_cpu(root.path(), i, "1");
            test_write_cpu_max_freq(root.path(), i, 2400000);
        }
        for i in 8..12 {
            test_write_online_cpu(root.path(), i, "1");
            test_write_cpu_max_freq(root.path(), i, 1800000);
        }

        // Call function to test.
        hotplug_cpus_impl(root.path(), HotplugCpuAction::OfflineHalf).unwrap();

        // Check result.
        for i in 0..8 {
            test_check_online_cpu(root.path(), i, "1");
        }

        for i in 8..12 {
            test_check_online_cpu(root.path(), i, "0");
        }
    }
}
