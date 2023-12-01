// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Metric reporting daemon to collect disk I/O stats from /proc/vmstat and report them via garcon

/// This program polls the /proc/vmstats file in order to report disk / swap
/// usage. At the time of this writing, vmstats are not namespaced to the
/// container, so we will capture them for the entire termina VM. In order to
/// avoid duplication (e.g. if there are multiple containers running) we check
/// if we are running inside the default 'penguin' container, based on
/// /etc/hostname.
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::process::Command;
use std::thread;
use std::time::Duration;

use argh::FromArgs;
use log::{debug, info};
use stderrlog::StdErrLog;

const VMSTAT_FILE: &str = "/proc/vmstat";
const HOSTNAME_FILE: &str = "/etc/hostname";
const CROSTINI_HOSTNAME: &str = "penguin";
const INTERVAL_SECONDS: u64 = 5 * 60;

fn parse_vmstat(reader: impl BufRead) -> HashMap<&'static str, u64> {
    let mut vmstat: HashMap<&str, u64> = HashMap::new();
    for maybe_line in reader.lines() {
        if let Ok(line) = maybe_line {
            if let Some((vmstat_key, value)) = line.split_once(' ') {
                if let Some(metric_key) = match vmstat_key {
                    "pswpin" => Some("crostini-swap-kb-read"),
                    "pswpout" => Some("crostini-swap-kb-written"),
                    "pgpgin" => Some("crostini-disk-kb-read"),
                    "pgpgout" => Some("crostini-disk-kb-written"),
                    _ => None, // don't care about this vmstat key
                } {
                    if let Ok(int_val) = value.parse() {
                        vmstat.insert(metric_key, int_val);
                    }
                }
            }
        }
    }
    debug!("Values from /proc/vmstat: {:?}", vmstat);
    vmstat
}

fn read_vmstat() -> impl BufRead {
    let file = File::open(VMSTAT_FILE).expect("should have been able to read /proc/vmstat");
    BufReader::new(file)
}

fn send_metrics(metrics: &Vec<String>) -> () {
    let mut cmd = Command::new("/opt/google/cros-containers/bin/garcon");
    cmd.arg("--client")
        .arg("--metrics")
        .arg(metrics.join(",").as_str());

    debug!("Calling: {:?}", cmd.get_args());

    match cmd.status() {
        Ok(exit_status) => {
            if let Some(code) = exit_status.code() {
                if code != 0 {
                    debug!("failed to send metrics via garcon, return code: {}", code);
                }
            } else {
                if !exit_status.success() {
                    debug!("failed to send metrics via garcon, status: {}", exit_status);
                }
            }
        }
        Err(e) => {
            debug!("failed to send metrics via garcon: {}", e);
        }
    };
}

fn calculate_diff(
    vmstat: &HashMap<&'static str, u64>,
    last_stat: &HashMap<&'static str, u64>,
) -> Vec<String> {
    let mut metrics: Vec<String> = Vec::new();

    if last_stat.is_empty() {
        return metrics;
    }

    for key in vmstat.keys() {
        if let (Some(&vmstat_val), Some(&last_stat_val)) = (vmstat.get(key), last_stat.get(key)) {
            if let Some(diff) = vmstat_val.checked_sub(last_stat_val) {
                debug!("Incremental activity - {}: {}", key, diff);
                if diff != 0 {
                    // We report metric value in KiB, multiply by 4 to convert from
                    // /proc/vmstat counts, which are 4096-byte page-sized blocks
                    let metric_diff_kb = diff * 4;
                    metrics.push(format!("{key}={metric_diff_kb}"));
                }
            }
        }
    }
    metrics
}

fn collect_and_report_metrics_forever(testonly_single_run: bool) {
    info!("Crostini metric reporter started");
    let mut last_stat = HashMap::new();
    loop {
        let vmstat = parse_vmstat(read_vmstat());
        let metrics: Vec<String> = calculate_diff(&vmstat, &last_stat);

        if testonly_single_run {
            break;
        }
        if !metrics.is_empty() {
            send_metrics(&metrics);
        }
        last_stat = vmstat;

        thread::sleep(Duration::from_secs(INTERVAL_SECONDS));
    }
}

fn in_crostini_container() -> bool {
    let contents =
        fs::read_to_string(HOSTNAME_FILE).expect("should have been able to read /etc/hostname");
    contents.contains(CROSTINI_HOSTNAME)
}

#[derive(FromArgs)]
/// Command line arguments
struct Args {
    /// only run one loop for testing
    #[argh(switch, short = 't')]
    test_single_run: bool,

    /// enable verbose logging
    #[argh(switch, short = 'v')]
    verbose: bool,

    /// run outside of crostini
    #[argh(switch)]
    run_outside_crostini: bool,
}

fn main() {
    let args: Args = argh::from_env();

    if !args.run_outside_crostini && !in_crostini_container() {
        println!("metrics_reporter must only be run inside the crostini container, bailing");
        return;
    }

    let verbosity = match args.verbose {
        false => 2,
        true => 5,
    };

    if let Err(e) = StdErrLog::new().verbosity(verbosity).init() {
        eprintln!("failed to init syslog: {}", e);
        return;
    }

    collect_and_report_metrics_forever(args.test_single_run);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_vmstat() {
        let vmstat = "oom_kill 0\n\
        pswpin 0\n\
        pswpout 0\n\
        nr_dirty_threshold 11569432\n\
        nr_dirty_background_threshold 5777653\n\
        pgpgin 34269030\n\
        pgpgout 73709632";
        let vmstat = parse_vmstat(vmstat.as_bytes());
        for src in ["disk", "swap"] {
            for rw in ["read", "written"] {
                assert!(vmstat.contains_key(format!("crostini-{src}-kb-{rw}").as_str()) == true);
            }
        }
    }

    #[test]
    fn test_calculate_diff() {
        let vmstat: HashMap<&str, u64> = HashMap::from([
            ("pswpin", 123),
            ("pswpout", 456),
            ("pgpgin", 789),
            ("pgpgout", 1000),
        ]);
        let last_stat: HashMap<&str, u64> = HashMap::from([
            ("pswpin", 23),
            ("pswpout", 256),
            ("pgpgin", 489),
            ("pgpgout", 600),
        ]);
        let mut metrics: Vec<String> = calculate_diff(&vmstat, &last_stat);
        assert_eq!(
            metrics.sort(),
            vec![
                "crostini-disk-kb-read=1200",
                "crostini-disk-kb-written=1600",
                "crostini-swap-kb-read=400",
                "crostini-swap-kb-written=800"
            ]
            .sort()
        );
    }
}
