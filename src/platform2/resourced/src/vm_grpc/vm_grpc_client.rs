// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::{bail, Result};
use futures_executor::block_on;
use grpcio::{CallOption, ChannelBuilder, EnvBuilder};
use libchromeos::sys::{debug, info, warn};
use protobuf::RepeatedField;

use crate::cpu_scaling::DeviceCpuStatus;
use crate::vm_grpc::proto::resourced_bridge::{CpuInfoCoreData, CpuInfoData, CpuRaplPowerData};
use crate::vm_grpc::proto::resourced_bridge_grpc::ResourcedCommClient;

// Polling interval used when checking if connection is alive.
const CONN_POLLING_INTERVAL_SEC: u64 = 1;

// Total time to retry a dropped connection before aborting.
const CONN_TIMEOUT_SEC: u64 = 1;

// Default heartbeat message time delay in ms.
const DEFAULT_MESSAGE_TIME_MS: i64 = 5000;

/// Object that packages Client functionality.
///
/// `vm_content_id`: CID of the VM to listen for.
///
/// `client`: Object that holds GRPC client functionality.
///
/// `batt_dev`: Object that holds battery functionality.
///
/// `batt_dev`: Object that holds cpu functionality
///
/// `default_sleep_time_ms`: Default thread polling time in milliseconds.
///             This value will be overwritten by the guest GRPC client
///             at runtime.
///
/// # Return: None
pub(crate) struct VmGrpcClient {
    vm_content_id: i16,
    client: ResourcedCommClient,
    cpu_dev: DeviceCpuStatus,
    default_sleep_time_ms: u64,
    root_path: PathBuf,
}

impl VmGrpcClient {
    /// Starts the host-side GRPC client thread.
    /// This function will start a new grpc server instance on a
    /// separate thread and listen for incoming traffic on the given `vsock` ports.
    ///
    /// `vm_content_id`: CID of the VM to listen for.
    ///
    /// `port`: port for all incoming traffic.
    ///
    /// `root`: root path relative to sysfs.
    ///
    /// `pkt_tx_interval`: Arc<AtomicI64> that will be shared with server thread.
    ///             Server will modify this value based on VM request.  Client
    ///             will use this value to set the update interval of host metric
    ///             packets.  Client can also modify this value in case client detects
    ///             crash in the guest VM GRPC server.
    ///
    /// # Return
    ///
    /// Result of starting the thread.  Will return an error if thread is already running.
    /// TODO: Include and `Arc` object for thread control/exit.
    pub fn run(
        vm_content_id: i16,
        port: u16,
        root: &Path,
        pkt_tx_interval: Arc<AtomicI64>,
    ) -> Result<()> {
        // Ensure only 1 client thread can run.
        static CLIENT_THREAD_RUNNING: AtomicBool = AtomicBool::new(false);

        if !CLIENT_THREAD_RUNNING.load(Ordering::Relaxed) {
            CLIENT_THREAD_RUNNING.store(true, Ordering::Relaxed)
        } else {
            bail!("Client thread already running, ignoring run request");
        }

        // Create the client object for the internal thread.
        let client = VmGrpcClient::create_vm_rpc_client(vm_content_id, port)?;
        let cpu_dev = DeviceCpuStatus::new(root.to_path_buf())?;
        let default_sleep_time_ms: u64 = 100;

        let grpc_client = VmGrpcClient {
            vm_content_id,
            client,
            cpu_dev,
            default_sleep_time_ms,
            root_path: root.to_path_buf(),
        };

        thread::spawn(
            move || match grpc_client.grpc_client_main(pkt_tx_interval) {
                Ok(_) => info!("GRPC client thread exit successfully"),
                Err(e) => {
                    warn!("GRPC Client thread exit unexpectedly: {}", e);
                    CLIENT_THREAD_RUNNING.store(false, Ordering::Relaxed);
                    // TODO: If client drops, stop the server also.
                }
            },
        );

        Ok(())
    }

    fn grpc_client_main(&self, pkt_tx_interval: Arc<AtomicI64>) -> Result<()> {
        info!("Grpc client main loop");

        let mut consecutive_fail = 0;
        let mut sleep_time_ms: u64;

        let mut msg_time_ms: i64 = DEFAULT_MESSAGE_TIME_MS;

        // Blocking wait until socket connection can be made
        if self.wait_for_connection(CONN_POLLING_INTERVAL_SEC, CONN_TIMEOUT_SEC) {
            self.send_vm_init()?;
            info!("Init payload sent!");
        } else {
            pkt_tx_interval.store(-1, Ordering::Relaxed);
            bail!(
                "Could not establish connection with guest Vm after {} seconds",
                CONN_TIMEOUT_SEC
            );
        }

        loop {
            // Buffer the pkt_tx_interval value to avoid multiple atomic reads.
            let packet_tx_interval_buf: i64 = pkt_tx_interval.load(Ordering::Relaxed);

            // CPU update block: If guest-side grpc client needs CPU updates, it will
            // send a START_CPU_UPDATE RPC request to host-side server.  Host-server
            // changes the pkt_tx_interval to the requested value, and this client block
            // will send out updates at that frequency.
            if packet_tx_interval_buf > 0 {
                match self.send_cpu_update() {
                    Ok(_) => consecutive_fail = 0,
                    Err(_) => consecutive_fail += 1,
                }

                // ~1s of retries in AC mode before declaring connection dropped
                if consecutive_fail > CONN_TIMEOUT_SEC as i64 * 1000 / packet_tx_interval_buf {
                    warn!(
                        "Could not send CPU updates for {:?} sec. Guest connection likely dropped",
                        CONN_TIMEOUT_SEC
                    );
                    warn!("Stopping new updates and reseting CPU freq.");

                    pkt_tx_interval.store(-1, Ordering::Relaxed);
                    // Will fall into no CPU update block, fail ping check and reset there
                    // (after 100ms, forced with msg_time reset)
                    msg_time_ms = 0;
                    consecutive_fail = 0;
                    sleep_time_ms = self.default_sleep_time_ms;
                } else {
                    sleep_time_ms = packet_tx_interval_buf as u64;
                }
            } else {
                // Reduce idle log spam and ping connection to once/5sec
                // (when not actively sending CPU packets)
                if msg_time_ms <= 0 {
                    let connection_alive = self.vm_connection_is_alive();
                    debug!(
                        "{}ms poll.  connection_alive:{}",
                        self.default_sleep_time_ms, connection_alive
                    );

                    if !connection_alive {
                        warn!("Connection to guest VM died.  Reset CPU frequencies.");
                        self.cpu_dev.reset_all_max_min_cpu_freq()?;

                        // Blocking wait on this thread until socket connection can be made.
                        if self.wait_for_connection(CONN_POLLING_INTERVAL_SEC, CONN_TIMEOUT_SEC) {
                            self.send_vm_init()?;
                            info!("Init payload sent again!");
                        } else {
                            bail!(
                                "Could not re-establish connection with guest Vm {} seconds",
                                CONN_TIMEOUT_SEC
                            );
                        }
                    }

                    msg_time_ms = DEFAULT_MESSAGE_TIME_MS;
                } else {
                    msg_time_ms -= self.default_sleep_time_ms as i64;
                }
                sleep_time_ms = self.default_sleep_time_ms;
            }

            thread::sleep(Duration::from_millis(sleep_time_ms));
        }
    }

    fn create_vm_rpc_client(vm_content_id: i16, port: u16) -> Result<ResourcedCommClient> {
        let env = Arc::new(EnvBuilder::new().build());
        let addr = format!("vsock:{}:{}", vm_content_id, port);

        info!("Client on address {}", addr);
        let ch = ChannelBuilder::new(env).connect(&addr);
        Ok(ResourcedCommClient::new(ch))
    }

    // TODO: make pub so main.rs can do a quick sanity check
    fn vm_connection_is_alive(&self) -> bool {
        let env = Arc::new(EnvBuilder::new().build());
        let addr = format!("vsock:{}:5553", self.vm_content_id);
        let ch = ChannelBuilder::new(env).connect(&addr);

        // Give 1 sec to respond, should be plenty of time
        futures_executor::block_on(ch.wait_for_connected(Duration::from_secs(1)));
        let c_state_after = ch.check_connectivity_state(true);

        matches!(c_state_after, grpcio::ConnectivityState::GRPC_CHANNEL_READY)
    }

    fn wait_for_connection(&self, poll_increment_s: u64, timeout_s: u64) -> bool {
        let mut total_time_s = 0;
        while !self.vm_connection_is_alive() {
            debug!("ping vm server...");
            thread::sleep(Duration::from_secs(poll_increment_s));
            total_time_s += poll_increment_s;

            if total_time_s >= timeout_s {
                return false;
            }
        }
        true
    }

    fn get_cpu_info_data(&self) -> Result<CpuInfoData> {
        let data = self
            .cpu_dev
            .get_static_cpu_info(self.root_path.to_owned())?;
        let mut cpu_info_data = CpuInfoData::default();
        let mut all_core_data: RepeatedField<CpuInfoCoreData> = RepeatedField::new();

        for core in data {
            let mut core_data = CpuInfoCoreData::default();
            let core_num: i64 = core.core_num;
            core_data.set_core_num(core_num);
            core_data.set_cpu_freq_base_khz(core.base_freq_khz);
            core_data.set_cpu_freq_curr_khz(
                self.cpu_dev
                    .get_core_curr_freq_khz(self.root_path.to_owned(), core_num)?,
            );
            core_data.set_cpu_freq_max_khz(core.max_freq_khz);
            core_data.set_cpu_freq_min_khz(core.min_freq_khz);

            all_core_data.push(core_data);
        }

        cpu_info_data.set_cpu_core_data(all_core_data);

        Ok(cpu_info_data)
    }

    // TODO: make pub so main thread can send this on conn reestablish
    fn send_vm_init(&self) -> Result<()> {
        let req = self.get_cpu_info_data()?;

        info!("Core data sent to Vm");
        // Propagate error up the stack to count multiple failures and retry if needed.
        let options = CallOption::default()
            .wait_for_ready(true)
            .timeout(Duration::from_secs(1));
        let _reply = block_on(self.client.vm_init_data_async_opt(&req, options)?)?;

        Ok(())
    }

    fn send_cpu_update(&self) -> Result<()> {
        let mut req = CpuRaplPowerData::default();
        //FIXME: PL0_max reading from sysfs is broken, need to get it from /sys/bus/.. (b/214262504)
        req.set_power_limit_0(self.cpu_dev.get_pl0_curr()? as i64);
        req.set_power_limit_1(self.cpu_dev.get_pl1_curr()? as i64);
        req.set_cpu_energy(self.cpu_dev.get_energy_curr()? as i64);

        // TODO: 100ms update prints, maybe too spammy?  Aggregate to
        // every 10th if too spammy.
        debug!(
            "CPU update: pl0 {}/{}, energy {}/{}",
            req.get_power_limit_0(),
            self.cpu_dev.get_pl0_max()?,
            req.get_cpu_energy(),
            self.cpu_dev.get_energy_max()?
        );

        //Propagate error up the stack to count multiple failures.
        let _reply = self.client.cpu_power_update(&req)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};
    use tempfile::tempdir;

    #[test]
    fn test_client_create() {
        // Unit Testing is limited in this module without bringing up a full server.
        // Only checking init sequence.
        // TODO: stub out client/server interactions or add integration test.
        let root = tempdir().unwrap();

        setup_mock_cpu_dev_dirs(root.path());
        setup_mock_files(root.path());
        for cpu in 0..MOCK_NUM_CPU {
            write_mock_cpu(root.path(), cpu, 3200000, 3000000, 400000, 1000000);
        }
        setup_mock_battery_files(root.path());

        let pkt_tx_interval = std::sync::Arc::new(AtomicI64::new(-2));
        let pkt_tx_interval_clone = pkt_tx_interval.clone();
        let s = VmGrpcClient::run(32, 5555, Path::new(root.path()), pkt_tx_interval);

        // Test that client attempted to send vm_init.
        assert!(s.is_ok());

        // Test that second invoke fails
        let s2 = VmGrpcClient::run(32, 5555, Path::new(root.path()), pkt_tx_interval_clone);
        assert!(s2.is_err());
    }

    /// Base path for power_limit relative to rootdir.
    const DEVICE_POWER_LIMIT_PATH: &str = "sys/class/powercap/intel-rapl:0";

    /// Base path for cpufreq relative to rootdir.
    const DEVICE_CPUFREQ_PATH: &str = "sys/devices/system/cpu/cpufreq";

    const DEVICE_BATTERY_PATH: &str = "sys/class/power_supply/BAT0";

    const MOCK_NUM_CPU: i32 = 8;

    fn write_mock_cpu(
        root: &Path,
        cpu_num: i32,
        baseline_max: u64,
        curr_max: u64,
        baseline_min: u64,
        curr_min: u64,
    ) {
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

        std::fs::write(policy_path.join("scaling_max_freq"), curr_max.to_string()).unwrap();
        std::fs::write(policy_path.join("scaling_min_freq"), curr_min.to_string()).unwrap();
    }

    fn setup_mock_cpu_dev_dirs(root: &Path) {
        fs::create_dir_all(root.join(DEVICE_POWER_LIMIT_PATH)).unwrap();
        for i in 0..MOCK_NUM_CPU {
            fs::create_dir_all(root.join(DEVICE_CPUFREQ_PATH).join(format!("policy{i}"))).unwrap();
        }
    }

    fn setup_mock_files(root: &Path) {
        let pl_files: Vec<&str> = vec![
            "constraint_0_power_limit_uw",
            "constraint_0_max_power_uw",
            "constraint_1_power_limit_uw",
            "constraint_1_max_power_uw",
            "energy_uj",
            "max_energy_range_uj",
        ];

        let cpufreq_files: Vec<&str> = vec!["scaling_max_freq", "cpuinfo_max_freq"];

        for pl_file in &pl_files {
            std::fs::write(
                root.join(DEVICE_POWER_LIMIT_PATH)
                    .join(PathBuf::from(pl_file)),
                "0",
            )
            .unwrap();
        }

        for i in 0..MOCK_NUM_CPU {
            let policy_path = root.join(DEVICE_CPUFREQ_PATH).join(format!("policy{i}"));

            for cpufreq_file in &cpufreq_files {
                std::fs::write(policy_path.join(PathBuf::from(cpufreq_file)), "0").unwrap();
            }
        }
    }

    fn setup_mock_battery_files(root: &Path) {
        fs::create_dir_all(root.join(DEVICE_BATTERY_PATH)).unwrap();
        std::fs::write(root.join(DEVICE_BATTERY_PATH).join("status"), "Full").unwrap();
        std::fs::write(root.join(DEVICE_BATTERY_PATH).join("charge_now"), "100").unwrap();
        std::fs::write(root.join(DEVICE_BATTERY_PATH).join("charge_full"), "100").unwrap();
    }
}
