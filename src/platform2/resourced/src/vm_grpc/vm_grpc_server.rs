// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::{bail, Result};
use futures_util::future::{FutureExt as _, TryFutureExt as _};
use grpcio::{ChannelBuilder, Environment, ResourceQuota, RpcContext, ServerBuilder, UnarySink};
use libchromeos::sys::{error, info, warn};
use protobuf::RepeatedField;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::cpu_scaling::DeviceCpuStatus;
use crate::vm_grpc::proto::resourced_bridge::{
    CpuInfoCoreData, CpuInfoData, EmptyMessage, RequestedInterval, ReturnCode, ReturnCode_Status,
};
use crate::vm_grpc::proto::resourced_bridge_grpc::{
    create_resourced_comm_listener, ResourcedCommListener,
};
use crate::vm_grpc::vm_grpc_util::{vm_server_stop_req_reset, vm_server_stop_requested};

// Polling interval for grpc_server to check for a server stop request.
const VM_GRPC_SERVER_STOP_POLLING_INTERVAL_SEC: u64 = 1;

// Server side handler
#[derive(Clone)]
struct ResourcedCommListenerService {
    cpu_dev: DeviceCpuStatus,
    packet_tx_interval: Arc<AtomicI64>,
}

//Server object
pub(crate) struct VmGrpcServer {
    _cid: i16,
    _port: u16,
    _running: bool,
}

impl VmGrpcServer {
    /// Starts the GRPC server.
    /// This function will start a new grpc server instance on a
    /// separate thread and listen for incoming traffic on the given `vsock` ports.
    ///
    /// `cid`: CID of the VM to listen for.
    ///
    /// `port`: port for all incoming traffic.
    ///
    /// `path`: root path relative to sysfs.
    ///
    /// `pkt_tx_interval`: Arc<AtomicI64> that will be shared with client thread.
    ///             Server will modify this value based on VM request.  Client
    ///             Will use this value to set the update interval of host metric
    ///             packets.  Client can also modify this value in case client detects
    ///             crash in the guest VM GRPC server.
    ///
    /// # Return
    ///
    /// An object with the status of the running server.
    /// TODO: Include and `Arc` object for thread control/exit.
    pub fn run(
        cid: i16,
        port: u16,
        root: &Path,
        pkt_tx_interval: Arc<AtomicI64>,
    ) -> Result<VmGrpcServer> {
        static SERVER_RUNNING: AtomicBool = AtomicBool::new(false);

        if !SERVER_RUNNING.load(Ordering::Relaxed) {
            SERVER_RUNNING.store(true, Ordering::Relaxed)
        } else {
            bail!("Server was already started, ignoring run request");
        }

        let cpu_dev = DeviceCpuStatus::new(root.to_path_buf())?;

        // This reference will be moved to the spawned thread.  Shared memory with
        // client thread.
        let packet_tx_interval = Arc::clone(&pkt_tx_interval);

        // Set this to default value at server start.  Server always starts at no_update
        // state (pkt_tx_interval = -1)
        packet_tx_interval.store(-1, Ordering::Relaxed);

        thread::spawn(move || {
            info!("Running grpc server");

            let env = Arc::new(Environment::new(1));
            let service = create_resourced_comm_listener(ResourcedCommListenerService {
                cpu_dev,
                packet_tx_interval,
            });

            let quota = ResourceQuota::new(Some("ResourcedServerQuota")).resize_memory(1024 * 1024);
            let ch_builder = ChannelBuilder::new(env.clone()).set_resource_quota(quota);

            let server = ServerBuilder::new(env)
                .register_service(service)
                .bind(format!("vsock:{}", cid), port)
                .channel_args(ch_builder.build_args())
                .build();

            match server {
                Ok(mut s) => {
                    s.start();

                    for (host, port) in s.bind_addrs() {
                        info!("resourced grpc server started on {}:{}", host, port);
                    }

                    info!(
                        "Sleeping grpc server thread, polling at {:?}s for stop request",
                        VM_GRPC_SERVER_STOP_POLLING_INTERVAL_SEC
                    );

                    // TODO: @shahdath: Change to a background server thread that processes
                    // dbus messages internally.
                    while !vm_server_stop_requested() {
                        thread::sleep(Duration::from_secs(
                            VM_GRPC_SERVER_STOP_POLLING_INTERVAL_SEC,
                        ));
                    }

                    info!("Grpc server stop request received.  cleaning up.");
                    s.shutdown();
                    SERVER_RUNNING.store(false, Ordering::Relaxed);
                    vm_server_stop_req_reset();
                    info!("Grpc server cleanup complete.");
                }
                Err(e) => {
                    warn!("Could not start server. Is vsock support missing?");
                    warn!("{}", e);
                }
            }
        });

        Ok(VmGrpcServer {
            _cid: cid,
            _port: port,
            _running: true,
        })
    }
}

impl ResourcedCommListener for ResourcedCommListenerService {
    fn get_cpu_info(
        &mut self,
        ctx: RpcContext<'_>,
        req: EmptyMessage,
        sink: UnarySink<CpuInfoData>,
    ) {
        info!("==> Get CPU Info request");

        let mut resp = CpuInfoData::default();

        if let Ok(data) = self.cpu_dev.get_static_cpu_info(PathBuf::from("/")) {
            let mut all_core_data: RepeatedField<CpuInfoCoreData> = RepeatedField::new();

            for core in data {
                let mut core_data = CpuInfoCoreData::default();
                let core_num: i64 = core.core_num;

                core_data.set_core_num(core_num);
                core_data.set_cpu_freq_base_khz(core.base_freq_khz);
                core_data.set_cpu_freq_max_khz(core.max_freq_khz);
                core_data.set_cpu_freq_min_khz(core.min_freq_khz);
                if let Ok(core_curr_freq) = self
                    .cpu_dev
                    .get_core_curr_freq_khz(PathBuf::from("/"), core_num)
                {
                    core_data.set_cpu_freq_curr_khz(core_curr_freq);
                } else {
                    // We don't abort if frequency couldn't be read.
                    warn!("Could not read cpu frequency for core {core_num}");
                    core_data.set_cpu_freq_curr_khz(0);
                }

                all_core_data.push(core_data);
            }

            resp.set_cpu_core_data(all_core_data);
        } else {
            // Fail if static data couldn't be send.
            warn!("Couldn't get static CPU data, not sending rpc response");
            return;
        }

        let f = sink
            .success(resp)
            .map_err(move |e| error!("failed to reply {:?}: {:?}", req, e))
            .map(|_| ());
        ctx.spawn(f)
    }

    fn start_cpu_updates(
        &mut self,
        ctx: RpcContext<'_>,
        req: RequestedInterval,
        sink: UnarySink<ReturnCode>,
    ) {
        info!(
            "==> CPU update request: interval: {}",
            req.get_interval_ms().to_string()
        );

        self.packet_tx_interval
            .store(req.get_interval_ms(), Ordering::Relaxed);
        let resp = ReturnCode::default();
        let f = sink
            .success(resp)
            .map_err(move |e| error!("failed to reply {:?}: {:?}", req, e))
            .map(|_| ());
        ctx.spawn(f)
    }

    fn stop_cpu_updates(
        &mut self,
        ctx: RpcContext<'_>,
        req: EmptyMessage,
        sink: UnarySink<ReturnCode>,
    ) {
        info!("==> CPU update stop request");

        self.packet_tx_interval.store(-1, Ordering::Relaxed);
        let resp = ReturnCode::default();
        let f = sink
            .success(resp)
            .map_err(move |e| error!("failed to reply {:?}: {:?}", req, e))
            .map(|_| ());
        ctx.spawn(f)
    }

    fn set_cpu_frequency(
        &mut self,
        ctx: grpcio::RpcContext,
        req: crate::vm_grpc::proto::resourced_bridge::RequestedCpuFrequency,
        sink: grpcio::UnarySink<crate::vm_grpc::proto::resourced_bridge::ReturnCode>,
    ) {
        let mut resp = ReturnCode::default();
        match self.cpu_dev.set_all_max_cpu_freq(req.get_freq_val() as u64) {
            Ok(_) => {
                info!(
                    "==> CPU frequncy set to {}Hz",
                    req.get_freq_val().to_string()
                );
                resp.set_status(ReturnCode_Status::SUCCESS);
            }
            Err(_) => {
                warn!(
                    "Error setting CPU frequncy to {}Hz!",
                    req.get_freq_val().to_string()
                );
                resp.set_status(ReturnCode_Status::FAIL_UNABLE_TO_SET);
            }
        }

        let f = sink
            .success(resp)
            .map_err(move |e| error!("failed to reply {:?}: {:?}", req, e))
            .map(|_| ());
        ctx.spawn(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};
    use tempfile::tempdir;

    #[test]
    fn test_service_create() {
        // Unit Testing is limited in this module without bringing up a full server.
        // Only checking init sequence.
        let root = tempdir().unwrap();

        setup_mock_cpu_dev_dirs(root.path());
        setup_mock_files(root.path());
        for cpu in 0..MOCK_NUM_CPU {
            write_mock_cpu(root.path(), cpu, 3200000, 3000000, 400000, 1000000);
        }

        let pkt_tx_interval = std::sync::Arc::new(AtomicI64::new(-2));
        let pkt_tx_interval_clone = pkt_tx_interval.clone();
        let s = VmGrpcServer::run(32, 5555, Path::new(root.path()), pkt_tx_interval);

        // Test that server is attempted, and the Arc<i64> is set to init value of -1.
        // The internal thread likely failed since it can't bind the socket port.
        assert_eq!(pkt_tx_interval_clone.load(Ordering::Relaxed), -1);
        assert!(s.is_ok());

        // Test that second invoke fails
        let s2 = VmGrpcServer::run(32, 5555, Path::new(root.path()), pkt_tx_interval_clone);
        assert!(s2.is_err());
    }

    /// Base path for power_limit relative to rootdir.
    const DEVICE_POWER_LIMIT_PATH: &str = "sys/class/powercap/intel-rapl:0";

    /// Base path for cpufreq relative to rootdir.
    const DEVICE_CPUFREQ_PATH: &str = "sys/devices/system/cpu/cpufreq";

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
}
