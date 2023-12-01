// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[path = "../proto/resourced_bridge.rs"]
mod resourced_bridge;

#[path = "../proto/resourced_bridge_grpc.rs"]
mod resourced_bridge_grpc;

use futures_util::future::{FutureExt as _, TryFutureExt as _};
use grpcio::{
    ChannelBuilder, EnvBuilder, Environment, ResourceQuota, RpcContext, ServerBuilder, UnarySink,
};
use once_cell::sync::Lazy;
use std::env;
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::resourced_bridge::{
    CpuRaplPowerData, EmptyMessage, RequestedCpuFrequency, RequestedInterval,
};
use crate::resourced_bridge_grpc::ResourcedCommListenerClient;
use crate::resourced_bridge_grpc::{create_resourced_comm, ResourcedComm};

static mut VM_INIT_RX: Lazy<bool> = Lazy::new(|| false);

/// Builds a a mock server/client stub that emulates guest VM gRPC calls.
/// This executable can be run in the VM once resourced has started its v1 gRPC
/// server
fn main() {
    println!("+-----------------------------------------------------+");
    println!("|  Mock Client to stub VM side interactions (v2 API)  |");
    println!("+-----------------------------------------------------+");

    // Default host and port. Can be overwritten from cmdline.
    let mut server_host = "vsock:-1".to_string();
    let mut server_port = "5553".to_string();
    let client_addr = "vsock:2:5551";

    let args: Vec<String> = env::args().collect();

    if args.len() == 3 {
        println!("Args: {:?}", args);
        server_host = args[1].clone();
        server_port = args[2].clone();
    }

    thread::spawn(move || {
        println!("Stating VM server on {}:{}", server_host, server_port);
        start_mock_powerd_listener(&server_host, server_port.parse::<u16>().unwrap());
    });

    println!("VM server thread started (upto 30sec timeout)");

    let mut time_remaining_ms = 30000;
    loop {
        if unsafe { *VM_INIT_RX } || time_remaining_ms <= 0 {
            break;
        } else {
            thread::sleep(core::time::Duration::from_millis(100));
            time_remaining_ms -= 100;
        }
    }

    println!("<== VM client send cpu update RPC request");
    trigger_cpu_updates(100, client_addr);

    let mut cycle_cnt = 0;

    loop {
        thread::sleep(std::time::Duration::from_secs(2));

        println!("<== Get CPU Info");
        get_cpu_info(client_addr);

        println!("<== Frequency update RPC request 3.2G");
        send_cpu_freq_change_request(3200000, client_addr);

        thread::sleep(core::time::Duration::from_secs(2));
        println!("<==  Frequency update RPC request 3.4G");
        send_cpu_freq_change_request(3400000, client_addr);

        if cycle_cnt > 10 {
            cycle_cnt = 0;

            println!("Send update_stop request");
            stop_cpu_updates(client_addr);

            println!("Sleeping 15s");
            thread::sleep(core::time::Duration::from_secs(15));

            println!("<== VM client send cpu update RPC request");
            trigger_cpu_updates(100, client_addr);
        } else {
            cycle_cnt += 1;
        }
    }
}

fn get_cpu_info(addr: &str) {
    println!("Using addr {}", addr);
    let env = Arc::new(EnvBuilder::new().build());
    let ch = ChannelBuilder::new(env).connect(addr);
    let client = ResourcedCommListenerClient::new(ch);

    let req = EmptyMessage::default();
    let reply = client.get_cpu_info(&req).expect("rpc");
    println!("Server response: {:?}", reply.get_cpu_core_data());
    //TODO: clean print
}

fn trigger_cpu_updates(freq_ms: i64, addr: &str) {
    println!("Using addr {}", addr);
    let env = Arc::new(EnvBuilder::new().build());
    let ch = ChannelBuilder::new(env).connect(addr);
    let client = ResourcedCommListenerClient::new(ch);

    let mut req = RequestedInterval::default();
    req.set_interval_ms(freq_ms);
    let reply = client.start_cpu_updates(&req).expect("rpc");
    println!("Server response: {:?}", reply.get_status());
}

fn stop_cpu_updates(addr: &str) {
    println!("Using addr {}", addr);
    let env = Arc::new(EnvBuilder::new().build());
    let ch = ChannelBuilder::new(env).connect(addr);
    let client = ResourcedCommListenerClient::new(ch);

    let req = EmptyMessage::default();
    let reply = client.stop_cpu_updates(&req).expect("rpc");
    println!("Server response: {:?}", reply.get_status());
}

fn send_cpu_freq_change_request(freq_hz: i64, addr: &str) {
    println!("Using addr {}", addr);
    let env = Arc::new(EnvBuilder::new().build());
    let ch = ChannelBuilder::new(env).connect(addr);
    let client = ResourcedCommListenerClient::new(ch);

    let mut req = RequestedCpuFrequency::default();
    req.set_freq_val(freq_hz);
    let reply = client.set_cpu_frequency(&req).expect("rpc");
    println!("Server response: {:?}", reply.get_status());
}

#[derive(Clone)]
struct ResourcedCommService;

impl ResourcedComm for ResourcedCommService {
    fn vm_init_data(
        &mut self,
        ctx: grpcio::RpcContext,
        req: crate::resourced_bridge::CpuInfoData,
        sink: grpcio::UnarySink<crate::resourced_bridge::EmptyMessage>,
    ) {
        println!("{:?}", req.get_cpu_core_data());

        unsafe {
            *VM_INIT_RX = true;
        }

        let resp = EmptyMessage::default();
        let f = sink
            .success(resp)
            .map_err(move |e| println!("failed to reply {:?}: {:?}", req, e))
            .map(|_| ());
        ctx.spawn(f)
    }

    fn cpu_power_update(
        &mut self,
        ctx: RpcContext<'_>,
        req: CpuRaplPowerData,
        sink: UnarySink<EmptyMessage>,
    ) {
        println!(
            "{:?} powerd cpu update: pl0:{}\tpl1:{}\tE:{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Coudn't resolve time")
                .as_millis(),
            req.get_power_limit_0(),
            req.get_power_limit_1(),
            req.get_cpu_energy()
        );
        let resp = EmptyMessage::default();
        let f = sink
            .success(resp)
            .map_err(move |e| println!("failed to reply {:?}: {:?}", req, e))
            .map(|_| ());
        ctx.spawn(f)
    }
}

fn start_mock_powerd_listener(host: &str, port: u16) {
    println!("Create mock grpcio server");

    const RESIZE_MEM_LIMIT: usize = 1024 * 1024;
    let env = Arc::new(Environment::new(1));
    let service = create_resourced_comm(ResourcedCommService);

    let quota = ResourceQuota::new(Some("ResourcedServerQuota")).resize_memory(RESIZE_MEM_LIMIT);
    let ch_builder = ChannelBuilder::new(env.clone()).set_resource_quota(quota);

    let mut server = ServerBuilder::new(env)
        .register_service(service)
        .bind(host, port)
        .channel_args(ch_builder.build_args())
        .build()
        .unwrap();
    server.start();
    for (host, port) in server.bind_addrs() {
        println!("mock powerd grpc vm server started on {}:{}", host, port);
    }

    println!("Parking mock VM Server thread");
    thread::park();
}
