// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod socket_rpc;
mod storage;

use std::env;
use std::process::exit;

use anyhow::anyhow;
use getopts::Options;
use libchromeos::syslog;
use libsirenia::cli::HelpOption;
use libsirenia::linux::events::EventMultiplexer;
use log::error;
use log::info;

use crate::socket_rpc::register_socket_rpc;
use crate::storage::initialize_storage;

const IDENT: &str = "cronista";

fn get_usage() -> String {
    IDENT.to_string()
}

fn main() -> anyhow::Result<()> {
    // Set up command line arguments.
    let mut opts = Options::new();
    let help_opt = HelpOption::new(&mut opts);
    let socket_rpc_cli = socket_rpc::CliConfigGenerator::new(&mut opts);

    // Parse command line arguments and perform initialization.
    let args: Vec<String> = env::args().collect();
    let matches = help_opt.parse_and_check_self(&opts, &args, get_usage);
    syslog::init(IDENT.to_string(), true /* log_to_syslog */)
        .map_err(|err| anyhow!("failed to initialize the syslog: {:?}", err))?;
    info!("starting {}", IDENT);
    initialize_storage()?;
    let mut ctx = EventMultiplexer::new()?;

    // Initialize and register event handlers.
    let listen_addr = register_socket_rpc(
        &socket_rpc_cli
            .generate_config(&matches)
            .unwrap_or_else(|e| -> socket_rpc::Config {
                error!("{}", e);
                opts.usage(&get_usage());
                exit(1)
            }),
        &mut ctx,
    )
    .unwrap();
    if let Some(addr) = listen_addr {
        info!("waiting for connection at: {}", addr);
    } else {
        info!("waiting for connection");
    }

    // Main loop.
    info!("initialization complete");
    while !ctx.is_empty() {
        if let Err(e) = ctx.run_once() {
            error!("{}", e);
        };
    }
    Ok(())
}
