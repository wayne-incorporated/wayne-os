// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Holds all the code related to RPC over vsock.

use std::os::raw::c_uint;
use std::result::Result as StdResult;

use crosvm_base::unix::vsock::SocketAddr;
use crosvm_base::unix::vsock::VsockCid;
use getopts::Matches;
use getopts::Options;
use libsirenia::cli;
use libsirenia::cli::TransportTypeOption;
use libsirenia::communication::persistence::Cronista;
use libsirenia::communication::persistence::CronistaServer;
use libsirenia::communication::persistence::Scope;
use libsirenia::communication::persistence::Status;
use libsirenia::linux::events::EventMultiplexer;
use libsirenia::rpc::register_server;
use libsirenia::rpc::Error as RpcError;
use libsirenia::transport::TransportType;
use log::error;
use log::info;
use thiserror::Error as ThisError;

use crate::storage;
use crate::storage::is_unwritten_id;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("failed to parse the transport: {0:?}")]
    ParseTransport(cli::Error),
}

type Result<T> = StdResult<T, Error>;

const DEFAULT_BIND_PORT: c_uint = 5554;

/// Configuration parameters for a socket rpc instance.
pub struct Config {
    bind_addr: TransportType,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            bind_addr: TransportType::VsockConnection(SocketAddr {
                cid: VsockCid::Any,
                port: DEFAULT_BIND_PORT,
            }),
        }
    }
}

/// A helper to generate a socket_rpc::Config from getopts::Options.
pub struct CliConfigGenerator {
    bind_addr: TransportTypeOption,
}

impl CliConfigGenerator {
    /// Registers the relevant parameters with the specified Options.
    pub fn new(opts: &mut Options) -> Self {
        CliConfigGenerator {
            bind_addr: TransportTypeOption::default(opts),
        }
    }

    /// Generates a Config from the specified matches.
    pub fn generate_config(&self, matches: &Matches) -> Result<Config> {
        let mut config = Config::default();
        if let Some(cli_addr) = self
            .bind_addr
            .from_matches(matches)
            .map_err(Error::ParseTransport)?
        {
            config.bind_addr = cli_addr;
        }
        Ok(config)
    }
}

/// Sets up a socket based RPC server on the EventMultiplexer.
pub fn register_socket_rpc(
    config: &Config,
    event_multiplexer: &mut EventMultiplexer,
) -> StdResult<Option<TransportType>, RpcError> {
    let handler: Box<dyn CronistaServer> = Box::new(CronistaServerImpl {});
    register_server(event_multiplexer, &config.bind_addr, handler)
}

/// Manages a single RPC connection.
#[derive(Clone)]
struct CronistaServerImpl {}

impl Cronista<anyhow::Error> for CronistaServerImpl {
    fn persist(
        &mut self,
        scope: Scope,
        domain: String,
        identifier: String,
        data: Vec<u8>,
    ) -> anyhow::Result<Status> {
        info!("Received persist message",);
        Ok(
            match storage::persist(scope, &domain, &identifier, data.as_slice()) {
                Ok(_) => Status::Success,
                Err(err) => {
                    error!("persist failure: {}", err);
                    Status::Failure
                }
            },
        )
    }

    fn remove(
        &mut self,
        scope: Scope,
        domain: String,
        identifier: String,
    ) -> StdResult<Status, anyhow::Error> {
        info!("Received remove message",);
        let res = storage::remove(scope, &domain, &identifier);
        Ok(match &res {
            Ok(_) => Status::Success,
            Err(err) => {
                if is_unwritten_id(&res) {
                    Status::IdNotFound
                } else {
                    error!("remove failure: {}", err);
                    Status::Failure
                }
            }
        })
    }

    fn retrieve(
        &mut self,
        scope: Scope,
        domain: String,
        identifier: String,
    ) -> anyhow::Result<(Status, Vec<u8>)> {
        info!("Received retrieve message");
        let res = storage::retrieve(scope, &domain, &identifier);
        if is_unwritten_id(&res) {
            return Ok((Status::IdNotFound, Vec::new()));
        }
        Ok(match res {
            Ok(data) => (Status::Success, data),
            Err(err) => {
                error!("retrieve failure: {}", err);
                (Status::Failure, Vec::new())
            }
        })
    }
}
