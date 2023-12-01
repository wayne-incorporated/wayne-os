// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Verify sirenia-rpc_macros works for the intended use case.

extern crate sirenia_rpc_macros;

use std::fmt;
use std::fmt::Display;
use std::fmt::Formatter;
use std::iter;
use std::thread::spawn;

use anyhow::anyhow;
use assert_matches::assert_matches;
use libsirenia::rpc::RpcDispatcher;
use libsirenia::transport::create_transport_from_pipes;
use serde::Deserialize;
use serde::Serialize;
use sirenia_rpc_macros::sirenia_rpc;

const MAGIC_NUMBER: i32 = 42;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Error {
    MagicNumber,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use Error::*;
        match self {
            MagicNumber => write!(f, "You entered the magic number."),
        }
    }
}

impl std::error::Error for Error {}

#[sirenia_rpc(error = "Error")]
pub trait TestRpc<E> {
    fn checked_neg(&mut self, input: i32) -> Result<Option<i32>, E>;
    fn checked_add(&mut self, addend_a: i32, addend_b: i32) -> Result<Option<i32>, E>;
    #[error()]
    fn terminate(&mut self) -> Result<(), E>;
    fn echo_bytes(&mut self, bytes: Vec<u8>) -> Result<Vec<u8>, E>;
}

#[derive(Clone)]
struct TestRpcServerImpl {}

impl TestRpc<anyhow::Error> for TestRpcServerImpl {
    fn checked_neg(&mut self, input: i32) -> Result<Option<i32>, anyhow::Error> {
        if input == MAGIC_NUMBER {
            Err(Error::MagicNumber.into())
        } else {
            Ok(input.checked_neg())
        }
    }

    fn checked_add(&mut self, addend_a: i32, addend_b: i32) -> Result<Option<i32>, anyhow::Error> {
        if addend_a == MAGIC_NUMBER || addend_b == MAGIC_NUMBER {
            Err(Error::MagicNumber.into())
        } else {
            Ok(addend_a.checked_add(addend_b))
        }
    }

    fn terminate(&mut self) -> Result<(), anyhow::Error> {
        Err(anyhow!("Done"))
    }

    fn echo_bytes(&mut self, bytes: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
        Ok(bytes)
    }
}

#[test]
fn smoke_test() {
    let (server_transport, client_transport) = create_transport_from_pipes().unwrap();

    let handler: Box<dyn TestRpcServer> = Box::new(TestRpcServerImpl {});
    let mut dispatcher = RpcDispatcher::new_nonblocking(handler, server_transport).unwrap();

    // Queue the client RPC:
    let client_thread = spawn(move || {
        let mut rpc_client = TestRpcClient::new(client_transport);

        let neg_resp = rpc_client.checked_neg(125).unwrap();
        assert_matches!(neg_resp, Some(-125));

        let neg_err_resp = rpc_client.checked_neg(42);
        if let Err(err) = neg_err_resp {
            assert_matches!(err.downcast_ref::<Error>(), Some(Error::MagicNumber));
        } else {
            panic!("Got {:?}; expected Err(Error::MagicNumber)", neg_err_resp)
        };

        let add_resp = rpc_client.checked_add(5, 4).unwrap();
        assert_matches!(add_resp, Some(9));

        assert!(rpc_client.terminate().is_err());
    });

    let sleep_for = None;
    assert_matches!(dispatcher.read_complete_message(sleep_for), Ok(None));
    assert_matches!(dispatcher.read_complete_message(sleep_for), Ok(None));
    assert_matches!(dispatcher.read_complete_message(sleep_for), Ok(None));
    assert_matches!(dispatcher.read_complete_message(sleep_for), Ok(Some(_)));
    // Explicitly call drop to close the pipe so the client thread gets the hang up since the return
    // value should be a RemoveFd mutator.
    drop(dispatcher);

    client_thread.join().unwrap();
}

#[test]
fn byte_field_size_test() {
    let bytes: Vec<u8> = iter::repeat(77u8).take(1024).collect();
    let bytes_len = bytes.len();
    let request = TestRpcRequest::EchoBytes { bytes };
    assert!(flexbuffers::to_vec(request).unwrap().len() < bytes_len * 12 / 10);
}
