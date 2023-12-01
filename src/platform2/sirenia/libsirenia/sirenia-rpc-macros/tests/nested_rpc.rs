// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Verify sirenia-rpc_macros works for the intended use case.

extern crate sirenia_rpc_macros;

use std::thread::spawn;

use anyhow::anyhow;
use assert_matches::assert_matches;
use libsirenia::rpc::RpcDispatcher;
use libsirenia::transport::create_transport_from_pipes;
use sirenia_rpc_macros::sirenia_rpc;

#[sirenia_rpc]
pub trait TestRpc<E> {
    fn checked_neg(&mut self, input: i32) -> Result<Option<i32>, E>;
    fn checked_add(&mut self, addend_a: i32, addend_b: i32) -> Result<Option<i32>, E>;
}

#[sirenia_rpc]
pub trait OtherRpc<E> {
    fn checked_neg(&mut self, input: i64) -> Result<Option<i64>, E>;
    fn checked_add(&mut self, addend_a: i64, addend_b: i64) -> Result<Option<i64>, E>;
}

#[sirenia_rpc]
pub trait NestedRpc<E>: TestRpc<E> + OtherRpc<E> {
    fn terminate(&mut self) -> Result<(), E>;
    fn echo_bytes(&mut self, bytes: Vec<u8>) -> Result<Vec<u8>, E>;
}

#[derive(Clone)]
struct NestedRpcServerImpl {}

impl TestRpc<anyhow::Error> for NestedRpcServerImpl {
    fn checked_neg(&mut self, input: i32) -> Result<Option<i32>, anyhow::Error> {
        Ok(input.checked_neg())
    }

    fn checked_add(&mut self, addend_a: i32, addend_b: i32) -> Result<Option<i32>, anyhow::Error> {
        Ok(addend_a.checked_add(addend_b))
    }
}

impl OtherRpc<anyhow::Error> for NestedRpcServerImpl {
    fn checked_neg(&mut self, input: i64) -> Result<Option<i64>, anyhow::Error> {
        Ok(input.checked_neg())
    }

    fn checked_add(&mut self, addend_a: i64, addend_b: i64) -> Result<Option<i64>, anyhow::Error> {
        Ok(addend_a.checked_add(addend_b))
    }
}

impl NestedRpc<anyhow::Error> for NestedRpcServerImpl {
    fn terminate(&mut self) -> Result<(), anyhow::Error> {
        Err(anyhow!("Done"))
    }

    fn echo_bytes(&mut self, bytes: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
        Ok(bytes)
    }
}

#[test]
fn nested_rpc_test() {
    let (server_transport, client_transport) = create_transport_from_pipes().unwrap();

    let handler: Box<dyn NestedRpcServer> = Box::new(NestedRpcServerImpl {});
    let mut dispatcher = RpcDispatcher::new_nonblocking(handler, server_transport).unwrap();

    // Queue the client RPC:
    let client_thread = spawn(move || {
        let mut rpc_client = NestedRpcClient::new(client_transport);

        let neg_resp = TestRpc::<anyhow::Error>::checked_neg(&mut rpc_client, 125).unwrap();
        assert_matches!(neg_resp, Some(-125));

        let add_resp = OtherRpc::<anyhow::Error>::checked_add(&mut rpc_client, 5, 4).unwrap();
        assert_matches!(add_resp, Some(9));

        assert!(rpc_client.terminate().is_err());
    });

    let sleep_for = None;
    assert_matches!(dispatcher.read_complete_message(sleep_for), Ok(None));
    assert_matches!(dispatcher.read_complete_message(sleep_for), Ok(None));
    assert_matches!(dispatcher.read_complete_message(sleep_for), Ok(Some(_)));
    // Explicitly call drop to close the pipe so the client thread gets the hang up since the return
    // value should be a RemoveFd mutator.
    drop(dispatcher);

    client_thread.join().unwrap();
}
