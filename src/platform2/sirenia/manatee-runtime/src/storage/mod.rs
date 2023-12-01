// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Defines the messages and abstracts out communication for storage between
//! TEE apps, Trichechus, and Dugong.

use std::sync::Arc;

use libsirenia::communication::persistence::Status;
use libsirenia::communication::tee_api::TeeApi;
use libsirenia::communication::tee_api::TeeApiClient;
use libsirenia::storage::to_read_data_error;
use libsirenia::storage::to_remove_error;
use libsirenia::storage::to_write_data_error;
use libsirenia::storage::Error;
use libsirenia::storage::Result;
use libsirenia::storage::Storage;
use libsirenia::transport::Transport;
use sync::Mutex;

use crate::rpc_handle;

/// Holds the rpc client for the specific instance of the TEE App.
#[derive(Clone)]
pub struct TrichechusStorage {
    rpc: Arc<Mutex<TeeApiClient>>,
}

impl TrichechusStorage {
    /// Initialize the storage related middleware.
    ///
    /// This uses the TEE API over RPC which is protected by a mutex so keep that in mind when
    /// planning deadlock avoidance.
    pub fn new() -> Self {
        TrichechusStorage { rpc: rpc_handle() }
    }
}

impl Default for TrichechusStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Transport> for TrichechusStorage {
    fn from(transport: Transport) -> Self {
        TrichechusStorage {
            rpc: Arc::new(Mutex::new(TeeApiClient::new(transport))),
        }
    }
}

impl Storage for TrichechusStorage {
    /// Read without deserializing.
    fn read_raw(&mut self, id: &str) -> Result<Vec<u8>> {
        // TODO: Log the rpc error.
        match self.rpc.lock().read_data(id.to_string()) {
            Ok((Status::Success, res)) => Ok(res.into()),
            Ok((Status::IdNotFound, _)) => Err(Error::IdNotFound(id.to_string())),
            Ok((Status::Failure, _)) | Ok((Status::CryptoFailure, _)) => Err(Error::ReadData(None)),
            Err(err) => Err(to_read_data_error(err)),
        }
    }

    fn remove(&mut self, id: &str) -> Result<()> {
        match self.rpc.lock().remove(id.to_string()) {
            Ok(Status::Success) => Ok(()),
            Ok(_) => Err(Error::Remove(None)),
            Err(err) => Err(to_remove_error(err)),
        }
    }

    /// Write without serializing.
    fn write_raw(&mut self, id: &str, data: &[u8]) -> Result<()> {
        match self.rpc.lock().write_data(id.to_string(), data.to_vec()) {
            Ok(Status::Success) => Ok(()),
            Ok(_) => Err(Error::WriteData(None)),
            Err(err) => Err(to_write_data_error(err)),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap as Map;
    use std::rc::Rc;
    use std::thread::spawn;
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;

    use anyhow::anyhow;
    use anyhow::Error;
    use anyhow::Result;
    use assert_matches::assert_matches;
    use libsirenia::communication::tee_api::TeeApiServer;
    use libsirenia::rpc::RpcDispatcher;
    use libsirenia::storage::Error as StorageError;
    use libsirenia::transport::create_transport_from_pipes;
    use serde_bytes::ByteBuf;

    use super::*;

    const TEST_ID: &str = "id";

    #[derive(Clone)]
    struct TeeApiServerImpl {
        map: Rc<RefCell<Map<String, Vec<u8>>>>,
    }

    impl TeeApi<Error> for TeeApiServerImpl {
        fn read_data(&mut self, id: String) -> Result<(Status, ByteBuf)> {
            match self.map.borrow().get(&id) {
                Some(val) => Ok((Status::Success, val.clone().into())),
                None => Err(anyhow!("id missing")),
            }
        }

        fn remove(&mut self, id: String) -> Result<Status> {
            Ok(match self.map.borrow_mut().remove(&id) {
                Some(_) => Status::Success,
                None => Status::IdNotFound,
            })
        }

        fn write_data(&mut self, id: String, data: Vec<u8>) -> Result<Status> {
            self.map.borrow_mut().insert(id, data);
            Ok(Status::Success)
        }
    }

    fn get_test_value() -> String {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string()
    }

    fn setup() -> (RpcDispatcher<Box<dyn TeeApiServer>>, TrichechusStorage) {
        let (server_transport, client_transport) = create_transport_from_pipes().unwrap();

        let handler: Box<dyn TeeApiServer> = Box::new(TeeApiServerImpl {
            map: Rc::new(RefCell::new(Map::new())),
        });
        let dispatcher = RpcDispatcher::new(handler, server_transport);

        (dispatcher, TrichechusStorage::from(client_transport))
    }

    #[test]
    fn write_and_read() {
        let (mut dispatcher, mut trichechus_storage) = setup();

        let client_thread = spawn(move || {
            let data = get_test_value();
            trichechus_storage.write_data(TEST_ID, &data).unwrap();

            let retrieved_data = trichechus_storage.read_data::<String>(TEST_ID).unwrap();
            assert_eq!(retrieved_data, data);
        });

        let sleep_for = None;
        assert_matches!(dispatcher.read_complete_message(sleep_for), Ok(None));
        assert_matches!(dispatcher.read_complete_message(sleep_for), Ok(None));

        client_thread.join().unwrap();
    }

    #[test]
    fn read_id_not_found() {
        let (mut dispatcher, mut trichechus_storage) = setup();

        let client_thread = spawn(move || {
            let error = trichechus_storage.read_data::<String>(TEST_ID).unwrap_err();
            println!("Client thread: {}", error);
            assert_matches!(error, StorageError::ReadData(_));
        });

        let sleep_for = None;
        assert_matches!(dispatcher.read_complete_message(sleep_for), Ok(Some(_)));

        // Explicitly call drop to close the pipe so the client thread gets the hang up since the return
        // value should be a RemoveFd mutator.
        drop(dispatcher);

        client_thread.join().unwrap();
    }
}
