// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! API endpoint library for the TEE apps to communicate with Trichechus.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod storage;

use std::borrow::Borrow;
use std::borrow::BorrowMut;
use std::collections::BTreeMap as Map;
use std::fs::File;
use std::marker::PhantomData;
use std::os::unix::io::FromRawFd;
use std::sync::Arc;

use libsirenia::communication::tee_api::TeeApiClient;
pub use libsirenia::storage::Error;
pub use libsirenia::storage::Result;
use libsirenia::storage::Storable;
use libsirenia::storage::Storage;
use libsirenia::transport::Transport;
use libsirenia::transport::DEFAULT_CONNECTION_R_FD;
use libsirenia::transport::DEFAULT_CONNECTION_W_FD;
use once_cell::sync::OnceCell;
pub use sync::Mutex;

/// Return a client RPC handle for the TEE API.
///
/// This performs lazy initialization.
pub fn rpc_handle() -> Arc<Mutex<TeeApiClient>> {
    static RPC: OnceCell<Arc<Mutex<TeeApiClient>>> = OnceCell::new();
    RPC.get_or_init(|| {
        Arc::new(Mutex::new(TeeApiClient::new(
            // Safe because this is only called once by get_or_init().
            Transport::from_files(
                unsafe { File::from_raw_fd(DEFAULT_CONNECTION_R_FD) },
                unsafe { File::from_raw_fd(DEFAULT_CONNECTION_W_FD) },
            ),
        )))
    })
    .clone()
}

/// Represents some scoped data temporarily loaded from the backing store.
pub struct ScopedData<S: Storable, T: Storage, R: BorrowMut<T>> {
    identifier: String,
    data: S,
    storage: R,
    storage_phantom: PhantomData<*const T>,
}

impl<S: Storable, T: Storage, R: BorrowMut<T>> AsRef<S> for ScopedData<S, T, R> {
    fn as_ref(&self) -> &S {
        self.borrow()
    }
}

impl<S: Storable, T: Storage, R: BorrowMut<T>> AsMut<S> for ScopedData<S, T, R> {
    fn as_mut(&mut self) -> &mut S {
        self.borrow_mut()
    }
}

/// Borrows the data read-only.
impl<S: Storable, T: Storage, R: BorrowMut<T>> Borrow<S> for ScopedData<S, T, R> {
    fn borrow(&self) -> &S {
        &self.data
    }
}

/// Borrows a mutable reference to the data (the ScopedData must be
/// constructed read-write).
impl<S: Storable, T: Storage, R: BorrowMut<T>> BorrowMut<S> for ScopedData<S, T, R> {
    fn borrow_mut(&mut self) -> &mut S {
        &mut self.data
    }
}

impl<S: Storable, T: Storage, R: BorrowMut<T>> Drop for ScopedData<S, T, R> {
    fn drop(&mut self) {
        // TODO: Figure out how we want to handle errors on storing.
        // We might want to log failures, but not necessarily crash. This will
        // require us to bind mount the log into the sandbox though
        // (which we should probably do anyway).
        //
        // One option would be set a callback. We could provide some standard
        // callbacks like unwrap and log.
        self.storage
            .borrow_mut()
            .write_data(&self.identifier, &self.data)
            .unwrap();
    }
}

/// Reads the data into itself then writes back on a flush.
impl<S: Storable, T: Storage, R: BorrowMut<T>> ScopedData<S, T, R> {
    /// Creates and returns a new scoped data. Attempts to read the value of
    /// the id from the backing store and uses the passed in closure to
    /// determine the default value if the id is not found.
    pub fn new(mut storage: R, identifier: &str, f: fn(&str) -> S) -> Result<Self> {
        match storage.borrow_mut().read_data(identifier) {
            Ok(data) => {
                let id = identifier.to_string();
                Ok(ScopedData {
                    identifier: id,
                    data,
                    storage,
                    storage_phantom: PhantomData,
                })
            }
            Err(libsirenia::storage::Error::IdNotFound(_)) => {
                let data = f(identifier);
                let id = identifier.to_string();
                Ok(ScopedData {
                    identifier: id,
                    data,
                    storage,
                    storage_phantom: PhantomData,
                })
            }
            Err(e) => Err(e),
        }
    }

    /// Write the data back out to the backing store.
    pub fn flush(&mut self) -> Result<()> {
        self.storage
            .borrow_mut()
            .write_data(&self.identifier, &self.data)
            .unwrap();
        Ok(())
    }
}

/// A helper type for when the storage implementation doesn't need to be shared. See ScopedData.
pub type ExclusiveScopedData<'a, S, T> = ScopedData<S, T, &'a mut T>;

/// Represents an entire key value store for one identifier.
pub type ScopedKeyValueStore<S, T, R> = ScopedData<Map<String, S>, T, R>;

/// A helper type for when the storage implementation doesn't need to be shared.
/// See ScopedKeyValueStore.
pub type ExclusiveScopedKeyValueStore<'a, S, T> = ScopedKeyValueStore<S, T, &'a mut T>;

#[cfg(test)]
mod tests {
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;

    use libsirenia::storage::StorableMember;

    use super::*;

    const TEST_ID: &str = "id";

    struct MockStorage {
        map: Map<String, StorableMember>,
    }

    impl MockStorage {
        fn new() -> Self {
            let map = Map::new();
            MockStorage { map }
        }
    }

    impl Storage for MockStorage {
        fn read_raw(&mut self, _id: &str) -> Result<Vec<u8>> {
            Err(libsirenia::storage::Error::ReadData(None))
        }

        fn remove(&mut self, _id: &str) -> Result<()> {
            Err(libsirenia::storage::Error::Remove(None))
        }

        fn write_raw(&mut self, _id: &str, _data: &[u8]) -> Result<()> {
            Err(libsirenia::storage::Error::WriteData(None))
        }

        fn read_data<S: Storable>(&mut self, id: &str) -> Result<S> {
            match self.map.get(id) {
                Some(val) => {
                    let data = val.try_borrow::<S>().unwrap();
                    Ok(data.to_owned())
                }
                None => Err(libsirenia::storage::Error::IdNotFound(id.to_string())),
            }
        }

        fn write_data<S: Storable>(&mut self, id: &str, data: &S) -> Result<()> {
            let store_data = StorableMember::new_deserialized::<S>(data.to_owned());
            self.map.insert(id.to_string(), store_data);
            Ok(())
        }
    }

    fn get_test_value() -> String {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string()
    }

    fn setup_test_case(write_back: bool) -> (MockStorage, String, String) {
        let mut store = MockStorage::new();
        let id = TEST_ID;
        let s = get_test_value();
        if write_back {
            store.write_data::<String>(id, &s).unwrap();
        }
        (store, id.to_string(), s)
    }

    fn callback_id_not_found(_s: &str) -> String {
        "Could not find id".to_string()
    }

    fn callback_id_found(_s: &str) -> String {
        unreachable!("This callback should not be called because the id was found in the store.")
    }

    #[test]
    fn write_and_read() {
        let (mut store, id, s) = setup_test_case(/* write back */ true);
        assert_eq!(s, store.read_data::<String>(&id).unwrap());
    }

    #[test]
    fn read_id_not_found() {
        let mut store = MockStorage::new();
        assert_eq!(
            libsirenia::storage::Error::IdNotFound(TEST_ID.to_string()).to_string(),
            store.read_data::<String>(TEST_ID).unwrap_err().to_string()
        );
    }

    #[test]
    fn make_new_scoped_data() {
        let (mut store, id, _s) = setup_test_case(/* write back */ false);
        let data: ExclusiveScopedData<String, MockStorage> =
            ScopedData::new(&mut store, &id, callback_id_not_found).unwrap();
        let res: &String = data.borrow();
        assert_eq!("Could not find id", res);
    }

    #[test]
    fn make_existing_scoped_data() {
        let (mut store, id, s) = setup_test_case(/* write back */ true);

        let data: ExclusiveScopedData<String, MockStorage> =
            ScopedData::new(&mut store, &id, callback_id_found).unwrap();
        let res: &String = data.borrow();
        assert_eq!(&s, res);
    }

    #[test]
    fn mut_and_drop_scoped_data() {
        let (mut store, id, mut s) = setup_test_case(/* write back */ true);

        {
            let mut data: ExclusiveScopedData<String, MockStorage> =
                ScopedData::new(&mut store, &id, callback_id_found).unwrap();
            let res: &mut String = data.borrow_mut();
            res.push_str(" New");
        }
        s.push_str(" New");

        assert_eq!(s, store.read_data::<String>(&id).unwrap());
    }

    #[test]
    fn mut_and_flush_scoped_data() {
        let (mut store, id, mut s) = setup_test_case(/* write back */ true);

        {
            let mut data: ExclusiveScopedData<String, MockStorage> =
                ScopedData::new(&mut store, &id, callback_id_found).unwrap();
            let res: &mut String = data.borrow_mut();
            res.push_str(" New");
            data.flush().unwrap();
        }
        s.push_str(" New");

        assert_eq!(s, store.read_data::<String>(&id).unwrap());
    }

    #[test]
    fn mut_and_drop_kvstore() {
        let mut store = MockStorage::new();
        let id = "id";
        let map = Map::new();
        store.write_data::<Map<String, String>>(id, &map).unwrap();

        {
            let fun = |_h: &str| panic!();
            let key = "key";
            let value = "value";
            let mut kvstore: ExclusiveScopedKeyValueStore<String, MockStorage> =
                ScopedKeyValueStore::new(&mut store, id, fun).unwrap();
            kvstore.as_mut().insert(key.to_string(), value.to_string());
            assert!(kvstore.as_mut().contains_key(key));
        }

        let res_map = store.read_data::<Map<String, String>>(id).unwrap();
        assert!(res_map.contains_key("key"));
        assert_eq!("value", res_map.get("key").unwrap())
    }
}
