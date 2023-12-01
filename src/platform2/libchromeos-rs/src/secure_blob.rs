// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt::{self, Debug, Display, Formatter};
use std::mem::swap;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// A container intended for handling sensitive data without leaving copies
/// behind after it is dropped (inspired by libbrillo::SecureBlob).
///
/// Note: when using serialize and deserialize, it is recommended to use a
/// SecureBlob for the buffers.
#[derive(Clone, Default, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct SecureBlob {
    data: Vec<u8>,
}

impl SecureBlob {
    /// Creates a SecureBlob that can be extended to `capacity` before a
    /// reallocation is needed.
    pub fn with_capacity(capacity: usize) -> Self {
        SecureBlob {
            data: Vec::with_capacity(capacity),
        }
    }

    /// Appends the contents of the slice to the SecureBlob taking care of
    /// zeroing the data if a reallocation is needed.
    pub fn extend_from_slice(&mut self, other: &[u8]) {
        let total_len = self.len() + other.len();
        if total_len > self.capacity() {
            let mut temp = Vec::with_capacity(total_len);
            temp.extend_from_slice(self.as_ref());
            self.data.zeroize();
            swap(&mut self.data, &mut temp)
        }
        self.data.extend_from_slice(other.as_ref());
    }

    /// How much data can be in the SecureBlob without a reallocation.
    pub fn capacity(&self) -> usize {
        self.data.capacity()
    }

    /// Returns `true` if the length of SecureBob is zero.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns the number of bytes in the SecureBlob.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Securely erase the contents of the SecureBlob.
    pub fn clear(&mut self) {
        self.data.zeroize();
        self.data.clear();
    }
}

impl AsRef<[u8]> for SecureBlob {
    fn as_ref(&self) -> &[u8] {
        self.data.as_slice()
    }
}

impl AsMut<[u8]> for SecureBlob {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data.as_mut_slice()
    }
}

impl Debug for SecureBlob {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "<SecureBlob[{}]>", self.data.len())
    }
}

impl Display for SecureBlob {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "<SecureBlob[{}]>", self.data.len())
    }
}

/// Takes ownership of the Vec.
impl From<Vec<u8>> for SecureBlob {
    fn from(v: Vec<u8>) -> Self {
        SecureBlob { data: v }
    }
}

/// Zeroizes the source after it is copied into the SecureBlob.
impl From<&mut [u8]> for SecureBlob {
    fn from(v: &mut [u8]) -> Self {
        let mut sec = SecureBlob { data: Vec::new() };
        sec.data.reserve_exact(v.len());
        sec.data.extend(v.iter().copied());
        v.zeroize();
        sec
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use std::mem::take;

    const TEST_DATA: &[u8; 6] = b"secret";

    #[test]
    fn from_vec() {
        let test = TEST_DATA.to_vec();
        let ptr_start = test.as_ptr();
        let secret = SecureBlob::from(test);

        // Make sure the data wasn't copied.
        assert_eq!(secret.data.as_ptr(), ptr_start)
    }

    #[test]
    fn from_slice() {
        let mut test = TEST_DATA.to_vec();
        let ptr_start = test.as_ptr();
        let secret = SecureBlob::from(AsMut::<[u8]>::as_mut(&mut test));

        // Make sure the data was copied.
        assert_ne!(secret.data.as_ptr(), ptr_start);
        // Make sure the original was zeroed.
        assert_eq!(test, [0; TEST_DATA.len()]);
    }

    #[test]
    fn clone() {
        let secret = SecureBlob::from(TEST_DATA.to_vec());
        let cloned_secret = secret.clone();

        drop(secret);

        // Make sure the clone wasn't zeroed.
        assert_eq!(cloned_secret.as_ref(), TEST_DATA);
    }

    #[test]
    fn extendfromslice_norealloc() {
        let test = TEST_DATA.to_vec();
        let mut secret = SecureBlob::with_capacity(TEST_DATA.len());

        assert!(secret.is_empty());
        assert_eq!(secret.capacity(), TEST_DATA.len());

        let middle_index = 3;
        secret.extend_from_slice(&test[0..middle_index]);
        assert_eq!(secret.len(), middle_index);

        secret.extend_from_slice(&test[middle_index..]);
        assert_eq!(secret.as_ref(), test);

        // Make sure there wasn't a realloc.
        assert_eq!(secret.capacity(), TEST_DATA.len());
    }

    #[test]
    fn extendfromslice_realloc() {
        let test = TEST_DATA.to_vec();
        let mut secret = SecureBlob::with_capacity(0);

        assert!(secret.is_empty());
        // Make sure there is a realloc.
        assert_eq!(secret.capacity(), 0);

        secret.extend_from_slice(&test);
        assert_eq!(secret.as_ref(), test);

        assert!(secret.capacity() >= TEST_DATA.len());
    }

    #[test]
    fn check_stack_move() {
        let mut secret = SecureBlob::from(TEST_DATA.to_vec());
        let before_ptr = secret.data.as_ptr();

        let moved = take(&mut secret);

        assert_eq!(moved.data.as_ptr(), before_ptr);
        assert_ne!(secret.data.as_ptr(), before_ptr);
    }

    #[test]
    fn check_heap_move() {
        let mut secret = Box::new(SecureBlob::from(TEST_DATA.to_vec()));
        let before_ptr = secret.data.as_ptr();

        let moved = take(secret.as_mut());

        assert_eq!(moved.data.as_ptr(), before_ptr);
        assert_ne!(secret.data.as_ptr(), before_ptr);
    }
}
