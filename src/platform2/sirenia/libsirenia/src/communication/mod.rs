// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Handles the communication abstraction for sirenia. Used both for
//! communication between dugong and trichechus and between TEEs and
//! trichechus.

pub mod persistence;
pub mod tee_api;
pub mod trichechus;

use std::array::TryFromSliceError;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt;
use std::fmt::Debug;
use std::io;
use std::io::BufWriter;
use std::io::Read;
use std::io::Write;
use std::ops::Deref;
use std::result::Result as StdResult;

use flexbuffers::FlexbufferSerializer;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde::Serialize;
use serde_bytes::ByteBuf;
use thiserror::Error as ThisError;

use crate::sys::eagain_is_ok;

pub const LENGTH_BYTE_SIZE: usize = 4;

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("failed to read: {0}")]
    Read(#[source] io::Error),
    #[error("no data to read from socket")]
    EmptyRead,
    #[error("failed to write: {0}")]
    Write(#[source] io::Error),
    #[error("error deserializing: {0}")]
    Deserialize(#[source] flexbuffers::DeserializationError),
    #[error("error serializing: {0}")]
    Serialize(#[source] flexbuffers::SerializationError),
}

/// The result of an operation in this crate.
pub type Result<T> = StdResult<T, Error>;

#[derive(Debug)]
pub struct NonBlockingMessageReader {
    read_buffer: Vec<u8>,
    read_size: usize,
    read_target: Option<usize>,
}

impl NonBlockingMessageReader {
    pub fn partial_read(&self) -> bool {
        self.read_size != 0 || self.read_target.is_some()
    }

    pub fn remaining(&self) -> Option<usize> {
        self.read_target.map(|a| a - self.read_size)
    }

    pub fn clear(&mut self) {
        self.read_buffer.clear();
        self.read_buffer.resize(LENGTH_BYTE_SIZE, 0u8);
        self.read_size = 0;
        self.read_target = None;
    }

    fn try_read<R: Read>(&mut self, r: &mut R) -> Result<()> {
        if let Some(size) =
            eagain_is_ok(r.read(&mut self.read_buffer.as_mut_slice()[self.read_size..]))
                .map_err(Error::Read)?
        {
            if size == 0 {
                return Err(Error::EmptyRead);
            }
            self.read_size += size;
        }
        Ok(())
    }

    pub fn read_message<'de, R: Read, D: Deserialize<'de>>(
        &'de mut self,
        r: &mut R,
    ) -> Result<Option<D>> {
        if self.read_target.is_none() {
            if self.read_size == 0 {
                // Perform a clear since self.read_buffer might have been borrowed.
                self.read_buffer.clear();
                self.read_buffer.resize(LENGTH_BYTE_SIZE, 0u8);
            }

            // Read the length of the serialized message first.
            debug_assert_eq!(self.read_buffer.len(), LENGTH_BYTE_SIZE);
            self.try_read(r)?;
            if self.read_size < LENGTH_BYTE_SIZE {
                return Ok(None);
            }

            let target =
                u32::from_be_bytes(self.read_buffer.as_slice().try_into().unwrap()) as usize;
            self.read_size = 0;
            self.read_target = Some(target);
            self.read_buffer.clear();
            self.read_buffer.resize(target, 0);
        }
        // Read the serialized message.
        let message_size = self.read_target.unwrap();
        if message_size == 0 {
            return Err(Error::EmptyRead);
        }
        debug_assert_eq!(self.read_buffer.len(), message_size);

        self.try_read(r)?;
        if self.read_size < message_size {
            return Ok(None);
        }
        // Partial clear since self.read_buffer will be borrowed.
        self.read_size = 0;
        self.read_target = None;

        let ret = flexbuffers::from_slice(self.read_buffer.as_slice())
            .map(Some)
            .map_err(Error::Deserialize);
        ret
    }
}

impl Default for NonBlockingMessageReader {
    fn default() -> Self {
        NonBlockingMessageReader {
            read_buffer: vec![0u8; LENGTH_BYTE_SIZE],
            read_size: 0,
            read_target: None,
        }
    }
}

// Reads a message from the given Read. First reads a u32 that says the length
// of the serialized message, then reads the serialized message and
// deserializes it.
pub fn read_message<R: Read, D: DeserializeOwned>(r: &mut R) -> Result<D> {
    // Read the length of the serialized message first
    let mut buf = [0; LENGTH_BYTE_SIZE];
    r.read_exact(&mut buf).map_err(Error::Read)?;

    let message_size: u32 = u32::from_be_bytes(buf);

    if message_size == 0 {
        return Err(Error::EmptyRead);
    }

    // Read the actual serialized message
    let mut ser_message = vec![0; message_size as usize];
    r.read_exact(&mut ser_message).map_err(Error::Read)?;

    flexbuffers::from_slice(&ser_message).map_err(Error::Deserialize)
}

// Writes the given message to the given Write. First writes the length of the
// serialized message then the serialized message itself.
pub fn write_message<W: Write, S: Serialize>(w: &mut W, m: S) -> Result<()> {
    let mut writer = BufWriter::new(w);

    // Serialize the message and calculate the length
    let mut ser = FlexbufferSerializer::new();
    m.serialize(&mut ser).map_err(Error::Serialize)?;

    let len: u32 = ser.view().len() as u32;

    let mut len_ser = FlexbufferSerializer::new();
    len.serialize(&mut len_ser).map_err(Error::Serialize)?;

    writer.write(&len.to_be_bytes()).map_err(Error::Write)?;
    writer.write(ser.view()).map_err(Error::Write)?;

    Ok(())
}

/// Types needed for trichechus RPC

pub const SHA256_SIZE: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(try_from = "ByteBuf")]
pub struct Digest(#[serde(serialize_with = "serde_bytes::serialize")] [u8; SHA256_SIZE]);

impl Deref for Digest {
    type Target = [u8; SHA256_SIZE];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<[u8; SHA256_SIZE]> for Digest {
    fn from(value: [u8; SHA256_SIZE]) -> Self {
        Digest(value)
    }
}

impl TryFrom<&[u8]> for Digest {
    type Error = TryFromSliceError;

    fn try_from(value: &[u8]) -> StdResult<Self, Self::Error> {
        Ok(Digest(value.try_into()?))
    }
}

impl TryFrom<ByteBuf> for Digest {
    type Error = TryFromSliceError;

    fn try_from(value: ByteBuf) -> StdResult<Self, Self::Error> {
        Ok(Digest(value.deref().try_into()?))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.map(|x| format!("{:02x}", x)).join(""))
    }
}

#[cfg(test)]
mod test {
    use std::io::Cursor;
    use std::io::Seek;
    use std::mem::size_of;

    use assert_matches::assert_matches;

    use super::*;

    const TEST_VALUE: u32 = 77;

    #[test]
    fn read_and_write_message() {
        let mut channel = Cursor::new(Vec::<u8>::with_capacity(size_of::<u32>() * 2));

        write_message(&mut channel, TEST_VALUE).unwrap();
        channel.rewind().unwrap();
        assert_matches!(read_message(&mut channel), Ok(TEST_VALUE));

        channel.rewind().unwrap();
        let mut reader = NonBlockingMessageReader::default();
        let ret: Option<u32> = reader.read_message(&mut channel).unwrap();
        assert_matches!(ret, Some(TEST_VALUE));
    }

    #[test]
    fn readmessage_error_read() {
        let mut channel = Cursor::new(Vec::<u8>::with_capacity(size_of::<u32>() * 2));

        let ret: Result<u32> = read_message(&mut channel);
        assert_matches!(ret, Err(Error::Read(_)));
    }

    #[test]
    fn nonblockingmessagereader_error_emptyread() {
        let mut channel = Cursor::new(Vec::<u8>::with_capacity(size_of::<u32>() * 2));
        let mut reader = NonBlockingMessageReader::default();
        let ret: Result<Option<u32>> = reader.read_message(&mut channel);
        assert_matches!(ret, Err(Error::EmptyRead));
    }

    #[test]
    fn nonblockingmessagereader_partial_read() {
        let mut buf = Vec::<u8>::with_capacity(size_of::<u32>() * 2);
        write_message(&mut Cursor::new(&mut buf), TEST_VALUE).unwrap();

        let mut reader = NonBlockingMessageReader::default();
        assert!(!reader.partial_read());
        eprintln!("0 Reader: {:?}", &reader);

        let mut offset = 0;
        const TAKE: usize = 1;
        let ret: Option<u32> = reader
            .read_message(&mut Cursor::new(&mut buf[offset..(offset + TAKE)]))
            .unwrap();
        assert_matches!(ret, None);
        eprintln!("1 Reader: {:?}", &reader);
        offset += TAKE;
        assert_eq!(reader.read_size, offset);
        assert!(reader.partial_read());
        assert_matches!(reader.remaining(), None);

        let remaining: usize = size_of::<u32>() - TAKE;
        let ret: Result<Option<u32>> =
            reader.read_message(&mut Cursor::new(&mut buf[offset..(offset + remaining)]));
        // This is an empty read because the end of the slice is reached trying to read the message.
        assert_matches!(ret, Err(Error::EmptyRead));
        eprintln!("2 Reader: {:?}", &reader);
        offset += remaining;
        assert!(reader.partial_read());
        assert_eq!(reader.read_size, offset - size_of::<u32>());
        assert_matches!(reader.remaining(), Some(v) if v == buf.len() - size_of::<u32>());

        let ret: Option<u32> = reader
            .read_message(&mut Cursor::new(&mut buf[offset..(offset + TAKE)]))
            .unwrap();
        assert_matches!(ret, None);
        eprintln!("3 Reader: {:?}", &reader);
        offset += TAKE;
        assert!(reader.partial_read());
        assert_matches!(reader.remaining(), Some(v) if v == buf.len() - size_of::<u32>() - TAKE);

        let ret: Option<u32> = reader
            .read_message(&mut Cursor::new(&mut buf[offset..]))
            .unwrap();
        assert_matches!(ret, Some(TEST_VALUE));
        eprintln!("4 Reader: {:?}", &reader);
        assert!(!reader.partial_read());
        assert_matches!(reader.remaining(), None);
    }
}
