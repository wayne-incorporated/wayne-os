// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io::{self, Read, Write};

use libchromeos::sys::{debug, error};

/// A Read adapter that ensures that the wrapped reader is always read until EOF.  This is useful
/// for ensuring that we always read complete HTTP messages from the IPP over USB device we're
/// connected to, even if the client disconnects.
///
/// If this is not done, then stale data left over in internal buffers could be sent to clients,
/// resulting in strange bugs.
pub struct CompleteReader<R: Read> {
    reader: R,
    finished: bool,
}

impl<R> CompleteReader<R>
where
    R: Read,
{
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            finished: false,
        }
    }
}

impl<R> Drop for CompleteReader<R>
where
    R: Read,
{
    fn drop(&mut self) {
        if !self.finished {
            let result = io::copy(&mut self.reader, &mut io::sink());
            match result {
                Ok(0) => (),
                Ok(drained) => debug!("* Succesfully drained {} bytes from reader", drained),
                Err(err) => error!("* Draining reader failed: {}", err),
            }
        }
    }
}

impl<R> Read for CompleteReader<R>
where
    R: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let result = self.reader.read(buf);
        match result {
            Ok(0) | Err(_) => self.finished = true,
            _ => (),
        }
        result
    }
}

/// A Read adapter that logs a message every time a data is successfully read.
/// This is used to provide logs of data read from an HTTP client.
pub struct LoggingReader<R: Read> {
    reader: R,
    name: String,
}

impl<R> LoggingReader<R>
where
    R: Read,
{
    pub fn new(reader: R, name: &str) -> Self {
        Self {
            reader,
            name: name.to_string(),
        }
    }
}

impl<R> Read for LoggingReader<R>
where
    R: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let result = self.reader.read(buf);
        match result {
            Ok(0) | Err(_) => (),
            Ok(read) => debug!("* Read {} bytes from {}", read, self.name),
        }
        result
    }
}

/// A Writer adapter that splits written data into HTTP chunked encoding.
/// The format of each chunk is "[data-length in hex]\r\n[data]\r\n",
/// and there is a terminating "0\r\n\r\n" chunk appended to the stream.
pub struct ChunkedWriter<W: Write> {
    writer: W,
    buf: Vec<u8>,
}

impl<W> ChunkedWriter<W>
where
    W: Write,
{
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            buf: Vec::new(),
        }
    }
}

impl<W> Write for ChunkedWriter<W>
where
    W: Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !self.buf.is_empty() {
            let written = self.writer.write(&self.buf)?;
            self.buf.drain(..written);
        }

        self.buf
            .extend_from_slice(format!("{:X}\r\n", buf.len()).as_bytes());
        self.buf.extend_from_slice(buf);
        self.buf.extend_from_slice(b"\r\n");
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.write_all(&self.buf)?;
        self.buf.truncate(0);
        Ok(())
    }
}

impl<W> Drop for ChunkedWriter<W>
where
    W: Write,
{
    fn drop(&mut self) {
        // Append terminating chunk.
        self.buf.extend_from_slice(b"0\r\n\r\n");
        let _ = self.flush();
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Seek, SeekFrom};

    use super::*;

    fn position<S: Seek>(mut s: S) -> u64 {
        s.seek(SeekFrom::Current(0))
            .expect("Getting stream position failed")
    }

    #[test]
    fn complete_reader() {
        let mut buf = Cursor::new(vec![0; 30]);
        let r = CompleteReader::new(&mut buf);
        drop(r);
        assert_eq!(position(&mut buf), 30);

        let mut buf = Cursor::new(vec![0; 30]);
        let mut r = CompleteReader::new(&mut buf);
        let read = r.read(&mut [0; 15]).expect("failed to read from reader");
        assert_eq!(read, 15);
        drop(r);
        assert_eq!(position(&mut buf), 30);

        let mut buf = Cursor::new(vec![0; 30]);
        let mut r = CompleteReader::new(&mut buf);
        let read = r.read(&mut [0; 4]).expect("failed to read from reader");
        assert_eq!(read, 4);
        let read = r.read(&mut [0; 5]).expect("failed to read from reader");
        assert_eq!(read, 5);
        drop(r);
        assert_eq!(position(&mut buf), 30);
    }

    #[test]
    fn chunked_writer() {
        let mut buf = Vec::new();
        let w = ChunkedWriter::new(&mut buf);
        drop(w);
        let expected = "0\r\n\r\n";
        assert_eq!(buf.as_slice(), expected.as_bytes());

        let mut buf = Vec::new();
        let mut w = ChunkedWriter::new(&mut buf);
        let written = w.write(b"test").expect("failed to write chunk");
        assert_eq!(written, 4);
        drop(w);
        let expected = "4\r\ntest\r\n0\r\n\r\n";
        assert_eq!(buf.as_slice(), expected.as_bytes());

        let mut buf = Vec::new();
        let mut w = ChunkedWriter::new(&mut buf);
        let written = w.write(b"test").expect("failed to write chunk");
        assert_eq!(written, 4);
        let to_write = b"slightly longer chunk";
        let written = w.write(to_write).expect("failed to write chunk");
        assert_eq!(written, to_write.len());
        drop(w);
        let expected = "4\r\ntest\r\n15\r\nslightly longer chunk\r\n0\r\n\r\n";
        assert_eq!(buf.as_slice(), expected.as_bytes());
    }
}
