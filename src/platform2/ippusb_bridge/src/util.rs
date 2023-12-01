// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io::{self, BufRead};

/// Read from `reader` until `delimiter` is seen or EOF is reached.
/// Returns read data.
pub fn read_until_delimiter(reader: &mut dyn BufRead, delimiter: &[u8]) -> io::Result<Vec<u8>> {
    let mut result: Vec<u8> = Vec::new();
    loop {
        let buf = match reader.fill_buf() {
            Ok(buf) => buf,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };

        if buf.is_empty() {
            return Ok(result);
        }

        // First check if our delimiter spans the old buffer and the new buffer.
        for split in 1..delimiter.len() {
            let (first_delimiter, second_delimiter) = delimiter.split_at(split);
            if first_delimiter.len() > result.len() || second_delimiter.len() > buf.len() {
                continue;
            }

            let first = result.get(result.len() - first_delimiter.len()..);
            let second = buf.get(..second_delimiter.len());
            if let (Some(first), Some(second)) = (first, second) {
                if first == first_delimiter && second == second_delimiter {
                    result.extend_from_slice(second);
                    reader.consume(second_delimiter.len());
                    return Ok(result);
                }
            }
        }

        // Then check if our delimiter occurs in the new buffer.
        if let Some(i) = buf
            .windows(delimiter.len())
            .position(|window| window == delimiter)
        {
            result.extend_from_slice(&buf[..i + delimiter.len()]);
            reader.consume(i + delimiter.len());
            return Ok(result);
        }

        // Otherwise just copy the entire buffer into result.
        let consumed = buf.len();
        result.extend_from_slice(buf);
        reader.consume(consumed);
    }
}

#[cfg(test)]
mod tests {
    use crate::util::read_until_delimiter;
    use std::io::{BufReader, Cursor};

    #[test]
    fn test_read_until_delimiter() {
        let mut source = Cursor::new(&b"abdcdef"[..]);
        let v = read_until_delimiter(&mut source, b"20").unwrap();
        assert_eq!(v, b"abdcdef");

        let mut source = Cursor::new(&b"abdcdef"[..]);
        let v = read_until_delimiter(&mut source, b"de").unwrap();
        assert_eq!(v, b"abdcde");

        let mut source = Cursor::new(&b"abdcdef"[..]);
        let v = read_until_delimiter(&mut source, b"dc").unwrap();
        assert_eq!(v, b"abdc");

        let mut source = Cursor::new(&b"abdcdef"[..]);
        let v = read_until_delimiter(&mut source, b"abd").unwrap();
        assert_eq!(v, b"abd");

        let mut source = BufReader::with_capacity(2, Cursor::new(&b"abdcdeffegh"[..]));
        let v = read_until_delimiter(&mut source, b"bdc").unwrap();
        assert_eq!(v, b"abdc");

        let v = read_until_delimiter(&mut source, b"ef").unwrap();
        assert_eq!(v, b"def");

        let v = read_until_delimiter(&mut source, b"g").unwrap();
        assert_eq!(v, b"feg");
    }
}
