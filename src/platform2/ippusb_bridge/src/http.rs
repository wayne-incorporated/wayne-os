// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::HashMap;
use std::fmt;
use std::io::{self, BufRead, BufReader, BufWriter, Cursor, Read, Write};
use std::num::ParseIntError;
use std::str::FromStr;

use libchromeos::sys::{debug, error};
use tiny_http::{Header, Method};

use crate::io_adapters::{ChunkedWriter, CompleteReader, LoggingReader};
use crate::usb_connector::UsbConnection;
use crate::util::read_until_delimiter;

// Minimum Request body size, in bytes, before we switch to forwarding requests
// using a chunked Transfer-Encoding.
const CHUNKED_THRESHOLD: usize = 1 << 15;
const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");

#[derive(Debug)]
pub enum Error {
    DuplicateBodyReader,
    EmptyField(String),
    ForwardRequestBody(io::Error),
    MalformedRequest,
    MalformedContentLength(String, ParseIntError),
    ParseResponse(httparse::Error),
    ReadResponseHeader(io::Error),
    WriteRequestHeader(io::Error),
    WriteResponse(io::Error),
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;
        match self {
            DuplicateBodyReader => write!(f, "Attempted to call body_reader() multiple times."),
            EmptyField(field) => write!(f, "HTTP Response field {} was unexpectedly empty", field),
            ForwardRequestBody(err) => write!(f, "Forwarding request body failed: {}", err),
            MalformedRequest => write!(f, "HTTP request is malformed"),
            MalformedContentLength(value, err) => write!(
                f,
                "Failed to parse response Content-Length '{}': {}",
                value, err
            ),
            ParseResponse(err) => write!(f, "Failed to parse HTTP Response header: {}", err),
            ReadResponseHeader(err) => write!(f, "Reading response header failed: {}", err),
            WriteRequestHeader(err) => write!(f, "Writing request header failed: {}", err),
            WriteResponse(err) => write!(f, "Responding to request failed: {}", err),
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Copy, Clone, PartialEq)]
enum BodyLength {
    Chunked,
    Exactly(usize),
}

struct ResponseReader<R: BufRead + Sized> {
    verbose_log: bool,
    reader: R,
    body_length: BodyLength,
    header_was_read: bool,
    created_body_reader: bool,
}

impl<R> ResponseReader<R>
where
    R: BufRead + Sized,
{
    fn new(verbose_log: bool, reader: R) -> ResponseReader<R> {
        ResponseReader {
            verbose_log,
            reader,
            // Assume body is empty unless we see a header to the contrary.
            body_length: BodyLength::Exactly(0),
            header_was_read: false,
            created_body_reader: false,
        }
    }

    fn read_header(&mut self) -> Result<(tiny_http::StatusCode, Vec<Header>)> {
        self.header_was_read = true;

        let buf = read_until_delimiter(&mut self.reader, b"\r\n\r\n")
            .map_err(Error::ReadResponseHeader)?;
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut response = httparse::Response::new(&mut headers);
        let (status, headers) = match response.parse(&buf).map_err(Error::ParseResponse)? {
            httparse::Status::Complete(i) if i == buf.len() => {
                let code = response
                    .code
                    .ok_or_else(|| Error::EmptyField("code".to_owned()))?;
                let status = tiny_http::StatusCode::from(code);
                let version = response
                    .version
                    .ok_or_else(|| Error::EmptyField("version".to_owned()))?;
                debug!(
                    "> HTTP/1.{} {} {}",
                    version,
                    code,
                    status.default_reason_phrase()
                );
                let mut parsed_headers = Vec::new();
                for header in headers.iter().take_while(|&&h| h != httparse::EMPTY_HEADER) {
                    if let Ok(h) = Header::from_bytes(header.name, header.value) {
                        if self.verbose_log {
                            debug!("  {}: {}", h.field, h.value);
                        }
                        parsed_headers.push(h);
                    } else {
                        error!(
                            "Ignoring malformed header {}:{:#?}",
                            header.name, header.value
                        );
                    }
                }
                (status, parsed_headers)
            }
            _ => return Err(Error::MalformedRequest),
        };

        // Determine the size of the body content.
        for header in headers.iter() {
            if header.field.equiv("Content-Length") {
                let length = usize::from_str(header.value.as_str()).map_err(|e| {
                    Error::MalformedContentLength(header.value.as_str().to_string(), e)
                })?;
                self.body_length = BodyLength::Exactly(length);
                break;
            }

            if header.field.equiv("Transfer-Encoding") {
                self.body_length = BodyLength::Chunked;
                break;
            }
        }

        Ok((status, headers))
    }

    fn body_reader<'r>(&'r mut self) -> Result<Box<dyn Read + 'r>> {
        if self.created_body_reader {
            return Err(Error::DuplicateBodyReader);
        }

        self.created_body_reader = true;
        match self.body_length {
            BodyLength::Exactly(length) => {
                let reader = (&mut self.reader).take(length as u64);
                Ok(Box::new(CompleteReader::new(reader)))
            }
            BodyLength::Chunked => {
                let reader = chunked_transfer::Decoder::new(&mut self.reader);
                Ok(Box::new(CompleteReader::new(reader)))
            }
        }
    }
}

impl<R> Drop for ResponseReader<R>
where
    R: BufRead,
{
    fn drop(&mut self) {
        if !self.created_body_reader {
            debug!("Draining in drop");
            if !self.header_was_read {
                // Read header to figure out how long the body is.
                let _ = self.read_header();
            }

            // Create a body reader which will totally read the response on drop.
            let _ = self.body_reader();
        }
    }
}

fn is_end_to_end(header: &Header) -> bool {
    !matches!(
        header.field.as_str().as_str(),
        "Connection"
        | "Expect" // Technically end-to-end, but we want to filter it.
        | "Keep-Alive"
        | "Proxy-Authenticate"
        | "Proxy-Authorization"
        | "TE"
        | "Trailers"
        | "Transfer-Encoding"
        | "Upgrade"
    )
}

fn supports_request_body(method: &Method) -> bool {
    !matches!(
        method,
        Method::Get | Method::Head | Method::Delete | Method::Options | Method::Trace
    )
}

#[derive(Eq)]
struct HeaderField {
    value: String,
}

impl HeaderField {
    fn new(value: &str) -> Self {
        Self {
            value: value.to_string(),
        }
    }
}

impl std::cmp::PartialEq for HeaderField {
    fn eq(&self, other: &Self) -> bool {
        self.value.eq_ignore_ascii_case(&other.value)
    }
}

impl std::hash::Hash for HeaderField {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.value.to_ascii_lowercase().hash(state);
    }
}

impl fmt::Display for HeaderField {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

struct Headers {
    values: HashMap<HeaderField, Vec<String>>,
}

impl Headers {
    pub fn new() -> Self {
        Headers {
            values: HashMap::new(),
        }
    }

    pub fn delete_header(&mut self, k: &str) -> Option<Vec<String>> {
        self.values.remove(&HeaderField::new(k))
    }

    pub fn add_header(&mut self, k: &str, v: &str) {
        self.values
            .entry(HeaderField::new(k))
            .or_default()
            .push(v.to_string());
    }

    pub fn has_header(&self, k: &str) -> bool {
        self.values.contains_key(&HeaderField::new(k))
    }
}

struct Request {
    method: String,
    url: String,
    headers: Headers,
    body_length: BodyLength,
    forwarded_body_length: BodyLength,
}

// Converts a tiny_http::Request into our internal Request format.
// Filter out Hop-by-hop headers and add Content-Length or Transfer-Encoding
// headers as needed.
fn rewrite_request(request: &tiny_http::Request) -> Request {
    let mut headers = Headers::new();
    // If the incoming request specifies a Transfer-Encoding, it must be chunked.
    let request_is_chunked = request
        .headers()
        .iter()
        .any(|h| h.field.equiv("Transfer-Encoding"));

    for header in request.headers().iter().filter(|&h| is_end_to_end(h)) {
        // Call as_str() twice for conversion from header name to &AsciiStr to &str.
        headers.add_header(header.field.as_str().as_str(), header.value.as_str());
    }

    let body_length = if !supports_request_body(request.method()) {
        BodyLength::Exactly(0)
    } else if request_is_chunked {
        BodyLength::Chunked
    } else if let Some(length) = request.body_length() {
        BodyLength::Exactly(length)
    } else {
        BodyLength::Exactly(0)
    };

    headers.delete_header("User-Agent");
    let user_agent = format!("ippusb_bridge/{}", VERSION.unwrap_or("unknown"));
    headers.add_header("User-Agent", &user_agent);

    // If the request body is relatively small, don't use a chunked encoding for
    // the proxied request.
    let forwarded_body_length = match body_length {
        BodyLength::Exactly(length) if length < CHUNKED_THRESHOLD => body_length,
        _ => BodyLength::Chunked,
    };

    if forwarded_body_length == BodyLength::Chunked {
        // Content-Length and chunked encoding are mutually exclusive.
        // We don't need to delete any existing Transfer-Encoding since it's a
        // Hop-by-hop header and is already filtered out above.
        headers.delete_header("Content-Length");
        headers.add_header("Transfer-Encoding", "chunked");
    } else if !headers.has_header("Content-Length") {
        headers.add_header("Content-Length", "0");
    }

    Request {
        method: request.method().to_string(),
        url: request.url().to_string(),
        headers,
        body_length,
        forwarded_body_length,
    }
}

fn serialize_request_header(
    verbose_log: bool,
    request: &Request,
    writer: &mut dyn Write,
) -> io::Result<()> {
    write!(writer, "{} {} HTTP/1.1\r\n", request.method, request.url)?;
    if verbose_log {
        debug!("{} {} HTTP/1.1\\r\n", request.method, request.url);
    }
    for (field, values) in request.headers.values.iter() {
        for value in values.iter() {
            write!(writer, "{}: {}\r\n", field, value)?;
            if verbose_log {
                debug!("  {}: {}\\r", field, value);
            }
        }
    }

    write!(writer, "\r\n")?;
    if verbose_log {
        debug!("\\r");
    }
    writer.flush()
}

pub fn handle_request(
    verbose_log: bool,
    usb: UsbConnection,
    mut request: tiny_http::Request,
) -> Result<()> {
    debug!(
        "< {} {} HTTP/1.{}",
        request.method(),
        request.url(),
        request.http_version().1
    );

    // Filter out headers that should not be forwarded, and update Content-Length and
    // Transfer-Encoding headers based on how the body (if any) will be transferred.
    let new_request = rewrite_request(&request);

    let mut logging_reader = LoggingReader::new(request.as_reader(), "client");
    let mut request_body: Box<dyn Read> = match new_request.forwarded_body_length {
        BodyLength::Exactly(length) => {
            // If we're not using chunked, we must have the entire request body before beginning to
            // forward the request. If we didn't and the client were to drop in the middle of
            // forwarding a request, we would have no way of cleanly terminating the connection.
            let mut buf = Vec::with_capacity(length);
            io::copy(&mut logging_reader, &mut buf).map_err(Error::ForwardRequestBody)?;
            Box::new(Cursor::new(buf))
        }
        _ => Box::new(logging_reader),
    };

    let mut usb_writer = BufWriter::new(&usb);
    // Write the modified request header to the printer.
    serialize_request_header(verbose_log, &new_request, &mut usb_writer)
        .map_err(Error::WriteRequestHeader)?;

    // Now that we have written data to the printer, we must ensure that we read
    // a complete HTTP response from the printer. Otherwise, that data may
    // remain in the printer's buffers and be sent to some other client.
    // ResponseReader ensures that this happens internally.
    let usb_reader = BufReader::new(LoggingReader::new(&usb, "printer"));
    let mut response_reader = ResponseReader::new(verbose_log, usb_reader);

    if new_request.body_length != BodyLength::Exactly(0) {
        debug!("* Forwarding client request body");
        let mut writer: Box<dyn Write> = match new_request.forwarded_body_length {
            BodyLength::Chunked => Box::new(ChunkedWriter::new(usb_writer)),
            _ => Box::new(usb_writer),
        };
        io::copy(&mut request_body, &mut writer).map_err(Error::ForwardRequestBody)?;
        writer.flush().map_err(Error::ForwardRequestBody)?;
    }
    drop(request_body);

    debug!("* Reading printer response header");
    let (status, headers) = response_reader.read_header()?;

    debug!("* Forwarding printer response body");
    let body_reader = response_reader.body_reader()?;
    let response = tiny_http::Response::new(status, headers, body_reader, None, None);
    request.respond(response).map_err(Error::WriteResponse)?;

    debug!("* Finished processing request");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_support() {
        use ascii::AsciiString;

        assert!(!supports_request_body(&Method::Get));
        assert!(!supports_request_body(&Method::Head));
        assert!(!supports_request_body(&Method::Options));
        assert!(!supports_request_body(&Method::Delete));
        assert!(!supports_request_body(&Method::Trace));
        assert!(supports_request_body(&Method::Post));
        assert!(supports_request_body(&Method::Put));
        assert!(supports_request_body(&Method::Patch));
        assert!(supports_request_body(&Method::NonStandard(
            AsciiString::from_ascii("TEST".to_string()).unwrap()
        )));
    }

    #[test]
    fn e2e_header() {
        let header = Header::from_bytes(&b"Content-Type"[..], &b"text/xml"[..]).unwrap();
        assert!(is_end_to_end(&header));

        let header = Header::from_bytes(&b"Connection"[..], &b"close"[..]).unwrap();
        assert!(!is_end_to_end(&header));

        let header = Header::from_bytes(&b"Keep-Alive"[..], &b"timeout=5, max=10"[..]).unwrap();
        assert!(!is_end_to_end(&header));

        let header = Header::from_bytes(&b"Transfer-Encoding"[..], &b"chunked"[..]).unwrap();
        assert!(!is_end_to_end(&header));

        // Special case since Expect is normally end-to-end.
        let header = Header::from_bytes(&b"Expect"[..], &b"100-continue"[..]).unwrap();
        assert!(!is_end_to_end(&header));
    }
}
