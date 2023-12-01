// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A generic RPC implementation that depends on serializable and deserializable enums for requests
//! and responses.

use std::any::Any;
use std::convert::TryInto;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;
use std::result::Result as StdResult;
use std::thread::sleep;
use std::thread::yield_now;
use std::time::Duration;

use log::error;
use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error as ThisError;

use crate::communication;
use crate::communication::read_message;
use crate::communication::write_message;
use crate::communication::NonBlockingMessageReader;
use crate::linux::events::AddEventSourceMutator;
use crate::linux::events::Error as EventsError;
use crate::linux::events::EventMultiplexer;
use crate::linux::events::EventSource;
use crate::linux::events::Mutator;
use crate::linux::events::RemoveFdMutator;
use crate::sys::set_nonblocking;
use crate::transport;
use crate::transport::ServerTransport;
use crate::transport::Transport;
use crate::transport::TransportType;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("failed to create the transport: {0}")]
    NewTransport(#[source] transport::Error),
    // This is used by sirenia-rpc-macros
    #[error("communication failed: {0}")]
    Communication(#[source] communication::Error),
    #[error("failed to add event source to multiplexer: {0}")]
    MultiplexerAddEvent(#[source] EventsError),
    #[error("got the wrong response")]
    ResponseMismatch,
    #[error("failed to set non-blocking: {0}")]
    SetNonBlocking(#[source] libchromeos::sys::Error),
    #[error("partial read.")]
    PartialRead,
    #[error("read failed: {0}")]
    ReadFailed(String),
    #[error("write failed: {0}")]
    WriteFailed(#[source] communication::Error),
    #[error("invoke failed")]
    InvokeFailed,
    #[error("end of stream")]
    EndOfStream,
    #[error("inner error")]
    Inner(Box<dyn Any + Send + Sync + 'static>),
}

type Result<T> = StdResult<T, Error>;

/// Registers an RPC server bound based on the specified TransportType that executes the given
/// handler for each received message. If custom logic is needed to filter incoming connections,
/// use TransportServer with an implementation of ConnectionHandler.
pub fn register_server<H: MessageHandler + 'static>(
    event_multiplexer: &mut EventMultiplexer,
    transport: &TransportType,
    handler: H,
) -> Result<Option<TransportType>> {
    let server = TransportServer::new(transport, SingleRpcConnectionHandler::new(handler))?;
    let listen_addr = server.bound_to().ok();
    let boxed: Box<dyn EventSource> = Box::new(server);
    event_multiplexer
        .add_event(boxed)
        .map_err(Error::MultiplexerAddEvent)?;
    Ok(listen_addr)
}

/// A paring between request and response messages. Define this trait for the desired
/// Request-Response pair to make Invoker<P> available for Transport instances.
pub trait Procedure {
    type Request: Serialize + DeserializeOwned + Debug;
    type Response: Serialize + DeserializeOwned + Debug;
}

/// The server-side implementation of a Procedure. Define this trait for use with RpcDispatcher.
#[allow(clippy::result_unit_err)]
pub trait MessageHandler: Procedure + Clone {
    fn handle_message(&mut self, request: Self::Request) -> StdResult<Self::Response, ()>;
}

/// The client-side of an RPC. Note that this is implemented genericly for Transport.
pub trait Invoker<P: Procedure> {
    fn invoke(&mut self, request: P::Request) -> Result<P::Response>;
}

impl<P: Procedure> Invoker<P> for Transport {
    fn invoke(&mut self, request: P::Request) -> Result<P::Response> {
        write_message(&mut self.w, request).map_err(Error::Communication)?;
        read_message(&mut self.r).map_err(Error::Communication)
    }
}

/// A handler for incoming TransportServer connections.
pub trait ConnectionHandler {
    fn handle_incoming_connection(&mut self, connection: Transport) -> Option<Box<dyn Mutator>>;
}

/// Manages a single RPC connection. Use this in cases where a
pub struct RpcDispatcher<H: MessageHandler + 'static> {
    handler: H,
    transport: Transport,
    reader: NonBlockingMessageReader,
    message_count: usize,
}

impl<H: MessageHandler + 'static> RpcDispatcher<H> {
    pub fn new(handler: H, transport: Transport) -> Self {
        RpcDispatcher {
            handler,
            transport,
            reader: NonBlockingMessageReader::default(),
            message_count: 0,
        }
    }

    pub fn new_nonblocking(handler: H, transport: Transport) -> Result<Self> {
        let mut dispatcher = RpcDispatcher::new(handler, transport);
        dispatcher.set_nonblocking()?;
        Ok(dispatcher)
    }

    pub fn set_nonblocking(&mut self) -> Result<()> {
        set_nonblocking(self.transport.r.as_raw_fd()).map_err(Error::SetNonBlocking)
    }

    pub fn new_as_boxed_mutator(handler: H, transport: Transport) -> Option<Box<dyn Mutator>> {
        match RpcDispatcher::new_nonblocking(handler, transport) {
            Ok(dispatcher) => Some(Box::new(AddEventSourceMutator::from(dispatcher))),
            Err(err) => {
                error!("failed to create dispatcher: {}", err);
                None
            }
        }
    }

    pub fn read_once(&mut self) -> Result<()> {
        match self.reader.read_message(&mut self.transport.r) {
            Ok(Option::<H::Request>::Some(r)) => {
                self.message_count += 1;
                let response = self
                    .handler
                    .handle_message(r)
                    .map_err(|_| Error::InvokeFailed)?;
                write_message(&mut self.transport.w, response).map_err(Error::WriteFailed)
            }
            Ok(Option::<H::Request>::None) => {
                // Wait for more bytes.
                Ok(())
            }
            Err(communication::Error::EmptyRead) => Err(if self.reader.partial_read() {
                Error::PartialRead
            } else {
                Error::EndOfStream
            }),
            Err(e) => Err(Error::ReadFailed(format!("{:?}", e))),
        }
    }

    // Make tests easier to write by providing a blocking message read.
    pub fn read_complete_message(
        &mut self,
        sleep_for: Option<Duration>,
    ) -> StdResult<Option<Box<dyn Mutator>>, String> {
        let start = self.message_count();
        let mut ret = self.on_event();
        while matches!(ret, Ok(None)) && self.message_count() == start {
            if let Some(sleep_for) = sleep_for {
                sleep(sleep_for)
            } else {
                yield_now();
            }
            ret = self.on_event();
        }
        ret
    }

    pub fn reader(&self) -> &NonBlockingMessageReader {
        &self.reader
    }

    pub fn message_count(&self) -> usize {
        self.message_count
    }
}

impl<H: MessageHandler + 'static> AsRawFd for RpcDispatcher<H> {
    fn as_raw_fd(&self) -> RawFd {
        self.transport.as_raw_fd()
    }
}

impl<H: MessageHandler + 'static> Debug for RpcDispatcher<H> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcDispatcher")
            .field("handler", &"impl Handler {}")
            .field("transport", &self.transport)
            .finish()
    }
}

/// Reads RPC messages from the transport and dispatches them to RPC handler.
impl<H: MessageHandler + 'static> EventSource for RpcDispatcher<H> {
    fn on_event(&mut self) -> StdResult<Option<Box<dyn Mutator>>, String> {
        match self.read_once() {
            Ok(()) => return Ok(None),
            Err(Error::EndOfStream) => {}
            Err(e) => {
                error!("RpcHandler error: {:?}", e);
            }
        };
        // The transport is no longer valid and should be removed.
        Ok(Some(Box::new(RemoveFdMutator(self.transport.as_raw_fd()))))
    }
}

pub struct SingleRpcConnectionHandler<H: MessageHandler + 'static> {
    handler: H,
}

impl<H: MessageHandler + 'static> SingleRpcConnectionHandler<H> {
    pub fn new(handler: H) -> Self {
        SingleRpcConnectionHandler { handler }
    }
}

impl<H: MessageHandler + 'static> ConnectionHandler for SingleRpcConnectionHandler<H> {
    fn handle_incoming_connection(&mut self, connection: Transport) -> Option<Box<dyn Mutator>> {
        RpcDispatcher::new_as_boxed_mutator(self.handler.clone(), connection)
    }
}

/// Listens for incoming connections and sets up a RPCHandler for each.
pub struct TransportServer<H: ConnectionHandler> {
    handler: H,
    transport: Box<dyn ServerTransport>,
}

impl<H: ConnectionHandler> TransportServer<H> {
    pub fn new(bind_addr: &TransportType, handler: H) -> Result<Self> {
        Ok(TransportServer {
            handler,
            transport: bind_addr.try_into().map_err(Error::NewTransport)?,
        })
    }

    // Make it possible to bind to an ephemeral port and get the port number later.
    pub fn bound_to(&self) -> StdResult<TransportType, transport::Error> {
        self.transport.bound_to()
    }
}

impl<H: ConnectionHandler> AsRawFd for TransportServer<H> {
    fn as_raw_fd(&self) -> RawFd {
        self.transport.as_raw_fd()
    }
}

impl<H: ConnectionHandler> Debug for TransportServer<H> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportServer")
            .field("handler", &"impl Handler {}")
            .field("transport", &"Box<dyn ServerTransport>")
            .finish()
    }
}

/// Creates a EventSource that adds any accept connections and returns a Mutator that will add the
/// client connection to the EventMultiplexer when applied.
impl<H: ConnectionHandler> EventSource for TransportServer<H> {
    fn on_event(&mut self) -> StdResult<Option<Box<dyn Mutator>>, String> {
        Ok(match self.transport.accept() {
            Ok(t) => self.handler.handle_incoming_connection(t),
            Err(e) => {
                error!("RpcServer error: {:?}", e);
                Some(Box::new(RemoveFdMutator(self.as_raw_fd())))
            }
        })
    }
}

#[cfg(test)]
mod test {
    use std::i32;
    use std::str::FromStr;
    use std::thread::spawn;

    use assert_matches::assert_matches;
    use serde::Deserialize;

    use super::*;
    use crate::transport::ClientTransport;
    use crate::transport::IpClientTransport;

    #[derive(Debug, Serialize, Deserialize)]
    enum Request {
        CheckedNeg(i32),
        CheckedAdd(i32, i32),
        Terminate,
    }

    #[derive(Debug, Serialize, Deserialize)]
    enum Response {
        CheckedNeg(Option<i32>),
        CheckedAdd(Option<i32>),
    }

    #[derive(Clone)]
    struct TestHandler {}

    impl Procedure for TestHandler {
        type Request = Request;
        type Response = Response;
    }

    impl MessageHandler for TestHandler {
        fn handle_message(&mut self, request: Self::Request) -> StdResult<Self::Response, ()> {
            match request {
                Request::CheckedNeg(v) => Ok(Response::CheckedNeg(v.checked_neg())),
                Request::CheckedAdd(a, b) => Ok(Response::CheckedAdd(a.checked_add(b))),
                Request::Terminate => Err(()),
            }
        }
    }

    #[test]
    fn smoke_test() {
        let mut ctx = EventMultiplexer::new().unwrap();
        let server_addr = if let Ok(Some(TransportType::IpConnection(addr))) = register_server(
            &mut ctx,
            &TransportType::from_str("127.0.0.1:0").unwrap(),
            TestHandler {},
        ) {
            addr
        } else {
            panic!();
        };

        let mut client_transport = IpClientTransport::new(server_addr, 0).unwrap();
        let handle = spawn(move || {
            // Queue the client RPC:
            let mut connection = client_transport.connect().unwrap();
            let neg_resp =
                Invoker::<TestHandler>::invoke(&mut connection, Request::CheckedNeg(125)).unwrap();
            assert_matches!(neg_resp, Response::CheckedNeg(Some(-125)));

            let add_resp =
                Invoker::<TestHandler>::invoke(&mut connection, Request::CheckedAdd(5, 4)).unwrap();
            assert_matches!(add_resp, Response::CheckedAdd(Some(9)));

            assert!(Invoker::<TestHandler>::invoke(&mut connection, Request::Terminate).is_err());
        });

        // Handle initial connection.
        ctx.run_once().unwrap();

        // Run until Request::Terminate which should remove the client connection.
        while ctx.len() > 1 {
            ctx.run_once().unwrap();
        }
        handle.join().unwrap();
    }
}
