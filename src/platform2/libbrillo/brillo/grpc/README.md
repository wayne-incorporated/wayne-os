This is an adapter for using the gRPC library with a MessageLoop.
Its interface consists of two classes:
* `AsyncGrpcClient` can be used to initiate RPCs and receive the response as a
  Callback.
* `AsyncGrpcServer` can be used to receive RPCs.

At the moment, no authentication is supported, becuase this utility is expected
to be used by two components communicating on the same machine.

## Glossary of chosen names / terms
* The *AsyncGrpcServer* accepts incoming gRPC RPCs.
* The *AsyncGrpcClient* initiates outgoing gRPC RPCs.
* The *Application* is the code using the *AsyncGrpcServer*/*AsyncGrpcClient*.
* A *Handler* is a function which is called for an incoming RPCs. A *Handler*
  must be *registered* to bind an RPC to the function.
* A *RpcState* is an implementation detail for the `AsyncGrpcServer`. It
  holds the necessary state for an expected or incoming RPC.

## AsyncGrpcClient
The `AsyncGrpcClient` accepts the address to send RPCs to and a `TaskRunner` in
its constructor.
Example for sending RPCs:

```
void OnRpcResponse(grpc::Status status,
                   std::unique_ptr<SomeRpcResponse> response) {
  // Process |status| and |response|.
}

std::string outgoing_address = ...;
AsyncGrpcClient<SomeService> client(message_loop.task_runner(),
                                    outgoing_address);
SomeRpcRequest request;
client.CallRpc(&SomeService::Stub::SomeRpc, request,
               base::BindOnce(&OnRpcResponse);
```

## AsyncGrpcServer
The `AsyncGrpcServer` accepts the address to listen on and a `TaskRunner` in its
constructor.
Then, `AsyncGrpcServer::RegisterHandler` must be called for each RPC that this
server should process, binding it to a Callback.
The `AsyncGrpcServer` must be started afterwards to start listening for
requests.

```
void OnSomeRpc(
    std::unique_ptr<SomeRpcRequest> request,
    base::OnceCallback<void(grpc::Status, std::unique_ptr<SomeRpcResponse>)>
        response_callback) {
  // Call |std::move(response_callback).Run(status, response)| when you have a
  // response!
}

std::string listening_address  = ...;
AsyncGrpcServer<SomeService::AsyncService> server(
    message_loop.task_runner(), listening_address);
server.RegisterHandler(&SomeService::AsyncService::RequestSomeRpc,
                       base::BindRepeating(&onSomeRpc));
server.Start();
```

## AsyncGrpcServer implementation notes
### RpcStateBase and RpcState
The `AsyncGrpcServerBase` class does not call gRPC functions or the Handler
directly. Instead, it only contains the general logic for driving RPCs, using
the `RpcStateBase` interface. In contrast, `RpcState` objects implement the
`RpcStateBase` interface and know details that are specific to the request /
response type of the RPC.

The lifecycle of a `RpcState` is:
1. `AsyncGrpcServerBase` instantiates a `RpcState` using a factory function.
   The factory function has been created by registering a Handler for an RPC.
2. `AsyncGrpcServerBase` calls the `RpcStateBase::` to request the RPC in
   gRPC.
3. When the RPC is incoming:
   `AsyncGrpcServerBase` calls `RpcStateBase::CallHandler` to call the Handler.
4. When the Handler is done:
   `AsyncGrpcServerBase` calls `RpcStateBase::Cancel` or
   `RpcStateBase::SendResponse` to cancel the RPC or send the response provided
   by the handler.
5. The `RpcState` object is destroyed.

In short, the responsibilities of a `RpcState` are:
* holding memory for the RPC request and response,
* requesting the RPC in gRPC,
* providing a response to gRPC.
All these responsibilities require knowledge of the RequestType or the
ResponseType.
