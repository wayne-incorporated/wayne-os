// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_GRPC_ASYNC_GRPC_CONSTANTS_H_
#define LIBBRILLO_BRILLO_GRPC_ASYNC_GRPC_CONSTANTS_H_

#include <base/time/time.h>
#include <brillo/brillo_export.h>

namespace brillo {

// Use this constant to explicitly set gRPC max send/receive message lengths,
// because GRPC_DEFAULT_MAX_SEND_MESSAGE_LENGTH const is -1.
// GRPC_DEFAULT_MAX_SEND_MESSAGE_LENGTH will be used as a default value if max
// send message length is not configured for client and server.
BRILLO_EXPORT extern const int kMaxGrpcMessageSize;

// Use the following constants to control the backoff timer for reconnecting
// used by the GRPC client.

// Sets GRPC_ARG_MIN_RECONNECT_BACKOFF_MS
BRILLO_EXPORT extern const base::TimeDelta kMinGrpcReconnectBackoffTime;
// Sets GRPC_ARG_INITIAL_RECONNECT_BACKOFF_MS
BRILLO_EXPORT extern const base::TimeDelta kInitialGrpcReconnectBackoffTime;
// Sets GRPC_ARG_MAX_RECONNECT_BACKOFF_MS
BRILLO_EXPORT extern const base::TimeDelta kMaxGrpcReconnectBackoffTime;

// Use this constant to set the default deadline for RPC requests performed by
// the GRPC client.
BRILLO_EXPORT extern const base::TimeDelta kDefaultRpcDeadline;

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_GRPC_ASYNC_GRPC_CONSTANTS_H_
