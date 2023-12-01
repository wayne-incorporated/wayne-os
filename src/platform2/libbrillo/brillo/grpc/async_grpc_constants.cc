// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/grpc/async_grpc_constants.h"

namespace brillo {

const int kMaxGrpcMessageSize = 4 * 1024 * 1024;

const base::TimeDelta kMinGrpcReconnectBackoffTime = base::Milliseconds(100);
const base::TimeDelta kInitialGrpcReconnectBackoffTime =
    base::Milliseconds(100);
const base::TimeDelta kMaxGrpcReconnectBackoffTime = base::Seconds(5);

const base::TimeDelta kDefaultRpcDeadline = base::Minutes(1);

}  // namespace brillo
