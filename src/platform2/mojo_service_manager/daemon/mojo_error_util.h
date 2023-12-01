// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MOJO_SERVICE_MANAGER_DAEMON_MOJO_ERROR_UTIL_H_
#define MOJO_SERVICE_MANAGER_DAEMON_MOJO_ERROR_UTIL_H_

#include <string>

#include <mojo/public/cpp/bindings/pending_receiver.h>

#include "mojo_service_manager/lib/mojom/service_manager.mojom.h"

namespace chromeos {
namespace mojo_service_manager {

// Resets a message pipe of a receiver with reason.
void ResetMojoReceiverPipeWithReason(
    mojo::ScopedMessagePipeHandle receiver_pipe,
    mojom::ErrorCode error,
    const std::string& message);

}  // namespace mojo_service_manager
}  // namespace chromeos

#endif  // MOJO_SERVICE_MANAGER_DAEMON_MOJO_ERROR_UTIL_H_
