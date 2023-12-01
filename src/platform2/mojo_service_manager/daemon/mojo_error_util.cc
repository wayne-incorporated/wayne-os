// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "mojo_service_manager/daemon/mojo_error_util.h"

#include <string>
#include <utility>

namespace chromeos {
namespace mojo_service_manager {

class NullInterface {};

void ResetMojoReceiverPipeWithReason(
    mojo::ScopedMessagePipeHandle receiver_pipe,
    mojom::ErrorCode error,
    const std::string& message) {
  // The pipe can be casted to a receiver with an arbitrary interface type,
  // because we don't actually use the interface.
  mojo::PendingReceiver<NullInterface> receiver{std::move(receiver_pipe)};
  receiver.ResetWithReason(static_cast<uint32_t>(error), message);
}

}  // namespace mojo_service_manager
}  // namespace chromeos
