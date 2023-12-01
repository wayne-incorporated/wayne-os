// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/net/io_handler.h"
#include "shill/net/rtnl_handler.h"
#include "shill/net/rtnl_listener.h"

#include <base/at_exit.h>
#include <base/check.h>
#include <base/check_op.h>
#include <base/functional/bind.h>
#include <base/logging.h>

namespace shill {

class RTNLHandlerFuzz {
 public:
  static void Run(const uint8_t* data, size_t size) {
    base::AtExitManager exit_manager;
    InputData input(static_cast<const unsigned char*>(data), size);

    // Listen for all messages.
    RTNLListener listener(~0, base::BindRepeating(&RTNLHandlerFuzz::Listener));
    RTNLHandler::GetInstance()->ParseRTNL(&input);
  }

 private:
  static void Listener(const RTNLMessage& msg) {
    CHECK_NE(msg.ToString(), "");

    const auto& bytes = msg.Encode();
    switch (msg.type()) {
      case RTNLMessage::kTypeRdnss:
      case RTNLMessage::kTypeDnssl:
        // RDNSS and DNSSL (RTM_NEWNDUSEROPT) don't have "query" modes, so we
        // don't support re-constructing them in user space.
        CHECK(bytes.IsEmpty());
        break;
      default:
        CHECK(!bytes.IsEmpty());
    }
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Turn off logging.
  logging::SetMinLogLevel(logging::LOGGING_FATAL);

  RTNLHandlerFuzz::Run(data, size);
  return 0;
}

}  // namespace shill
