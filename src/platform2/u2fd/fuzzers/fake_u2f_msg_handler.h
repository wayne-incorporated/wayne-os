// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef U2FD_FUZZERS_FAKE_U2F_MSG_HANDLER_H_
#define U2FD_FUZZERS_FAKE_U2F_MSG_HANDLER_H_

#include <string>

#include "u2fd/client/u2f_apdu.h"
#include "u2fd/u2f_msg_handler_interface.h"

namespace u2f {

class FakeU2fMessageHandler : public U2fMessageHandlerInterface {
 public:
  FakeU2fMessageHandler() = default;
  U2fResponseApdu ProcessMsg(const std::string& request) override;
};

}  // namespace u2f

#endif  // U2FD_FUZZERS_FAKE_U2F_MSG_HANDLER_H_
