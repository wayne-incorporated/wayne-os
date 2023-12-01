// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "u2fd/fuzzers/fake_u2f_msg_handler.h"

namespace u2f {

U2fResponseApdu FakeU2fMessageHandler::ProcessMsg(const std::string& request) {
  return U2fResponseApdu();
}

}  // namespace u2f
