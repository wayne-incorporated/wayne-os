// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef U2FD_U2F_MSG_HANDLER_INTERFACE_H_
#define U2FD_U2F_MSG_HANDLER_INTERFACE_H_

#include <string>

#include "u2fd/client/u2f_apdu.h"

namespace u2f {

// Interface of an U2F message handler.
// This is useful for fuzzing and unit testing.
class U2fMessageHandlerInterface {
 public:
  virtual U2fResponseApdu ProcessMsg(const std::string& request) = 0;

  virtual ~U2fMessageHandlerInterface() = default;
};

}  // namespace u2f

#endif  // U2FD_U2F_MSG_HANDLER_INTERFACE_H_
