// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include "shill/net/byte_string.h"
#include "shill/net/nl80211_message.h"

#include <base/logging.h>

namespace shill {
namespace {

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Turn off logging.
  logging::SetMinLogLevel(logging::LOGGING_FATAL);

  Nl80211Frame frame(ByteString(data, size));
  std::string output = frame.ToString();

  return 0;
}

}  // namespace
}  // namespace shill
