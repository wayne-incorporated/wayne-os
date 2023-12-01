// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "p2p/common/server_message.h"

#include <glib.h>
#include <inttypes.h>

#include <base/check.h>
#include <base/format_macros.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>

using std::string;

namespace p2p {

namespace util {

bool ValidP2PServerMessageMagic(const P2PServerMessage& message) {
  return message.magic == kP2PServerMagic;
}

bool ParseP2PServerMessageType(uint32_t value, P2PServerMessageType* result) {
  CHECK(result);
  if (value >= kNumP2PServerMessageTypes)
    return false;
  *result = static_cast<P2PServerMessageType>(value);
  return true;
}

bool ParseP2PServerRequestResult(int64_t value,
                                 P2PServerRequestResult* result) {
  CHECK(result);
  if (value < 0 || value >= kNumP2PServerRequestResults)
    return false;
  *result = static_cast<P2PServerRequestResult>(value);
  return true;
}

string ToString(const P2PServerMessage& message) {
  if (message.magic != kP2PServerMagic) {
    return base::StringPrintf(
        "{InvalidMagic[%" PRIx64 "], Unknown[%" PRIu32 "]: %" PRId64 "}",
        message.magic, message.message_type, message.value);
  }

  P2PServerMessageType message_type;
  if (!ParseP2PServerMessageType(message.message_type, &message_type)) {
    return base::StringPrintf("{InvalidType[%" PRIu32 "]: %" PRId64 "}",
                              message.message_type, message.value);
  }

  string res = "{" + ToString(message_type) + ": ";
  if (message_type == kP2PServerRequestResult) {
    P2PServerRequestResult req_res;
    if (!ParseP2PServerRequestResult(message.value, &req_res)) {
      return res + "InvalidRequestResult[" +
             base::NumberToString(message.value) + "]}";
    }
    return res + ToString(req_res) + "}";
  }
  return res + base::NumberToString(message.value) + "}";
}

std::string ToString(P2PServerMessageType message_type) {
  switch (message_type) {
    case kP2PServerNumConnections:
      return "NumConnections";
    case kP2PServerRequestResult:
      return "RequestResult";
    case kP2PServerServedSuccessfullyMB:
      return "ServedSuccessfullyMB";
    case kP2PServerServedInterruptedMB:
      return "ServedInterruptedMB";
    case kP2PServerRangeBeginPercentage:
      return "RangeBeginPercentage";
    case kP2PServerDownloadSpeedKBps:
      return "DownloadSpeedKBps";
    case kP2PServerPeakDownloadSpeedKBps:
      return "PeakDownloadSpeedKBps";
    case kP2PServerClientCount:
      return "ClientCount";
    case kP2PServerPortNumber:
      return "PortNumber";

    case kNumP2PServerMessageTypes:
      return "Unknown";
      // Don't add a default case to let the compiler warn about newly added
      // message types which should be added here.
  }
  return "Unknown";
}

std::string ToString(P2PServerRequestResult request_result) {
  switch (request_result) {
    case kP2PRequestResultResponseSent:
      return "ResponseSent";
    case kP2PRequestResultResponseInterrupted:
      return "ResponseInterrupted";
    case kP2PRequestResultMalformed:
      return "Malformed";
    case kP2PRequestResultNotFound:
      return "NotFound";
    case kP2PRequestResultIndex:
      return "Index";

    case kNumP2PServerRequestResults:
      return "Unknown";
      // Don't add a default case to let the compiler warn about newly added
      // message types which should be added here.
  }
  return "Unknown";
}

}  // namespace util

}  // namespace p2p
