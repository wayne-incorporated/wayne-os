// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P2P_COMMON_SERVER_MESSAGE_H_
#define P2P_COMMON_SERVER_MESSAGE_H_

#include <string>

namespace p2p {

namespace util {

// Magic value for the P2PServerMessage "magic" field.
const uint64_t kP2PServerMagic = 0x746F68536E6F6F4DULL;  // "MoonShot"

// Messages passed between the p2p-server and the p2p-http-server.
enum P2PServerMessageType {
  kP2PServerNumConnections = 0,
  kP2PServerRequestResult,
  kP2PServerServedSuccessfullyMB,
  kP2PServerServedInterruptedMB,
  kP2PServerRangeBeginPercentage,
  kP2PServerDownloadSpeedKBps,
  kP2PServerPeakDownloadSpeedKBps,
  kP2PServerClientCount,
  kP2PServerPortNumber,

  // Add new P2PServerMessageTypes above this line.
  kNumP2PServerMessageTypes
};

// The possible values passed for a kP2PServerRequestResult message.
enum P2PServerRequestResult {
  // The resource was found and the response served.
  kP2PRequestResultResponseSent = 0,

  // The resource was found but the client disconnected.
  kP2PRequestResultResponseInterrupted,

  kP2PRequestResultMalformed,  // Request was malformed.
  kP2PRequestResultNotFound,   // Requested resource was not found.
  kP2PRequestResultIndex,      // Requested the '/' or '/index.html' resource.

  // Add new P2PServerRequestResults above this line.
  kNumP2PServerRequestResults
};

struct P2PServerMessage {
  uint64_t magic;         // The magic value fixed to be "MoonShot".
  uint32_t message_type;  // The P2PServerMessageType.
  int64_t value;          // The value for the provided message type.
};

// Returns whether the magic field in the provided |message| is valid.
bool ValidP2PServerMessageMagic(const P2PServerMessage& message);

// Converts a uint32_t |value| to a P2PServerMessageType if the provided
// |value| is in range. Returns whether the conversion was successful.
bool ParseP2PServerMessageType(uint32_t value, P2PServerMessageType* result);

// Converts a int64_t |value| to a P2PServerRequestResult if the provided
// |value| is in range. Returns whether the conversion was successful.
bool ParseP2PServerRequestResult(int64_t value, P2PServerRequestResult* result);

// Convertion to human-readable string for debugging purposes.
std::string ToString(const P2PServerMessage& message);
std::string ToString(P2PServerMessageType message_type);
std::string ToString(P2PServerRequestResult request_result);

}  // namespace util

}  // namespace p2p

#endif  // P2P_COMMON_SERVER_MESSAGE_H_
