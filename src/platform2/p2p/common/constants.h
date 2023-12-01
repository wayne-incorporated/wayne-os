// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P2P_COMMON_CONSTANTS_H_
#define P2P_COMMON_CONSTANTS_H_

#include <stdint.h>

namespace p2p {

namespace constants {

// The maximum number of simulatenous downloads in the LAN.
constexpr int kMaxSimultaneousDownloads = 3;

// The number of seconds to wait when waiting for the number
// of p2p downloads in the LAN to drop below
// kMaxSimultaneousDownloads.
constexpr int kMaxSimultaneousDownloadsPollTimeSeconds = 30;

// The maximum rate per download, in bytes per second. Currently set
// to 125 kB/s.
constexpr int64_t kMaxSpeedPerDownload = 125 * 1000;

// The name of p2p server binary.
constexpr char kServerBinaryName[] = "p2p-server";

// The name of p2p HTTP server binary.
constexpr char kHttpServerBinaryName[] = "p2p-http-server";

// The default TCP port for the HTTP server ("AU").
constexpr uint16_t kHttpServerDefaultPort = 16725;

// The path of the directory for peer to peer content.
constexpr char kP2PDir[] = "/var/cache/p2p";

// Universal constants used for unit conversion.
constexpr int64_t kBytesPerKB = 1000;
constexpr int64_t kBytesPerMB = 1000000;

}  // namespace constants

}  // namespace p2p

#endif  // P2P_COMMON_CONSTANTS_H_
