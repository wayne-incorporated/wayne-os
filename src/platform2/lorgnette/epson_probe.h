// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LORGNETTE_EPSON_PROBE_H_
#define LORGNETTE_EPSON_PROBE_H_

#include <vector>

#include <lorgnette/proto_bindings/lorgnette_service.pb.h>

#include "lorgnette/manager.h"

// Method for probing for Epson-based network scanners.  The code in
// sane-backends for probing Epson based scanners does not work in
// Chrome OS since it expects a unicast reply to an outgoing broadcast
// probe.  This protocol is simple enough to implement within lorgnette
// and can take advantage of the FirewallManager to temporarily open up
// access to receive a reply.
namespace lorgnette {

class FirewallManager;

namespace epson_probe {

// Probe for Epson-based network scanners.  Use |firewall_manager| to request
// firewall permissions for receiving probe replies.  Return any new entries.
std::vector<ScannerInfo> ProbeForScanners(FirewallManager* firewall_manager);

}  // namespace epson_probe

}  // namespace lorgnette

#endif  // LORGNETTE_EPSON_PROBE_H_
