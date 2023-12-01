// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LORGNETTE_CLI_DISCOVERY_HANDLER_H_
#define LORGNETTE_CLI_DISCOVERY_HANDLER_H_

#include <string>

#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <lorgnette/proto_bindings/lorgnette_service.pb.h>

#include "lorgnette/cli/async_handler.h"
#include "lorgnette/dbus-proxies.h"

namespace lorgnette::cli {

// TODO(b/248023651): Add tests for this class when a fake Manager is available.
class DiscoveryHandler : public AsyncHandler {
 public:
  DiscoveryHandler(base::RepeatingClosure quit_closure,
                   org::chromium::lorgnette::ManagerProxy* manager);
  DiscoveryHandler(const DiscoveryHandler&) = delete;
  DiscoveryHandler& operator=(const DiscoveryHandler&) = delete;
  ~DiscoveryHandler() override;
  void ConnectSignal() override;

  bool StartDiscovery();

 private:
  void HandleScannerListChangedSignal(
      const lorgnette::ScannerListChangedSignal& signal);

  std::string session_id_;

  // Keep as the last member variable.
  base::WeakPtrFactory<DiscoveryHandler> weak_factory_{this};
};

}  // namespace lorgnette::cli

#endif  // LORGNETTE_CLI_DISCOVERY_HANDLER_H_
