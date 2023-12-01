// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "lorgnette/cli/discovery_handler.h"

#include <iostream>
#include <memory>

#include <brillo/errors/error.h>
#include <base/functional/bind.h>
#include <base/logging.h>

namespace lorgnette::cli {

namespace {

constexpr char kClientID[] = "lorgnette_cli";

}  // namespace

DiscoveryHandler::DiscoveryHandler(
    base::RepeatingClosure quit_closure,
    org::chromium::lorgnette::ManagerProxy* manager)
    : AsyncHandler(quit_closure, manager) {}

DiscoveryHandler::~DiscoveryHandler() {
  if (!session_id_.empty()) {
    StopScannerDiscoveryRequest request;
    request.set_session_id(session_id_);
    StopScannerDiscoveryResponse response;
    brillo::ErrorPtr error;
    if (!manager_->StopScannerDiscovery(request, &response, &error)) {
      LOG(ERROR) << "Failed to stop discovery session: " << error->GetMessage();
    }
  }
}

void DiscoveryHandler::ConnectSignal() {
  manager_->RegisterScannerListChangedSignalHandler(
      base::BindRepeating(&DiscoveryHandler::HandleScannerListChangedSignal,
                          weak_factory_.GetWeakPtr()),
      base::BindOnce(&DiscoveryHandler::OnConnectedCallback,
                     weak_factory_.GetWeakPtr()));
}

bool DiscoveryHandler::StartDiscovery() {
  StartScannerDiscoveryRequest request;
  request.set_client_id(kClientID);
  brillo::ErrorPtr error;
  StartScannerDiscoveryResponse response;
  if (!manager_->StartScannerDiscovery(request, &response, &error)) {
    LOG(ERROR) << "Failed to call StartScannerDiscovery: "
               << error->GetMessage();
    return false;
  }

  if (!response.started()) {
    return false;
  }

  session_id_ = response.session_id();
  return true;
}

void DiscoveryHandler::HandleScannerListChangedSignal(
    const ScannerListChangedSignal& signal) {
  if (signal.session_id() != session_id_) {
    return;
  }

  switch (signal.event_type()) {
    case ScannerListChangedSignal::SCANNER_ADDED:
      std::cout << "  + " << signal.scanner().name() << std::endl;
      break;

    case ScannerListChangedSignal::SCANNER_REMOVED:
      std::cout << "  - " << signal.scanner().name() << std::endl;
      break;

    case ScannerListChangedSignal::ENUM_COMPLETE:
      std::cout << "Enumeration complete" << std::endl;
      quit_closure_.Run();
      break;

    default:
      LOG(ERROR) << "Unknown event received: " << signal.event_type();
      break;
  }
}

}  // namespace lorgnette::cli
