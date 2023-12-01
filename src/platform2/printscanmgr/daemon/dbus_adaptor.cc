// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "printscanmgr/daemon/dbus_adaptor.h"

#include <utility>

#include <base/check.h>
#include <base/notreached.h>
#include <dbus/object_path.h>
#include <dbus/printscanmgr/dbus-constants.h>

namespace printscanmgr {

DbusAdaptor::DbusAdaptor(mojo::PendingRemote<mojom::Executor> remote)
    : org::chromium::printscanmgrAdaptor(this),
      printscan_tool_(std::move(remote)) {}

DbusAdaptor::~DbusAdaptor() = default;

void DbusAdaptor::RegisterAsync(
    scoped_refptr<dbus::Bus> bus,
    brillo::dbus_utils::AsyncEventSequencer::CompletionAction
        completion_action) {
  DCHECK(bus);
  dbus_object_ = std::make_unique<brillo::dbus_utils::DBusObject>(
      /*object_manager=*/nullptr, bus,
      dbus::ObjectPath(kPrintscanmgrServicePath));
  dbus_object_->AddOrGetInterface(kPrintscanmgrInterface);
  RegisterWithDBusObject(dbus_object_.get());
  dbus_object_->RegisterAsync(std::move(completion_action));
}

CupsAddAutoConfiguredPrinterResponse DbusAdaptor::CupsAddAutoConfiguredPrinter(
    const CupsAddAutoConfiguredPrinterRequest& request) {
  return cups_tool_.AddAutoConfiguredPrinter(request);
}

CupsAddManuallyConfiguredPrinterResponse
DbusAdaptor::CupsAddManuallyConfiguredPrinter(
    const CupsAddManuallyConfiguredPrinterRequest& request) {
  return cups_tool_.AddManuallyConfiguredPrinter(request);
}

CupsRemovePrinterResponse DbusAdaptor::CupsRemovePrinter(
    const CupsRemovePrinterRequest& request) {
  return cups_tool_.RemovePrinter(request);
}

CupsRetrievePpdResponse DbusAdaptor::CupsRetrievePpd(
    const CupsRetrievePpdRequest& request) {
  return cups_tool_.RetrievePpd(request);
}

PrintscanDebugSetCategoriesResponse DbusAdaptor::PrintscanDebugSetCategories(
    const PrintscanDebugSetCategoriesRequest& request) {
  return printscan_tool_.DebugSetCategories(request);
}

}  // namespace printscanmgr
