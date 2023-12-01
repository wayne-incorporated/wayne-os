// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PRINTSCANMGR_DAEMON_DBUS_ADAPTOR_H_
#define PRINTSCANMGR_DAEMON_DBUS_ADAPTOR_H_

#include <memory>

#include <base/memory/scoped_refptr.h>
#include <brillo/dbus/async_event_sequencer.h>
#include <brillo/dbus/dbus_object.h>
#include <brillo/errors/error.h>
#include <dbus/bus.h>
#include <mojo/public/cpp/bindings/pending_remote.h>
#include <printscanmgr/proto_bindings/printscanmgr_service.pb.h>

#include "printscanmgr/daemon/cups_tool.h"
#include "printscanmgr/daemon/printscan_tool.h"
#include "printscanmgr/dbus_adaptors/org.chromium.printscanmgr.h"
#include "printscanmgr/mojom/executor.mojom.h"

namespace printscanmgr {

// Implementation of org::chromium::printscanmgrInterface.
class DbusAdaptor final : public org::chromium::printscanmgrAdaptor,
                          public org::chromium::printscanmgrInterface {
 public:
  explicit DbusAdaptor(mojo::PendingRemote<mojom::Executor> remote);
  DbusAdaptor(const DbusAdaptor&) = delete;
  DbusAdaptor& operator=(const DbusAdaptor&) = delete;
  ~DbusAdaptor() override;

  // Registers the D-Bus object and interface.
  void RegisterAsync(scoped_refptr<dbus::Bus> bus,
                     brillo::dbus_utils::AsyncEventSequencer::CompletionAction
                         completion_action);

  // org::chromium::printscanmgrInterface overrides:
  CupsAddAutoConfiguredPrinterResponse CupsAddAutoConfiguredPrinter(
      const CupsAddAutoConfiguredPrinterRequest& request) override;
  CupsAddManuallyConfiguredPrinterResponse CupsAddManuallyConfiguredPrinter(
      const CupsAddManuallyConfiguredPrinterRequest& request) override;
  CupsRemovePrinterResponse CupsRemovePrinter(
      const CupsRemovePrinterRequest& request) override;
  CupsRetrievePpdResponse CupsRetrievePpd(
      const CupsRetrievePpdRequest& request) override;
  PrintscanDebugSetCategoriesResponse PrintscanDebugSetCategories(
      const PrintscanDebugSetCategoriesRequest& request) override;

 private:
  std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object_;
  CupsTool cups_tool_;
  PrintscanTool printscan_tool_;
};

}  // namespace printscanmgr

#endif  // PRINTSCANMGR_DAEMON_DBUS_ADAPTOR_H_
