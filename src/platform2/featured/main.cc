// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <brillo/daemons/daemon.h>
#include <brillo/flag_helper.h>
#include <brillo/message_loops/message_loop.h>
#include <brillo/syslog_logging.h>

#include <fcntl.h>
#include <memory>
#include <stdlib.h>
#include <sysexits.h>

#include "chromeos/dbus/service_constants.h"
#include "dbus/bus.h"
#include "dbus/exported_object.h"
#include "dbus/message.h"
#include "dbus/object_proxy.h"
#include "featured/service.h"
#include "featured/store_impl.h"
#include "featured/store_interface.h"
#include "featured/tmp_storage_impl.h"
#include "featured/tmp_storage_interface.h"

namespace {
class FeatureDaemon : public brillo::Daemon {
 public:
  FeatureDaemon() = default;
  FeatureDaemon(const FeatureDaemon&) = delete;
  FeatureDaemon& operator=(const FeatureDaemon&) = delete;
};
}  // namespace

int main(int argc, char** argv) {
  base::CommandLine::Init(argc, argv);

  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderr);

  // Perform necessary initialization for dbus
  // NOTE: If this declaration moves to _after_ the service->Start() call,
  // service->Start segfaults.
  FeatureDaemon daemon;

  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  scoped_refptr<dbus::Bus> bus = new dbus::Bus(options);
  std::unique_ptr<featured::StoreInterface> store =
      featured::StoreImpl::Create();
  if (!store) {
    LOG(ERROR) << "Could not create StoreImpl instance.";
    return EX_UNAVAILABLE;
  }
  std::unique_ptr<featured::TmpStorageInterface> tmp_storage_impl(nullptr);
  if (store) {
    tmp_storage_impl = std::make_unique<featured::TmpStorageImpl>();
  }
  std::shared_ptr<featured::DbusFeaturedService> service =
      std::make_shared<featured::DbusFeaturedService>(
          std::move(store), std::move(tmp_storage_impl));

  CHECK(service->Start(bus.get(), service)) << "Failed to start featured!";

  int rc = daemon.Run();
  return rc == EX_UNAVAILABLE ? EX_OK : rc;
}
