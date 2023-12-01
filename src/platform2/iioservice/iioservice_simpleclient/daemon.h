// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IIOSERVICE_IIOSERVICE_SIMPLECLIENT_DAEMON_H_
#define IIOSERVICE_IIOSERVICE_SIMPLECLIENT_DAEMON_H_

#include <memory>
#include <string>

#include <brillo/daemons/daemon.h>
#include <mojo/core/embedder/scoped_ipc_support.h>
#include <mojo_service_manager/lib/connect.h>

#include "iioservice/iioservice_simpleclient/sensor_client.h"

namespace iioservice {

class Daemon : public brillo::Daemon {
 public:
  ~Daemon() override;

 protected:
  Daemon();

  // Initializes |sensor_client_| (observer, query) that will interact with the
  // sensors as clients.
  virtual void SetSensorClient() = 0;

  // brillo::Daemon overrides:
  int OnInit() override;

  // Responds to iioservice Mojo disconnection by quitting the daemon.
  void OnMojoDisconnect();

  SensorClient::ScopedSensorClient sensor_client_ = {
      nullptr, SensorClient::SensorClientDeleter};

  // IPC Support
  std::unique_ptr<mojo::core::ScopedIPCSupport> ipc_support_;

 private:
  void ConnectToMojoServiceManager();

  void OnServiceManagerDisconnect(uint32_t custom_reason,
                                  const std::string& description);

  mojo::Remote<chromeos::mojo_service_manager::mojom::ServiceManager>
      service_manager_;
};

}  // namespace iioservice

#endif  // IIOSERVICE_IIOSERVICE_SIMPLECLIENT_DAEMON_H_
