// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/at_exit.h>
#include <memory>

#include "base/logging.h"
#include "media_perception/cras_client_impl.h"
#include "media_perception/cras_client_wrapper.h"
#include "media_perception/cros_dbus_service.h"
#include "media_perception/dbus_service.h"
#include "media_perception/mojo_connector.h"
#include "media_perception/video_capture_service_client_impl.h"

using DbusServicePtr = std::unique_ptr<mri::DbusService>;
using CrasClientWrapperPtr = std::unique_ptr<mri::CrasClientWrapper>;
using VideoCaptureServiceClientPtr =
    std::unique_ptr<mri::VideoCaptureServiceClient>;
// This is a reference to run_rtanalytics() in the RTA library.
extern "C" int run_rtanalytics(int argc,
                               char** argv,
                               DbusServicePtr&& dbus,
                               CrasClientWrapperPtr&& cras,
                               VideoCaptureServiceClientPtr&& vidcap);

int main(int argc, char** argv) {
  // Needs to exist for creating and starting ipc_thread.
  base::AtExitManager exit_manager;

  mri::MojoConnector mojo_connector;
  mri::CrOSDbusService* cros_dbus_service = new mri::CrOSDbusService();
  cros_dbus_service->SetMojoConnector(&mojo_connector);

  mri::VideoCaptureServiceClientImpl* vidcap_client =
      new mri::VideoCaptureServiceClientImpl();
  vidcap_client->SetMojoConnector(&mojo_connector);

  auto dbus = std::unique_ptr<mri::DbusService>(cros_dbus_service);
  auto cras =
      std::unique_ptr<mri::CrasClientWrapper>(new mri::CrasClientImpl());
  auto vidcap = std::unique_ptr<mri::VideoCaptureServiceClient>(vidcap_client);

  const int return_value = run_rtanalytics(argc, argv, std::move(dbus),
                                           std::move(cras), std::move(vidcap));
  return return_value;
}
