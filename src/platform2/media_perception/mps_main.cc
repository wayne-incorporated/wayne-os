// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/at_exit.h>
#include <base/logging.h>
#include <memory>

#include "media_perception/chrome_audio_service_client.h"
#include "media_perception/chrome_audio_service_client_impl.h"
#include "media_perception/cros_dbus_service.h"
#include "media_perception/dbus_service.h"
#include "media_perception/rtanalytics.h"
#include "media_perception/video_capture_service_client.h"
#include "media_perception/video_capture_service_client_impl.h"

// Rtanalytics implementation to be fulfilled by the library side.
extern "C" void init_mps(int argc,
                         char** argv,
                         std::shared_ptr<mri::ChromeAudioServiceClient> cras,
                         std::shared_ptr<mri::VideoCaptureServiceClient> vidcap,
                         std::shared_ptr<mri::Rtanalytics>* rtanalytics);

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
  auto cras = std::shared_ptr<mri::ChromeAudioServiceClient>(
      new mri::ChromeAudioServiceClientImpl());
  auto vidcap = std::shared_ptr<mri::VideoCaptureServiceClient>(vidcap_client);
  mojo_connector.SetVideoCaptureServiceClient(vidcap);
  mojo_connector.SetChromeAudioServiceClient(cras);

  auto rtanalytics = std::shared_ptr<mri::Rtanalytics>();
  init_mps(argc, argv, cras, vidcap, &rtanalytics);
  mojo_connector.SetRtanalytics(rtanalytics);

  cros_dbus_service->Connect(mri::Service::MEDIA_PERCEPTION);
  if (!cros_dbus_service->IsConnected()) {
    LOG(ERROR) << "Failed to connect to D-Bus.";
    return EXIT_FAILURE;
  }
  cros_dbus_service->PollMessageQueue();

  return EXIT_SUCCESS;
}
