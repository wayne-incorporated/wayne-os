// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "media_perception/media_perception_service_impl.h"

#include <utility>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>

#include "media_perception/media_perception_controller_impl.h"

namespace mri {

namespace {

void OnConnectionClosedOrError(
    const MediaPerceptionControllerImpl* const controller) {
  LOG(WARNING) << "Got closed connection.";
  delete controller;
}

}  // namespace

MediaPerceptionServiceImpl::MediaPerceptionServiceImpl(
    mojo::ScopedMessagePipeHandle pipe,
    base::RepeatingClosure connection_error_handler,
    std::shared_ptr<VideoCaptureServiceClient> video_capture_service_client,
    std::shared_ptr<ChromeAudioServiceClient> chrome_audio_service_client,
    std::shared_ptr<Rtanalytics> rtanalytics)
    : receiver_(this,
                mojo::PendingReceiver<
                    chromeos::media_perception::mojom::MediaPerceptionService>(
                    std::move(pipe))),
      video_capture_service_client_(video_capture_service_client),
      chrome_audio_service_client_(chrome_audio_service_client),
      rtanalytics_(rtanalytics) {
  receiver_.set_disconnect_handler(std::move(connection_error_handler));
}

void MediaPerceptionServiceImpl::GetController(
    mojo::PendingReceiver<
        chromeos::media_perception::mojom::MediaPerceptionController> receiver,
    mojo::PendingRemote<
        chromeos::media_perception::mojom::MediaPerceptionControllerClient>
        client) {
  client_ = mojo::Remote<
      chromeos::media_perception::mojom::MediaPerceptionControllerClient>(
      std::move(client));

  // Use a connection error handler to strongly bind |controller| to |request|.
  MediaPerceptionControllerImpl* const controller =
      new MediaPerceptionControllerImpl(
          std::move(receiver), video_capture_service_client_,
          chrome_audio_service_client_, rtanalytics_);
  controller->set_connection_error_handler(base::BindRepeating(
      &OnConnectionClosedOrError, base::Unretained(controller)));
}

void MediaPerceptionServiceImpl::ConnectToVideoCaptureService(
    mojo::PendingReceiver<video_capture::mojom::VideoSourceProvider> receiver) {
  if (client_)
    client_->ConnectToVideoCaptureService(std::move(receiver));
}

}  // namespace mri
