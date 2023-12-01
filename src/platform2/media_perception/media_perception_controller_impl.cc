// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "media_perception/media_perception_controller_impl.h"

#include <base/functional/bind.h>
#include <base/logging.h>
#include <memory>
#include <utility>

#include "media_perception/media_perception_impl.h"

namespace mri {

namespace {

// To avoid passing a lambda as a base::RepeatingClosure.
void OnConnectionClosedOrError(
    const MediaPerceptionImpl* const media_perception_impl) {
  DLOG(INFO) << "Got closed connection.";
  delete media_perception_impl;
}

}  // namespace

MediaPerceptionControllerImpl::MediaPerceptionControllerImpl(
    mojo::PendingReceiver<
        chromeos::media_perception::mojom::MediaPerceptionController> receiver,
    std::shared_ptr<VideoCaptureServiceClient> video_capture_service_client,
    std::shared_ptr<ChromeAudioServiceClient> chrome_audio_service_client,
    std::shared_ptr<Rtanalytics> rtanalytics)
    : receiver_(this, std::move(receiver)),
      video_capture_service_client_(video_capture_service_client),
      chrome_audio_service_client_(chrome_audio_service_client),
      rtanalytics_(rtanalytics) {}

void MediaPerceptionControllerImpl::set_connection_error_handler(
    base::RepeatingClosure connection_error_handler) {
  receiver_.set_disconnect_handler(std::move(connection_error_handler));
}

void MediaPerceptionControllerImpl::ActivateMediaPerception(
    mojo::PendingReceiver<chromeos::media_perception::mojom::MediaPerception>
        receiver) {
  DLOG(INFO) << "Got request to activate media perception.";

  // Use a connection error handler to strongly bind |media_perception_impl|
  // to |request|.
  MediaPerceptionImpl* const media_perception_impl = new MediaPerceptionImpl(
      std::move(receiver), video_capture_service_client_,
      chrome_audio_service_client_, rtanalytics_);
  media_perception_impl->set_connection_error_handler(base::BindRepeating(
      &OnConnectionClosedOrError, base::Unretained(media_perception_impl)));
}

}  // namespace mri
