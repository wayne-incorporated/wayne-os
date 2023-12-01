// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MEDIA_PERCEPTION_MEDIA_PERCEPTION_CONTROLLER_IMPL_H_
#define MEDIA_PERCEPTION_MEDIA_PERCEPTION_CONTROLLER_IMPL_H_

#include <memory>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/receiver.h>

#include "media_perception/chrome_audio_service_client.h"
#include "media_perception/mojom/media_perception_service.mojom.h"
#include "media_perception/rtanalytics.h"
#include "media_perception/video_capture_service_client.h"

namespace mri {

class MediaPerceptionControllerImpl
    : public chromeos::media_perception::mojom::MediaPerceptionController {
 public:
  MediaPerceptionControllerImpl(
      mojo::PendingReceiver<
          chromeos::media_perception::mojom::MediaPerceptionController>
          receiver,
      std::shared_ptr<VideoCaptureServiceClient> video_capture_service_client,
      std::shared_ptr<ChromeAudioServiceClient> chrome_audio_service_client,
      std::shared_ptr<Rtanalytics> rtanalytics);
  MediaPerceptionControllerImpl(const MediaPerceptionControllerImpl&) = delete;
  MediaPerceptionControllerImpl& operator=(
      const MediaPerceptionControllerImpl&) = delete;

  void set_connection_error_handler(
      base::RepeatingClosure connection_error_handler);

  // chromeos::media_perception::mojom::MediaPerceptionController:
  void ActivateMediaPerception(
      mojo::PendingReceiver<chromeos::media_perception::mojom::MediaPerception>
          receiver) override;

 private:
  mojo::Receiver<chromeos::media_perception::mojom::MediaPerceptionController>
      receiver_;

  std::shared_ptr<VideoCaptureServiceClient> video_capture_service_client_;
  std::shared_ptr<ChromeAudioServiceClient> chrome_audio_service_client_;

  std::shared_ptr<Rtanalytics> rtanalytics_;
};

}  // namespace mri

#endif  // MEDIA_PERCEPTION_MEDIA_PERCEPTION_CONTROLLER_IMPL_H_
