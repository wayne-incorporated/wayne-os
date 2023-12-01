// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MEDIA_PERCEPTION_MEDIA_PERCEPTION_SERVICE_IMPL_H_
#define MEDIA_PERCEPTION_MEDIA_PERCEPTION_SERVICE_IMPL_H_

#include <memory>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "media_perception/chrome_audio_service_client.h"
#include "media_perception/mojom/media_perception_service.mojom.h"
#include "media_perception/rtanalytics.h"
#include "media_perception/video_capture_service_client.h"

namespace mri {

class MediaPerceptionServiceImpl
    : public chromeos::media_perception::mojom::MediaPerceptionService {
 public:
  // Creates an instance bound to |pipe|. The specified
  // |connection_error_handler| will be invoked if the binding encounters a
  // connection error.
  MediaPerceptionServiceImpl(
      mojo::ScopedMessagePipeHandle pipe,
      base::RepeatingClosure connection_error_handler,
      std::shared_ptr<VideoCaptureServiceClient> video_capture_service_client,
      std::shared_ptr<ChromeAudioServiceClient> chrome_audio_service_client,
      std::shared_ptr<Rtanalytics> rtanalytics);
  MediaPerceptionServiceImpl(const MediaPerceptionServiceImpl&) = delete;
  MediaPerceptionServiceImpl& operator=(const MediaPerceptionServiceImpl&) =
      delete;

  void ConnectToVideoCaptureService(
      mojo::PendingReceiver<video_capture::mojom::VideoSourceProvider>
          receiver);

  // chromeos::media_perception::mojom::MediaPerceptionService:
  void GetController(
      mojo::PendingReceiver<
          chromeos::media_perception::mojom::MediaPerceptionController>
          receiver,
      mojo::PendingRemote<
          chromeos::media_perception::mojom::MediaPerceptionControllerClient>
          client) override;

 private:
  mojo::Remote<
      chromeos::media_perception::mojom::MediaPerceptionControllerClient>
      client_;

  mojo::Receiver<chromeos::media_perception::mojom::MediaPerceptionService>
      receiver_;

  std::shared_ptr<VideoCaptureServiceClient> video_capture_service_client_;
  std::shared_ptr<ChromeAudioServiceClient> chrome_audio_service_client_;

  std::shared_ptr<Rtanalytics> rtanalytics_;
};

}  // namespace mri

#endif  // MEDIA_PERCEPTION_MEDIA_PERCEPTION_SERVICE_IMPL_H_
