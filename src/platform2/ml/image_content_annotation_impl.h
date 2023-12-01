// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_IMAGE_CONTENT_ANNOTATION_IMPL_H_
#define ML_IMAGE_CONTENT_ANNOTATION_IMPL_H_

#include <base/functional/callback_forward.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/receiver.h>

#if USE_ONDEVICE_IMAGE_CONTENT_ANNOTATION
#include "ml/image_content_annotation.h"
#endif
#include "ml/mojom/image_content_annotation.mojom.h"
#include "ml/request_metrics.h"

struct ImageContentAnnotator;

namespace ml {

class ImageContentAnnotationLibrary;

// The implementation of ImageContentAnnotator.
// The implementation will either be a fake implementation when the USE flag is
// disabled, or a real implementation which utilizes libica.so when the USE flag
// is enabled.
// The real implementation will locally identify various entities in images,
// returning MachineID and confidence values. If locale is passed then it
// will also return localized string names of the entities.
// The fake implementation returns errors for all calls, and
// MachineLearningService::LoadImageAnnotator will also return
// FEATURE_NOT_SUPPORTED_ERROR.
class ImageContentAnnotatorImpl
    : public chromeos::machine_learning::mojom::ImageContentAnnotator {
 public:
  static bool Create(
      chromeos::machine_learning::mojom::ImageAnnotatorConfigPtr config,
      mojo::PendingReceiver<
          chromeos::machine_learning::mojom::ImageContentAnnotator> receiver,
      ImageContentAnnotationLibrary* interface);

  ImageContentAnnotatorImpl(const ImageContentAnnotatorImpl&) = delete;
  ImageContentAnnotatorImpl& operator=(const ImageContentAnnotatorImpl&) =
      delete;

 private:
  explicit ImageContentAnnotatorImpl(
      chromeos::machine_learning::mojom::ImageAnnotatorConfigPtr config,
      mojo::PendingReceiver<
          chromeos::machine_learning::mojom::ImageContentAnnotator> receiver,
      ImageContentAnnotationLibrary* interface);

  // Called when mojom connection is destroyed.
  ~ImageContentAnnotatorImpl() override;

  // chromeos::machine_learning::mojom::ImageContentAnnotator:
  void AnnotateRawImage(
      mojo_base::mojom::ReadOnlySharedMemoryRegionPtr rgb_bytes,
      uint32_t width,
      uint32_t height,
      uint32_t line_stride,
      AnnotateRawImageCallback callback) override;
  void AnnotateEncodedImage(
      ::mojo_base::mojom::ReadOnlySharedMemoryRegionPtr encoded_image,
      AnnotateEncodedImageCallback callback) override;

  void ErrorCallback(AnnotateRawImageCallback& callback,
                     RequestMetrics& request_metrics);

  void AnnotateImage(const uint8_t* rgb_bytes,
                     uint32_t width,
                     uint32_t height,
                     uint32_t line_stride,
                     AnnotateRawImageCallback callback,
                     RequestMetrics& request_metrics);

#if USE_ONDEVICE_IMAGE_CONTENT_ANNOTATION
  ImageContentAnnotationLibrary* library_ = nullptr;
  ::ImageContentAnnotator* annotator_ = nullptr;
#endif
  mojo::Receiver<chromeos::machine_learning::mojom::ImageContentAnnotator>
      receiver_;
  bool successfully_loaded_ = false;
};

}  // namespace ml

#endif  // ML_IMAGE_CONTENT_ANNOTATION_IMPL_H_
