// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/image_content_annotation_impl.h"

#include <utility>

#include <base/check.h>
#include <brillo/message_loops/message_loop.h>

#include "base/debug/leak_annotations.h"
#include "ml/mojom/image_content_annotation.mojom.h"
#include "ml/request_metrics.h"

using ::chromeos::machine_learning::mojom::ImageAnnotationResult;
using ::chromeos::machine_learning::mojom::ImageAnnotationResultPtr;

namespace ml {

bool ImageContentAnnotatorImpl::Create(
    chromeos::machine_learning::mojom::ImageAnnotatorConfigPtr config,
    mojo::PendingReceiver<
        chromeos::machine_learning::mojom::ImageContentAnnotator> receiver,
    ImageContentAnnotationLibrary* interface) {
  auto impl = new ImageContentAnnotatorImpl(std::move(config),
                                            std::move(receiver), interface);

  // In production, `impl` is intentionally leaked, because this
  // model runs in its own process and the model's memory is freed when the
  // process exits. However, if being tested with ASAN, this memory leak could
  // cause an error. Therefore, we annotate it as an intentional leak.
  ANNOTATE_LEAKING_OBJECT_PTR(impl);

  // Set the disconnection handler to quit the message loop (i.e. exit the
  // process) when the connection is gone, because this model is always run in
  // a dedicated process.
  // base::Unretained is safe here because the caller does not outlive the
  // message loop.
  impl->receiver_.set_disconnect_handler(
      base::BindOnce(&brillo::MessageLoop::BreakLoop,
                     base::Unretained(brillo::MessageLoop::current())));

  return impl->successfully_loaded_;
}

ImageContentAnnotatorImpl::ImageContentAnnotatorImpl(
    chromeos::machine_learning::mojom::ImageAnnotatorConfigPtr config,
    mojo::PendingReceiver<
        chromeos::machine_learning::mojom::ImageContentAnnotator> receiver,
    ImageContentAnnotationLibrary* interface)
    : receiver_(this, std::move(receiver)) {
  DCHECK(!USE_ONDEVICE_IMAGE_CONTENT_ANNOTATION);
  successfully_loaded_ = false;
}

ImageContentAnnotatorImpl::~ImageContentAnnotatorImpl() = default;

void ImageContentAnnotatorImpl::AnnotateRawImage(
    mojo_base::mojom::ReadOnlySharedMemoryRegionPtr rgb_bytes,
    uint32_t width,
    uint32_t height,
    uint32_t line_stride,
    AnnotateRawImageCallback callback) {
  ImageAnnotationResultPtr result = ImageAnnotationResult::New();
  result->status = ImageAnnotationResult::Status::ERROR;
  std::move(callback).Run(std::move(result));
}

void ImageContentAnnotatorImpl::AnnotateEncodedImage(
    ::mojo_base::mojom::ReadOnlySharedMemoryRegionPtr encoded_image,
    AnnotateEncodedImageCallback callback) {
  ImageAnnotationResultPtr result = ImageAnnotationResult::New();
  result->status = ImageAnnotationResult::Status::ERROR;
  std::move(callback).Run(std::move(result));
}

}  // namespace ml
