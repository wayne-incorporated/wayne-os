// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/image_content_annotation_impl.h"

#include <cstdint>
#include <utility>

#include <base/check.h>
#include <base/logging.h>
#include <brillo/message_loops/message_loop.h>

#include "base/debug/leak_annotations.h"
#include "chrome/knowledge/ica/ica.pb.h"
#include "ml/image_content_annotation.h"
#include "ml/mojom/shared_memory.mojom.h"
#include "ml/request_metrics.h"

namespace ml {

namespace {
using ::chromeos::machine_learning::mojom::ImageAnnotationResult;
using ::chromeos::machine_learning::mojom::ImageAnnotationResultPtr;
using ::chromeos::machine_learning::mojom::ImageAnnotationScore;
using ::chromeos::machine_learning::mojom::ImageAnnotationScorePtr;

// Map the shared memory region into this process's address space.
// Returns false if region is invalid.
bool MapRegion(const base::ReadOnlySharedMemoryRegion& region,
               base::ReadOnlySharedMemoryMapping* mapping) {
  if (!region.IsValid()) {
    return false;
  }
  *mapping = region.Map();
  return mapping->IsValid();
}

ImageAnnotationScorePtr AnnotationScorePtrFromProto(
    const chrome_knowledge::AnnotationScoreList::AnnotationScore& score) {
  auto p = ImageAnnotationScore::New();
  p->id = score.id();
  p->confidence = score.confidence();
  p->mid = score.mid();
  p->name = score.name();
  return p;
}

}  // namespace

bool ImageContentAnnotatorImpl::Create(
    chromeos::machine_learning::mojom::ImageAnnotatorConfigPtr config,
    mojo::PendingReceiver<
        chromeos::machine_learning::mojom::ImageContentAnnotator> receiver,
    ImageContentAnnotationLibrary* interface) {
  auto* const impl = new ImageContentAnnotatorImpl(
      std::move(config), std::move(receiver), interface);

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
    : library_(interface), receiver_(this, std::move(receiver)) {
  DCHECK(USE_ONDEVICE_IMAGE_CONTENT_ANNOTATION);
  DCHECK(library_->GetStatus() == ImageContentAnnotationLibrary::Status::kOk)
      << "ImageContentAnnotatorImpl should only be created if "
         "ImageContentAnnotationLibrary initialized successfully.";

  annotator_ = library_->CreateImageContentAnnotator();

  successfully_loaded_ =
      library_->InitImageContentAnnotator(annotator_, config->locale.c_str());
}

ImageContentAnnotatorImpl::~ImageContentAnnotatorImpl() {
  library_->DestroyImageContentAnnotator(annotator_);
}

void ImageContentAnnotatorImpl::ErrorCallback(
    AnnotateRawImageCallback& callback, RequestMetrics& request_metrics) {
  ImageAnnotationResultPtr result = ImageAnnotationResult::New();
  result->status = ImageAnnotationResult::Status::ERROR;
  request_metrics.RecordRequestEvent(result->status);
  std::move(callback).Run(std::move(result));
}

void ImageContentAnnotatorImpl::AnnotateImage(const uint8_t* rgb_bytes,
                                              uint32_t width,
                                              uint32_t height,
                                              uint32_t line_stride,
                                              AnnotateRawImageCallback callback,
                                              RequestMetrics& request_metrics) {
  chrome_knowledge::AnnotationScoreList annotation_scores;
  if (!library_->AnnotateImage(annotator_, rgb_bytes, width, height,
                               line_stride, &annotation_scores)) {
    LOG(ERROR) << "Failed to annotate image.";
    ErrorCallback(callback, request_metrics);
    return;
  }

  ImageAnnotationResultPtr result = ImageAnnotationResult::New();
  result->status = ImageAnnotationResult::Status::OK;
  for (const auto& annotation : annotation_scores.annotation()) {
    result->annotations.push_back(AnnotationScorePtrFromProto(annotation));
  }
  request_metrics.FinishRecordingPerformanceMetrics();
  request_metrics.RecordRequestEvent(result->status);
  std::move(callback).Run(std::move(result));
}

void ImageContentAnnotatorImpl::AnnotateRawImage(
    mojo_base::mojom::ReadOnlySharedMemoryRegionPtr rgb_bytes,
    uint32_t width,
    uint32_t height,
    uint32_t line_stride,
    AnnotateRawImageCallback callback) {
  RequestMetrics request_metrics("ImageAnnotator", "AnnotateRawImage");
  request_metrics.StartRecordingPerformanceMetrics();

  base::ReadOnlySharedMemoryMapping mapping;
  if (!MapRegion(
          mojo::UnwrapReadOnlySharedMemoryRegion(std::move(rgb_bytes->buffer)),
          &mapping)) {
    LOG(ERROR) << "Failed to map region";
    ErrorCallback(callback, request_metrics);
    return;
  }
  base::span<const uint8_t> bytes = mapping.GetMemoryAsSpan<uint8_t>();
  if (line_stride * height > bytes.size_bytes()) {
    LOG(ERROR) << "Memory region too small";
    ErrorCallback(callback, request_metrics);
    return;
  }

  AnnotateImage(bytes.data(), width, height, line_stride, std::move(callback),
                request_metrics);
}

void ImageContentAnnotatorImpl::AnnotateEncodedImage(
    ::mojo_base::mojom::ReadOnlySharedMemoryRegionPtr encoded_image,
    AnnotateEncodedImageCallback callback) {
  RequestMetrics request_metrics("ImageAnnotator", "AnnotateEncodedImage");
  request_metrics.StartRecordingPerformanceMetrics();

  base::ReadOnlySharedMemoryMapping mapping;
  if (!MapRegion(mojo::UnwrapReadOnlySharedMemoryRegion(
                     std::move(encoded_image->buffer)),
                 &mapping)) {
    LOG(ERROR) << "Failed to map region";
    ErrorCallback(callback, request_metrics);
    return;
  }
  base::span<const uint8_t> encoded_bytes = mapping.GetMemoryAsSpan<uint8_t>();
  if (encoded_bytes.empty()) {
    LOG(ERROR) << "Invalid image.";
    ErrorCallback(callback, request_metrics);
    return;
  }

  chrome_knowledge::AnnotationScoreList annotation_scores;
  if (!library_->AnnotateEncodedImage(annotator_, encoded_bytes.data(),
                                      encoded_bytes.size(),
                                      &annotation_scores)) {
    LOG(ERROR) << "Failed to annotate image.";
    ErrorCallback(callback, request_metrics);
    return;
  }
  ImageAnnotationResultPtr result = ImageAnnotationResult::New();
  result->status = ImageAnnotationResult::Status::OK;
  for (const auto& annotation : annotation_scores.annotation()) {
    result->annotations.push_back(AnnotationScorePtrFromProto(annotation));
  }
  request_metrics.FinishRecordingPerformanceMetrics();
  request_metrics.RecordRequestEvent(result->status);
  std::move(callback).Run(std::move(result));
}

}  // namespace ml
