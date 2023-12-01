// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/document_scanner_impl.h"

#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/logging.h>
#include <brillo/message_loops/message_loop.h>
#include <mojo/public/cpp/system/platform_handle.h>

#include "ml/mojom/shared_memory.mojom.h"
#include "ml/request_metrics.h"

namespace ml {
namespace {

using ::chromeos::machine_learning::mojom::DetectCornersResult;
using ::chromeos::machine_learning::mojom::DetectCornersResultPtr;
using ::chromeos::machine_learning::mojom::DocumentScannerResultStatus;
using ::chromeos::machine_learning::mojom::DoPostProcessingResult;
using ::gfx::mojom::PointFPtr;
using ::mojo_base::mojom::ReadOnlySharedMemoryRegionPtr;

using LibDocumentScanner =
    ::chromeos_camera::document_scanning::DocumentScanner;
using DetectFromMappingCallback = base::OnceCallback<bool(
    base::span<const uint8_t>, std::vector<LibDocumentScanner::Point>*)>;
using ResultCallback = base::OnceCallback<void(DetectCornersResultPtr)>;

PointFPtr ToGfxCorner(const LibDocumentScanner::Point& corner) {
  auto p = gfx::mojom::PointF::New();
  p->x = corner.x;
  p->y = corner.y;
  return p;
}

LibDocumentScanner::Point FromGfxCorner(const PointFPtr& corner) {
  LibDocumentScanner::Point p = {
      .x = corner->x,
      .y = corner->y,
  };
  return p;
}

// Map the |mapping| to the given |region|. Returns false if any error occurs.
bool MapRegion(const base::ReadOnlySharedMemoryRegion& region,
               base::ReadOnlySharedMemoryMapping* mapping) {
  if (!region.IsValid()) {
    return false;
  }
  *mapping = region.Map();
  return mapping->IsValid();
}

// Detect the document corners from the given |image_region| via
// |detect_callback|. Returns the detected result to |result_callback|.
// |metrics_name| is only used as the performance metrics id.
void DetectCorners(const std::string& metrics_name,
                   ReadOnlySharedMemoryRegionPtr image_region,
                   DetectFromMappingCallback detect_callback,
                   ResultCallback result_callback) {
  RequestMetrics request_metrics("DocumentScanner", metrics_name);
  request_metrics.StartRecordingPerformanceMetrics();

  auto error_callback = [&]() {
    std::move(result_callback)
        .Run(DetectCornersResult::New(DocumentScannerResultStatus::ERROR,
                                      std::vector<PointFPtr>()));
    request_metrics.RecordRequestEvent(DocumentScannerResultStatus::ERROR);
  };

  base::ReadOnlySharedMemoryMapping mapping;
  if (!MapRegion(mojo::UnwrapReadOnlySharedMemoryRegion(
                     std::move(image_region->buffer)),
                 &mapping)) {
    LOG(ERROR) << "Failed to map region";
    error_callback();
    return;
  }

  const auto& image = mapping.GetMemoryAsSpan<uint8_t>();
  std::vector<LibDocumentScanner::Point> corners;
  if (!std::move(detect_callback).Run(std::move(image), &corners)) {
    LOG(ERROR) << "Failed to detect corners";
    error_callback();
    return;
  }

  std::vector<PointFPtr> gfx_corners;
  for (auto& corner : corners) {
    gfx_corners.push_back(ToGfxCorner(corner));
  }
  std::move(result_callback)
      .Run(DetectCornersResult::New(DocumentScannerResultStatus::OK,
                                    std::move(gfx_corners)));
  request_metrics.FinishRecordingPerformanceMetrics();
  request_metrics.RecordRequestEvent(DocumentScannerResultStatus::OK);
}

}  // namespace

DocumentScannerImpl::DocumentScannerImpl(
    std::unique_ptr<chromeos_camera::document_scanning::DocumentScanner>
        scanner)
    : scanner_(std::move(scanner)) {}

DocumentScannerImpl::~DocumentScannerImpl() {
  brillo::MessageLoop::current()->BreakLoop();
}

void DocumentScannerImpl::DetectCornersFromNV12Image(
    ReadOnlySharedMemoryRegionPtr nv12_image,
    DetectCornersFromNV12ImageCallback callback) {
  auto detect_from_mapping_callback = base::BindOnce(
      [](LibDocumentScanner* scanner, base::span<const uint8_t> image,
         std::vector<LibDocumentScanner::Point>* corners) -> bool {
        return scanner->DetectCornersFromNV12Image(image.data(), corners);
      },
      scanner_.get());

  auto result_callback = base::BindOnce(
      [](DetectCornersFromNV12ImageCallback callback,
         DetectCornersResultPtr result) {
        std::move(callback).Run(std::move(result));
      },
      std::move(callback));

  DetectCorners("DetectCornersFromNV12", std::move(nv12_image),
                std::move(detect_from_mapping_callback),
                std::move(result_callback));
}

void DocumentScannerImpl::DetectCornersFromJPEGImage(
    ReadOnlySharedMemoryRegionPtr jpeg_image,
    DetectCornersFromJPEGImageCallback callback) {
  auto detect_from_mapping_callback = base::BindOnce(
      [](LibDocumentScanner* scanner, base::span<const uint8_t> image,
         std::vector<LibDocumentScanner::Point>* corners) -> bool {
        return scanner->DetectCornersFromJPEGImage(image.data(), image.size(),
                                                   corners);
      },
      scanner_.get());

  auto result_callback = base::BindOnce(
      [](DetectCornersFromJPEGImageCallback callback,
         DetectCornersResultPtr result) {
        std::move(callback).Run(std::move(result));
      },
      std::move(callback));

  DetectCorners("DetectCornersFromJPEG", std::move(jpeg_image),
                std::move(detect_from_mapping_callback),
                std::move(result_callback));
}

void DocumentScannerImpl::DoPostProcessing(
    ReadOnlySharedMemoryRegionPtr jpeg_image,
    std::vector<PointFPtr> gfx_corners,
    chromeos::machine_learning::mojom::Rotation rotation,
    DoPostProcessingCallback callback) {
  RequestMetrics request_metrics("DocumentScanner", "DoPostProcessing");
  request_metrics.StartRecordingPerformanceMetrics();

  auto error_callback = [&]() {
    std::move(callback).Run(DoPostProcessingResult::New(
        DocumentScannerResultStatus::ERROR, std::vector<uint8_t>()));
    request_metrics.RecordRequestEvent(DocumentScannerResultStatus::ERROR);
  };

  base::ReadOnlySharedMemoryMapping mapping;
  if (!MapRegion(
          mojo::UnwrapReadOnlySharedMemoryRegion(std::move(jpeg_image->buffer)),
          &mapping)) {
    LOG(ERROR) << "Failed to map region";
    error_callback();
    return;
  }

  const auto& image = mapping.GetMemoryAsSpan<uint8_t>();
  std::vector<LibDocumentScanner::Point> corners;
  for (auto& gfx_corner : gfx_corners) {
    corners.push_back(FromGfxCorner(gfx_corner));
  }

  auto imageRotation = ([rotation]() {
    using MojoRotation = chromeos::machine_learning::mojom::Rotation;
    using Rotation =
        chromeos_camera::document_scanning::DocumentScanner::Rotation;
    switch (rotation) {
      case MojoRotation::ROTATION_0:
        return Rotation::ROTATION_0;
      case MojoRotation::ROTATION_90:
        return Rotation::ROTATION_90;
      case MojoRotation::ROTATION_180:
        return Rotation::ROTATION_180;
      case MojoRotation::ROTATION_270:
        return Rotation::ROTATION_270;
    }
  })();
  std::vector<uint8_t> processed_jpeg_image;
  if (!scanner_->DoPostProcessingFromJPEGImage(image.data(), image.size(),
                                               corners, imageRotation,
                                               &processed_jpeg_image)) {
    LOG(ERROR) << "Failed to do post processing";
    error_callback();
    return;
  }

  std::move(callback).Run(DoPostProcessingResult::New(
      DocumentScannerResultStatus::OK, std::move(processed_jpeg_image)));
  request_metrics.FinishRecordingPerformanceMetrics();
  request_metrics.RecordRequestEvent(DocumentScannerResultStatus::OK);
}

}  // namespace ml
