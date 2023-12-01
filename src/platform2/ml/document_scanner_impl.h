// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_DOCUMENT_SCANNER_IMPL_H_
#define ML_DOCUMENT_SCANNER_IMPL_H_

#include <memory>
#include <vector>

#include <chromeos/libdocumentscanner/document_scanner.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/receiver.h>

#include "ml/mojom/document_scanner.mojom.h"

namespace ml {

class DocumentScannerImpl
    : public chromeos::machine_learning::mojom::DocumentScanner {
 public:
  explicit DocumentScannerImpl(
      std::unique_ptr<chromeos_camera::document_scanning::DocumentScanner>
          scanner);
  DocumentScannerImpl(const DocumentScannerImpl&) = delete;
  DocumentScannerImpl& operator=(const DocumentScannerImpl&) = delete;
  // Called when mojom connection is destroyed.
  ~DocumentScannerImpl();

 private:
  // mojom::DocumentScanner
  void DetectCornersFromNV12Image(
      mojo_base::mojom::ReadOnlySharedMemoryRegionPtr nv12_image,
      DetectCornersFromNV12ImageCallback callback) override;
  void DetectCornersFromJPEGImage(
      mojo_base::mojom::ReadOnlySharedMemoryRegionPtr jpeg_image,
      DetectCornersFromJPEGImageCallback callback) override;
  void DoPostProcessing(
      mojo_base::mojom::ReadOnlySharedMemoryRegionPtr jpeg_image,
      std::vector<gfx::mojom::PointFPtr> corners,
      chromeos::machine_learning::mojom::Rotation rotation,
      DoPostProcessingCallback callback) override;

  const std::unique_ptr<chromeos_camera::document_scanning::DocumentScanner>
      scanner_;
};

}  // namespace ml

#endif  // ML_DOCUMENT_SCANNER_IMPL_H_
