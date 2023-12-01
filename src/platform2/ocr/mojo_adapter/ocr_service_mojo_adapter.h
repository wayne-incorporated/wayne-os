// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef OCR_MOJO_ADAPTER_OCR_SERVICE_MOJO_ADAPTER_H_
#define OCR_MOJO_ADAPTER_OCR_SERVICE_MOJO_ADAPTER_H_

#include <memory>

#include <mojo/public/cpp/system/handle.h>

#include "ocr/mojo/ocr_service.mojom.h"

namespace ocr {

// Provides a Mojo connection to the OCR service. See mojo/ocr_service.mojom for
// details on the Mojo interface. This should only be used by
// processes whose only Mojo connection is to the OCR service.
// This is a public interface of the class providing the functionality.
class OcrServiceMojoAdapter {
 public:
  virtual ~OcrServiceMojoAdapter() = default;

  // Instantiates an OcrServiceMojoAdapter.
  static std::unique_ptr<OcrServiceMojoAdapter> Create();

  // Requests the OCR service to generate a searchable PDF from an
  // input image.
  virtual chromeos::ocr::mojom::OpticalCharacterRecognitionServiceResponsePtr
  GenerateSearchablePdfFromImage(
      mojo::ScopedHandle input_fd_handle,
      mojo::ScopedHandle output_fd_handle,
      chromeos::ocr::mojom::OcrConfigPtr ocr_config,
      chromeos::ocr::mojom::PdfRendererConfigPtr pdf_renderer_config) = 0;
};

}  // namespace ocr

#endif  // OCR_MOJO_ADAPTER_OCR_SERVICE_MOJO_ADAPTER_H_
