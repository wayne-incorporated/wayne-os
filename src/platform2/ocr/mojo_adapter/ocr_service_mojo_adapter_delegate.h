// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef OCR_MOJO_ADAPTER_OCR_SERVICE_MOJO_ADAPTER_DELEGATE_H_
#define OCR_MOJO_ADAPTER_OCR_SERVICE_MOJO_ADAPTER_DELEGATE_H_

#include <mojo/public/cpp/bindings/remote.h>

#include "ocr/mojo/ocr_service.mojom.h"

namespace ocr {

// Bootstraps Mojo connection to OCR service.
class OcrServiceMojoAdapterDelegate {
 public:
  virtual ~OcrServiceMojoAdapterDelegate() = default;

  // Bootstraps a Mojo connection to the OCR service and returns the bound
  // remote.
  virtual mojo::Remote<chromeos::ocr::mojom::OpticalCharacterRecognitionService>
  GetOcrService() = 0;
};

}  // namespace ocr

#endif  // OCR_MOJO_ADAPTER_OCR_SERVICE_MOJO_ADAPTER_DELEGATE_H_
