// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ocr/mojo_adapter/ocr_service_mojo_adapter.h"

#include <memory>
#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/run_loop.h>
#include <mojo/public/cpp/bindings/remote.h>
#include <mojo/public/cpp/system/handle.h>

#include "ocr/mojo/ocr_service.mojom.h"
#include "ocr/mojo_adapter/ocr_service_mojo_adapter_delegate.h"
#include "ocr/mojo_adapter/ocr_service_mojo_adapter_delegate_impl.h"

namespace ocr {

namespace {

namespace mojo_ipc = chromeos::ocr::mojom;

class OcrServiceMojoAdapterImpl final : public OcrServiceMojoAdapter {
 public:
  // Override |delegate| for testing only.
  explicit OcrServiceMojoAdapterImpl(
      OcrServiceMojoAdapterDelegate* delegate = nullptr);
  ~OcrServiceMojoAdapterImpl() override = default;
  OcrServiceMojoAdapterImpl(const OcrServiceMojoAdapterImpl&) = delete;
  OcrServiceMojoAdapterImpl& operator=(const OcrServiceMojoAdapterImpl&) =
      delete;

  // OcrServiceMojoAdapter:
  mojo_ipc::OpticalCharacterRecognitionServiceResponsePtr
  GenerateSearchablePdfFromImage(
      mojo::ScopedHandle input_fd_handle,
      mojo::ScopedHandle output_fd_handle,
      mojo_ipc::OcrConfigPtr ocr_config,
      mojo_ipc::PdfRendererConfigPtr pdf_renderer_config) override;

 private:
  // Binds our remote endpoint |ocr_service_| to the implementation
  // provided by the OCR service.
  bool Connect();

  // Default delegate implementation.
  std::unique_ptr<OcrServiceMojoAdapterDelegateImpl> delegate_impl_;
  // Unowned. Must outlive this instance. Used to bootstrap a Mojo connection
  // with the OCR service.
  OcrServiceMojoAdapterDelegate* delegate_;

  mojo::Remote<mojo_ipc::OpticalCharacterRecognitionService> ocr_service_;
};

// Saves |response| to |response_destination|.
template <class T>
void OnMojoResponseReceived(T* response_destination,
                            base::RepeatingClosure quit_closure,
                            T response) {
  *response_destination = std::move(response);
  quit_closure.Run();
}

OcrServiceMojoAdapterImpl::OcrServiceMojoAdapterImpl(
    OcrServiceMojoAdapterDelegate* delegate) {
  if (delegate) {
    delegate_ = delegate;
  } else {
    delegate_impl_ = std::make_unique<OcrServiceMojoAdapterDelegateImpl>();
    delegate_ = delegate_impl_.get();
  }
  DCHECK(delegate_);
}

mojo_ipc::OpticalCharacterRecognitionServiceResponsePtr
OcrServiceMojoAdapterImpl::GenerateSearchablePdfFromImage(
    mojo::ScopedHandle input_fd_handle,
    mojo::ScopedHandle output_fd_handle,
    mojo_ipc::OcrConfigPtr ocr_config,
    mojo_ipc::PdfRendererConfigPtr pdf_renderer_config) {
  if (!ocr_service_.is_bound() && !Connect())
    return nullptr;

  mojo_ipc::OpticalCharacterRecognitionServiceResponsePtr response;
  base::RunLoop run_loop;
  ocr_service_->GenerateSearchablePdfFromImage(
      std::move(input_fd_handle), std::move(output_fd_handle),
      std::move(ocr_config), std::move(pdf_renderer_config),
      base::BindOnce(
          &OnMojoResponseReceived<
              mojo_ipc::OpticalCharacterRecognitionServiceResponsePtr>,
          &response, run_loop.QuitClosure()));
  run_loop.Run();

  return response;
}

bool OcrServiceMojoAdapterImpl::Connect() {
  ocr_service_ = delegate_->GetOcrService();
  if (!ocr_service_.is_bound())
    LOG(ERROR) << "Failed to connect to OCR service.";

  return ocr_service_.is_bound();
}

}  // namespace

std::unique_ptr<OcrServiceMojoAdapter> OcrServiceMojoAdapter::Create() {
  return std::make_unique<OcrServiceMojoAdapterImpl>();
}

}  // namespace ocr
