// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ocr/ocr_service_impl.h"

#include <sys/fcntl.h>
#include <unistd.h>

#include <memory>
#include <utility>

#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/stringprintf.h>
#include <leptonica/allheaders.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/system/handle.h>
#include <mojo/public/cpp/system/platform_handle.h>
#include <tesseract/baseapi.h>
#include <tesseract/renderer.h>

#include "ocr/mojo/ocr_service.mojom.h"

namespace ocr {

namespace {

namespace mojo_ipc = chromeos::ocr::mojom;

// Location of trained Tesseract models.
constexpr char kTessdataPath[] = "/usr/share/tessdata";

}  // namespace

OcrServiceImpl::OcrServiceImpl() {
  receivers_.set_disconnect_handler(base::BindRepeating(
      &OcrServiceImpl::OnDisconnect, base::Unretained(this)));
}

OcrServiceImpl::~OcrServiceImpl() = default;

void OcrServiceImpl::GenerateSearchablePdfFromImage(
    mojo::ScopedHandle input_fd_handle,
    mojo::ScopedHandle output_fd_handle,
    mojo_ipc::OcrConfigPtr ocr_config,
    mojo_ipc::PdfRendererConfigPtr pdf_renderer_config,
    GenerateSearchablePdfFromImageCallback callback) {
  mojo_ipc::OpticalCharacterRecognitionServiceResponse response;

  std::unique_ptr<tesseract::TessBaseAPI> api =
      std::make_unique<tesseract::TessBaseAPI>();
  if (api->Init(kTessdataPath, ocr_config->language.c_str())) {
    LOG(ERROR) << "Could not initialize tesseract.";
    response.result = mojo_ipc::OcrResultEnum::LANGUAGE_NOT_SUPPORTED_ERROR;
    response.result_message =
        base::StringPrintf("Could not initialize tesseract with language %s.",
                           ocr_config->language.c_str());
    std::move(callback).Run(response.Clone());
    api->End();
    return;
  }

  // Redirect the standard input to the input image file.
  base::ScopedFD input_file(
      mojo::UnwrapPlatformHandle(std::move(input_fd_handle)).TakeFD());
  if (!input_file.is_valid()) {
    LOG(ERROR) << "Input ScopedFD extracted from Mojo handle is invalid.";
    response.result = mojo_ipc::OcrResultEnum::INPUT_FILE_ERROR;
    response.result_message = "Invalid input image ScopedFD.";
    std::move(callback).Run(response.Clone());
    api->End();
    return;
  }

  if (HANDLE_EINTR(dup2(input_file.get(), STDIN_FILENO)) == -1) {
    PLOG(ERROR) << "Failed to redirect stdin to input image file descriptor";
    response.result = mojo_ipc::OcrResultEnum::INPUT_FILE_ERROR;
    response.result_message = "Invalid input image file descriptor.";
    std::move(callback).Run(response.Clone());
    api->End();
    return;
  }

  // Redirect the standard output to the output PDF file.
  int stdout_fd_copy = HANDLE_EINTR(dup(STDOUT_FILENO));
  base::ScopedFD output_file(
      mojo::UnwrapPlatformHandle(std::move(output_fd_handle)).TakeFD());
  if (!output_file.is_valid()) {
    LOG(ERROR) << "Output ScopedFD extracted from Mojo handle is invalid.";
    response.result = mojo_ipc::OcrResultEnum::OUTPUT_FILE_ERROR;
    response.result_message = "Invalid output PDF ScopedFD.";
    std::move(callback).Run(response.Clone());
    api->End();
    return;
  }

  if (HANDLE_EINTR(dup2(output_file.get(), STDOUT_FILENO)) == -1) {
    PLOG(ERROR) << "Failed to redirect stdout to output PDF file descriptor";
    response.result = mojo_ipc::OcrResultEnum::OUTPUT_FILE_ERROR;
    response.result_message = "Invalid output image file descriptor.";
    std::move(callback).Run(response.Clone());
    api->End();
    return;
  }

  // Perform OCR.
  std::unique_ptr<tesseract::TessPDFRenderer> renderer =
      std::make_unique<tesseract::TessPDFRenderer>(
          "stdout", api->GetDatapath(), pdf_renderer_config->textonly);
  bool success = api->ProcessPages("stdin", nullptr, ocr_config->timeout_ms,
                                   renderer.get());
  api->End();

  // Restore stdout.
  if (fflush(stdout)) {
    PLOG(ERROR) << "Error while flushing stdout";
    response.result = mojo_ipc::OcrResultEnum::OUTPUT_FILE_ERROR;
    response.result_message = "Error while flushing stdout.";
    std::move(callback).Run(response.Clone());
    return;
  }

  HANDLE_EINTR(dup2(stdout_fd_copy, STDOUT_FILENO));
  close(stdout_fd_copy);

  if (!success) {
    PLOG(ERROR) << "Error during Ocr processing";
    response.result = mojo_ipc::OcrResultEnum::PROCESS_PAGE_ERROR;
    response.result_message = "Error during OCR processing.";
    std::move(callback).Run(response.Clone());
    return;
  }

  response.result = mojo_ipc::OcrResultEnum::SUCCESS;
  response.result_message = "Searchable PDF was generated successfully.";
  std::move(callback).Run(response.Clone());
}

void OcrServiceImpl::AddReceiver(
    mojo::PendingReceiver<mojo_ipc::OpticalCharacterRecognitionService>
        pending_receiver,
    bool should_quit) {
  receivers_.Add(this, std::move(pending_receiver), should_quit);
}

void OcrServiceImpl::SetOnDisconnectCallback(
    base::RepeatingCallback<void(bool)> on_disconnect_callback) {
  on_disconnect_callback_ = std::move(on_disconnect_callback);
}

void OcrServiceImpl::OnDisconnect() {
  if (on_disconnect_callback_)
    std::move(on_disconnect_callback_).Run(receivers_.current_context());
}

}  // namespace ocr
