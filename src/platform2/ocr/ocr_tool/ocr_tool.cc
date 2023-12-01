// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fcntl.h>

#include <iostream>
#include <memory>
#include <string>
#include <utility>

#include <base/at_exit.h>
#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/message_loop/message_pump_type.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/string_util.h>
#include <base/task/single_thread_task_executor.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>
#include <mojo/public/cpp/system/handle.h>
#include <mojo/public/cpp/system/platform_handle.h>

#include "ocr/mojo/ocr_service.mojom.h"
#include "ocr/mojo_adapter/ocr_service_mojo_adapter.h"

namespace {

namespace mojo_ipc = chromeos::ocr::mojom;

mojo::ScopedHandle GetFileHandle(const base::FilePath& path, int oflag) {
  base::ScopedFD fd(HANDLE_EINTR(open(path.value().c_str(), oflag, 0644)));

  if (fd.get() < 0) {
    PLOG(ERROR) << "Unable to open file: " << path.value();
    return mojo::ScopedHandle();
  }

  return mojo::WrapPlatformHandle(mojo::PlatformHandle(std::move(fd)));
}

mojo::ScopedHandle GetInputFileHandle(const base::FilePath& input_filepath) {
  return GetFileHandle(input_filepath,
                       O_RDONLY | O_NOFOLLOW | O_NOCTTY | O_CLOEXEC);
}

mojo::ScopedHandle GetOutputFileHandle(const base::FilePath& output_filepath) {
  return GetFileHandle(output_filepath, O_CREAT | O_WRONLY | O_CLOEXEC);
}

}  // namespace

int main(int argc, char* argv[]) {
  // Parse command line flags.
  DEFINE_string(
      input_image_filename, "",
      "Filename of input image. Supported image formats: PNG, JPEG and TIFF.");
  DEFINE_string(output_pdf_filename, "", "Filename of output PDF file.");
  DEFINE_string(language, "eng",
                "Document language. Supported languages: eng (English).");

  brillo::FlagHelper::Init(argc, argv,
                           "ocr_tool - Optical Character Recognition "
                           "command line tool.");
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  // When the at_exit_manager object goes out of scope, all the registered
  // callbacks and singleton destructors will be called.
  base::AtExitManager at_exit_manager;
  // Mojo requires a sequenced context.
  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);

  // Get adapter instance to send requests to OCR service.
  std::unique_ptr<ocr::OcrServiceMojoAdapter> adapter =
      ocr::OcrServiceMojoAdapter::Create();
  DCHECK(adapter);

  // Validate input arguments.
  base::FilePath input_image_filename =
      base::FilePath(FLAGS_input_image_filename);
  if (input_image_filename.empty()) {
    LOG(ERROR) << "--input_image_filename must be specified."
                  " Use --help for help on usage.";
    return EXIT_FAILURE;
  }

  base::FilePath output_pdf_filename =
      base::FilePath(FLAGS_output_pdf_filename);
  if (output_pdf_filename.empty())
    output_pdf_filename = input_image_filename.ReplaceExtension("pdf");

  if (!base::EqualsCaseInsensitiveASCII(output_pdf_filename.Extension(),
                                        ".pdf")) {
    LOG(ERROR) << "--output_pdf_filename must have a .pdf extension."
                  " Use --help for help on usage.";
    return EXIT_FAILURE;
  }

  if (FLAGS_language.compare("eng") != 0) {
    LOG(ERROR) << "Selected language " << FLAGS_language
               << " is not supported."
                  " Use --help for help on usage.";
    return EXIT_FAILURE;
  }

  // Construct request.
  mojo::ScopedHandle input_fd_handle = GetInputFileHandle(input_image_filename);
  if (!input_fd_handle)
    return EXIT_FAILURE;

  mojo::ScopedHandle output_fd_handle =
      GetOutputFileHandle(output_pdf_filename);
  if (!output_fd_handle)
    return EXIT_FAILURE;

  mojo_ipc::OcrConfigPtr ocr_config = mojo_ipc::OcrConfig::New();
  ocr_config->language = FLAGS_language;
  mojo_ipc::PdfRendererConfigPtr pdf_renderer_config =
      mojo_ipc::PdfRendererConfig::New();

  // Perform OCR.
  auto response = adapter->GenerateSearchablePdfFromImage(
      std::move(input_fd_handle), std::move(output_fd_handle),
      std::move(ocr_config), std::move(pdf_renderer_config));

  if (!response) {
    LOG(ERROR) << "No response received from GenerateSearchablePdfFromImage().";
    return EXIT_FAILURE;
  }

  bool success = response->result == mojo_ipc::OcrResultEnum::SUCCESS;
  if (success) {
    std::cout << "Generated searchable PDF file: " << output_pdf_filename
              << std::endl;
  } else {
    LOG(ERROR) << response->result_message;
  }

  return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
