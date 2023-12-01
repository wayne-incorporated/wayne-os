// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fcntl.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/files/scoped_temp_dir.h>
#include <base/functional/bind.h>
#include <base/message_loop/message_pump_type.h>
#include <base/posix/eintr_wrapper.h>
#include <base/run_loop.h>
#include <base/task/single_thread_task_executor.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <mojo/core/embedder/embedder.h>
#include <mojo/public/cpp/system/handle.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/system/platform_handle.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "ocr/mojo/ocr_service.mojom.h"
#include "ocr/ocr_service_impl.h"

namespace ocr {

namespace {

namespace mojo_ipc = chromeos::ocr::mojom;

// The relative path of the input test image.
constexpr char kTestImageRelativePath[] = "./test_images/phototest.tif";
// The name of the output pdf file.
constexpr char kOutputPdfFilename[] = "phototest.pdf";

mojo::ScopedHandle GetInputFileHandle(const std::string& input_filename) {
  base::ScopedFD input_fd(HANDLE_EINTR(
      open(input_filename.c_str(), O_RDONLY | O_NOFOLLOW | O_NOCTTY)));
  return mojo::WrapPlatformHandle(mojo::PlatformHandle(std::move(input_fd)));
}

mojo::ScopedHandle GetOutputFileHandle(const std::string& output_filename) {
  base::ScopedFD out_fd(
      HANDLE_EINTR(open(output_filename.c_str(), O_CREAT | O_WRONLY, 0644)));
  return mojo::WrapPlatformHandle(mojo::PlatformHandle(std::move(out_fd)));
}

}  // namespace

class OcrServiceImplTest : public testing::Test {
 protected:
  OcrServiceImplTest() { mojo::core::Init(); }

  void SetUp() override { ASSERT_TRUE(temp_dir_.CreateUniqueTempDir()); }

  OcrServiceImpl* ocr_service() { return &ocr_service_impl_; }
  const base::FilePath& temp_dir_path() const { return temp_dir_.GetPath(); }

 private:
  OcrServiceImpl ocr_service_impl_;
  base::SingleThreadTaskExecutor executor_{base::MessagePumpType::IO};
  base::ScopedTempDir temp_dir_;
};

// Tests OCR on a valid input image and with valid parameters.
TEST_F(OcrServiceImplTest, GenerateSearchablePdfFromImageSuccess) {
  mojo::Remote<mojo_ipc::OpticalCharacterRecognitionService> remote;
  EXPECT_FALSE(remote);
  ocr_service()->AddReceiver(remote.BindNewPipeAndPassReceiver(),
                             false /* should_quit */);
  ASSERT_TRUE(remote);

  // Construct request.
  const std::string input_image_filename =
      base::FilePath(kTestImageRelativePath).value();
  mojo::ScopedHandle input_fd_handle = GetInputFileHandle(input_image_filename);
  const std::string output_filename =
      temp_dir_path().Append(kOutputPdfFilename).value();
  mojo::ScopedHandle output_fd_handle = GetOutputFileHandle(output_filename);
  mojo_ipc::OcrConfigPtr ocr_config = mojo_ipc::OcrConfig::New();
  mojo_ipc::PdfRendererConfigPtr pdf_renderer_config =
      mojo_ipc::PdfRendererConfig::New();

  // Perform OCR.
  bool ocr_callback_done = false;
  // Ensure that remote is bound.
  remote->GenerateSearchablePdfFromImage(
      std::move(input_fd_handle), std::move(output_fd_handle),
      std::move(ocr_config), std::move(pdf_renderer_config),
      base::BindOnce(
          [](bool* ocr_callback_done,
             const mojo_ipc::OpticalCharacterRecognitionServiceResponsePtr
                 response) {
            EXPECT_EQ(response->result, mojo_ipc::OcrResultEnum::SUCCESS);
            *ocr_callback_done = true;
          },
          &ocr_callback_done));
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(ocr_callback_done);
}

TEST_F(OcrServiceImplTest, OcrFailToLoadLanguage) {
  // Construct request.
  const std::string input_image_filename =
      base::FilePath(kTestImageRelativePath).value();
  mojo::ScopedHandle input_fd_handle = GetInputFileHandle(input_image_filename);
  const std::string output_filename =
      temp_dir_path().Append(kOutputPdfFilename).value();
  mojo::ScopedHandle output_fd_handle = GetOutputFileHandle(output_filename);
  mojo_ipc::OcrConfigPtr ocr_config = mojo_ipc::OcrConfig::New();
  ocr_config->language = "deu";
  mojo_ipc::PdfRendererConfigPtr pdf_renderer_config =
      mojo_ipc::PdfRendererConfig::New();

  // Perform OCR.
  bool ocr_callback_done = false;
  // Ensure that remote is bound.
  ocr_service()->GenerateSearchablePdfFromImage(
      std::move(input_fd_handle), std::move(output_fd_handle),
      std::move(ocr_config), std::move(pdf_renderer_config),
      base::BindOnce(
          [](bool* ocr_callback_done,
             const mojo_ipc::OpticalCharacterRecognitionServiceResponsePtr
                 response) {
            EXPECT_EQ(response->result,
                      mojo_ipc::OcrResultEnum::LANGUAGE_NOT_SUPPORTED_ERROR);
            *ocr_callback_done = true;
          },
          &ocr_callback_done));
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(ocr_callback_done);
}

TEST_F(OcrServiceImplTest, OcrInvalidInputImageFileHandle) {
  // Construct request.
  mojo::ScopedHandle input_fd_handle = mojo::ScopedHandle();
  const std::string output_filename =
      temp_dir_path().Append(kOutputPdfFilename).value();
  mojo::ScopedHandle output_fd_handle = GetOutputFileHandle(output_filename);
  mojo_ipc::OcrConfigPtr ocr_config = mojo_ipc::OcrConfig::New();
  mojo_ipc::PdfRendererConfigPtr pdf_renderer_config =
      mojo_ipc::PdfRendererConfig::New();

  // Perform OCR.
  bool ocr_callback_done = false;
  // Ensure that remote is bound.
  ocr_service()->GenerateSearchablePdfFromImage(
      std::move(input_fd_handle), std::move(output_fd_handle),
      std::move(ocr_config), std::move(pdf_renderer_config),
      base::BindOnce(
          [](bool* ocr_callback_done,
             const mojo_ipc::OpticalCharacterRecognitionServiceResponsePtr
                 response) {
            EXPECT_EQ(response->result,
                      mojo_ipc::OcrResultEnum::INPUT_FILE_ERROR);
            *ocr_callback_done = true;
          },
          &ocr_callback_done));
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(ocr_callback_done);
}

TEST_F(OcrServiceImplTest, OcrInvalidOutputPdfFileHandle) {
  // Construct request.
  const std::string input_image_filename =
      base::FilePath(kTestImageRelativePath).value();
  mojo::ScopedHandle input_fd_handle = GetInputFileHandle(input_image_filename);
  mojo::ScopedHandle output_fd_handle = mojo::ScopedHandle();
  mojo_ipc::OcrConfigPtr ocr_config = mojo_ipc::OcrConfig::New();
  mojo_ipc::PdfRendererConfigPtr pdf_renderer_config =
      mojo_ipc::PdfRendererConfig::New();

  // Perform OCR.
  bool ocr_callback_done = false;
  // Ensure that remote is bound.
  ocr_service()->GenerateSearchablePdfFromImage(
      std::move(input_fd_handle), std::move(output_fd_handle),
      std::move(ocr_config), std::move(pdf_renderer_config),
      base::BindOnce(
          [](bool* ocr_callback_done,
             const mojo_ipc::OpticalCharacterRecognitionServiceResponsePtr
                 response) {
            EXPECT_EQ(response->result,
                      mojo_ipc::OcrResultEnum::OUTPUT_FILE_ERROR);
            *ocr_callback_done = true;
          },
          &ocr_callback_done));
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(ocr_callback_done);
}

}  // namespace ocr
