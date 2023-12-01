// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "camera/common/stream_manipulator.h"
#include "camera/common/test_support/fake_still_capture_processor.h"
#include "camera/mojo/effects/effects_pipeline.mojom.h"
#include "common/camera_hal3_helpers.h"
#include "cros-camera/camera_buffer_manager.h"
#include "cros-camera/camera_buffer_utils.h"
#include "features/effects/effects_stream_manipulator.h"
#include "ml_core/dlc/dlc_loader.h"
#include "ml_core/tests/test_utilities.h"

#include <base/command_line.h>
#include <base/files/file_util.h>
#include <base/synchronization/waitable_event.h>
#include <base/values.h>
#include <gtest/gtest.h>
#include <base/test/task_environment.h>
#include <base/test/test_timeouts.h>

#include <base/logging.h>
#include <hardware/camera3.h>
#include <functional>
#include <utility>

constexpr uint32_t kRGBAFormat = HAL_PIXEL_FORMAT_RGBX_8888;
constexpr uint32_t kBufferUsage = GRALLOC_USAGE_SW_READ_OFTEN |
                                  GRALLOC_USAGE_SW_WRITE_OFTEN |
                                  GRALLOC_USAGE_HW_TEXTURE;

const base::FilePath kSampleImagePath = base::FilePath(
    "/usr/local/share/ml-core-effects-test-assets/office_sample_720.yuv");
const base::FilePath kBlurImagePath = base::FilePath(
    "/usr/local/share/ml-core-effects-test-assets/office_blur_720.yuv");
const base::FilePath kMaxBlurImagePath = base::FilePath(
    "/usr/local/share/ml-core-effects-test-assets/office_max_blur_720.yuv");
const base::FilePath kReplaceImagePath = base::FilePath(
    "/usr/local/share/ml-core-effects-test-assets/office_replace_720.yuv");
const base::FilePath kRelightImagePath = base::FilePath(
    "/usr/local/share/ml-core-effects-test-assets/office_relight_720.yuv");

const int kNumFrames = 5;

base::FilePath dlc_path;

namespace cros::tests {

std::atomic<bool> effect_set_success = false;
std::unique_ptr<base::RunLoop> loop;

void SetEffectCallback(bool success) {
  if (success)
    effect_set_success = true;
  loop->Quit();
}

camera3_stream_t yuv_720_stream = {
    .stream_type = CAMERA3_STREAM_OUTPUT,
    .width = 1280,
    .height = 720,
    .format = HAL_PIXEL_FORMAT_YCbCr_420_888,
    .usage = GRALLOC_USAGE_HW_COMPOSER,
    .max_buffers = 4,
};

class EffectsStreamManipulatorTest : public ::testing::Test {
 protected:
  void SetUp() override {
    runtime_options_.SetDlcRootPath(base::FilePath(dlc_path));
    runtime_options_.SetSWPrivacySwitchState(
        mojom::CameraPrivacySwitchState::OFF);

    if (!base::CreateTemporaryFile(&config_path_)) {
      FAIL() << "Failed to create temporary file";
    }

    egl_context_ = EglContext::GetSurfacelessContext();
    if (!egl_context_->IsValid()) {
      FAIL() << "Failed to create EGL context";
    }
    if (!egl_context_->MakeCurrent()) {
      FAIL() << "Failed to make EGL context current";
    }
    image_processor_ = std::make_unique<GpuImageProcessor>();

    effect_set_success = false;
    loop = std::make_unique<base::RunLoop>();

    stream_config_.AppendStream(&yuv_720_stream);

    output_buffer_ = CameraBufferManager::AllocateScopedBuffer(
        yuv_720_stream.width, yuv_720_stream.height, yuv_720_stream.format,
        yuv_720_stream.usage);
  }

  StreamManipulator::RuntimeOptions runtime_options_;
  std::unique_ptr<EffectsStreamManipulator> stream_manipulator_;
  Camera3StreamConfiguration stream_config_;
  StreamEffectMap stream_effects_map_;
  base::FilePath config_path_;

  ScopedBufferHandle output_buffer_;
  std::vector<Camera3StreamBuffer> output_buffers_;

  void InitialiseStreamManipulator();
  void ProcessFileThroughStreamManipulator(base::FilePath infile,
                                           base::FilePath outfile,
                                           int num_repeats);
  void GetRgbaBufferFromYuvBuffer(ScopedBufferHandle& yuv_buffer,
                                  ImageFrame& frame_info);
  bool CompareFrames(ScopedBufferHandle& ref_buffer,
                     ScopedBufferHandle& output_buffer);

  void WaitForEffectSetAndReset();

  std::unique_ptr<EglContext> egl_context_;
  std::unique_ptr<GpuImageProcessor> image_processor_;

  base::test::TaskEnvironment task_environment_;
  base::WaitableEvent frame_processed_;
};

void EffectsStreamManipulatorTest::WaitForEffectSetAndReset() {
  loop->Run();
  ASSERT_TRUE(effect_set_success);
  effect_set_success = false;
  loop = std::make_unique<base::RunLoop>();
}

void EffectsStreamManipulatorTest::InitialiseStreamManipulator() {
  stream_manipulator_ = EffectsStreamManipulator::Create(
      config_path_, &runtime_options_,
      std::make_unique<FakeStillCaptureProcessor>(), SetEffectCallback);

  base::RepeatingCallback<void(Camera3CaptureDescriptor)> result_cb =
      base::BindRepeating(
          [](base::WaitableEvent& frame_processed,
             Camera3CaptureDescriptor descriptor) {
            // resume only after the requested frame is processed
            if (descriptor.num_output_buffers() >= 1) {
              frame_processed.Signal();
            }
          },
          std::ref(frame_processed_));

  stream_manipulator_->Initialize(
      nullptr,
      StreamManipulator::Callbacks{.result_callback = result_cb,
                                   .notify_callback = base::DoNothing()});

  stream_manipulator_->ConfigureStreams(&stream_config_, &stream_effects_map_);
  stream_manipulator_->OnConfiguredStreams(&stream_config_);
}

void EffectsStreamManipulatorTest::ProcessFileThroughStreamManipulator(
    base::FilePath infile, base::FilePath outfile, int num_repeats) {
  for (uint32_t i = 0; i < num_repeats; ++i) {
    // read input file into buffer
    ReadFileIntoBuffer(*output_buffer_, infile);
    Camera3CaptureDescriptor result(
        camera3_capture_result_t{.frame_number = i});
    output_buffers_.emplace_back(
        Camera3StreamBuffer::MakeRequestOutput(camera3_stream_buffer_t{
            .stream = &yuv_720_stream,
            .buffer = output_buffer_.get(),
            .status = CAMERA3_BUFFER_STATUS_OK,
            .acquire_fence = -1,
            .release_fence = -1,
        }));
    result.SetOutputBuffers(std::move(output_buffers_));
    stream_manipulator_->GetTaskRunner()->PostTask(
        FROM_HERE, base::BindOnce(
                       [](StreamManipulator* stream_manipulator,
                          Camera3CaptureDescriptor result) {
                         ASSERT_TRUE(stream_manipulator->ProcessCaptureResult(
                             std::move(result)));
                       },
                       stream_manipulator_.get(), std::move(result)));
    frame_processed_.Wait();
    frame_processed_.Reset();
  }

  if (outfile != base::FilePath("")) {
    WriteBufferIntoFile(*output_buffer_, outfile);
    LOG(INFO) << "File written to: " << outfile;
  }
}

void EffectsStreamManipulatorTest::GetRgbaBufferFromYuvBuffer(
    ScopedBufferHandle& yuv_buffer, ImageFrame& frame_info) {
  uint32_t width = CameraBufferManager::GetWidth(*yuv_buffer);
  uint32_t height = CameraBufferManager::GetHeight(*yuv_buffer);

  ASSERT_EQ(width, frame_info.frame_width);
  ASSERT_EQ(height, frame_info.frame_height);

  SharedImage yuv_image = SharedImage::CreateFromBuffer(
      *yuv_buffer, Texture2D::Target::kTarget2D, true);

  ScopedBufferHandle frame_buffer = CameraBufferManager::AllocateScopedBuffer(
      width, height, kRGBAFormat, kBufferUsage);
  SharedImage rgba_image_ = SharedImage::CreateFromBuffer(
      *frame_buffer, Texture2D::Target::kTarget2D);

  image_processor_->NV12ToRGBA(yuv_image.y_texture(), yuv_image.uv_texture(),
                               rgba_image_.texture());
  glFinish();

  ScopedMapping scoped_mapping = ScopedMapping(rgba_image_.buffer());

  ASSERT_EQ(scoped_mapping.plane(0).stride, frame_info.stride);

  uint8_t* buffer_ptr =
      reinterpret_cast<uint8_t*>(scoped_mapping.plane(0).addr);
  for (int i = 0; i < frame_info.stride * height; ++i) {
    frame_info.frame_data[i] = buffer_ptr[i];
  }
}

bool EffectsStreamManipulatorTest::CompareFrames(
    ScopedBufferHandle& ref_buffer, ScopedBufferHandle& output_buffer) {
  if (CameraBufferManager::GetWidth(*ref_buffer) !=
          CameraBufferManager::GetWidth(*output_buffer) ||
      CameraBufferManager::GetHeight(*ref_buffer) !=
          CameraBufferManager::GetHeight(*output_buffer)) {
    return false;
  }

  uint32_t width = CameraBufferManager::GetWidth(*ref_buffer);
  uint32_t height = CameraBufferManager::GetHeight(*ref_buffer);

  std::unique_ptr<uint8_t[]> ref_buffer_rgb(new uint8_t[width * height * 4]);
  std::unique_ptr<uint8_t[]> output_buffer_rgb(new uint8_t[width * height * 4]);

  ImageFrame ref_info = ImageFrame{.frame_data = ref_buffer_rgb.get(),
                                   .frame_width = width,
                                   .frame_height = height,
                                   .stride = width * 4};
  ImageFrame output_info = ImageFrame{.frame_data = output_buffer_rgb.get(),
                                      .frame_width = width,
                                      .frame_height = height,
                                      .stride = width * 4};

  GetRgbaBufferFromYuvBuffer(ref_buffer, ref_info);
  GetRgbaBufferFromYuvBuffer(output_buffer, output_info);

  return FuzzyBufferComparison(ref_info.frame_data, output_info.frame_data,
                               ref_info.stride * ref_info.frame_height, 5,
                               75000);
}

TEST_F(EffectsStreamManipulatorTest, ReplaceEffectAppliedUsingEnableFlag) {
  mojom::EffectsConfigPtr config = mojom::EffectsConfig::New();
  config->replace_enabled = true;
  runtime_options_.SetEffectsConfig(std::move(config));

  InitialiseStreamManipulator();
  ProcessFileThroughStreamManipulator(kSampleImagePath, base::FilePath(""), 1);
  WaitForEffectSetAndReset();
  ProcessFileThroughStreamManipulator(kSampleImagePath, base::FilePath(""),
                                      kNumFrames);

  ScopedBufferHandle ref_buffer = CameraBufferManager::AllocateScopedBuffer(
      yuv_720_stream.width, yuv_720_stream.height, yuv_720_stream.format,
      yuv_720_stream.usage);
  ReadFileIntoBuffer(*ref_buffer, kReplaceImagePath);

  EXPECT_TRUE(CompareFrames(ref_buffer, output_buffer_));
}

TEST_F(EffectsStreamManipulatorTest, BlurEffectWithExtraBlurLevel) {
  mojom::EffectsConfigPtr config = mojom::EffectsConfig::New();
  config->blur_enabled = true;
  config->blur_level = mojom::BlurLevel::kMaximum;
  runtime_options_.SetEffectsConfig(std::move(config));

  InitialiseStreamManipulator();
  ProcessFileThroughStreamManipulator(kSampleImagePath, base::FilePath(""), 1);
  WaitForEffectSetAndReset();
  ProcessFileThroughStreamManipulator(kSampleImagePath, base::FilePath(""),
                                      kNumFrames);

  ScopedBufferHandle ref_buffer = CameraBufferManager::AllocateScopedBuffer(
      yuv_720_stream.width, yuv_720_stream.height, yuv_720_stream.format,
      yuv_720_stream.usage);
  ReadFileIntoBuffer(*ref_buffer, kMaxBlurImagePath);

  EXPECT_TRUE(CompareFrames(ref_buffer, output_buffer_));
}

TEST_F(EffectsStreamManipulatorTest, RelightEffectAppliedUsingEnableFlag) {
  mojom::EffectsConfigPtr config = mojom::EffectsConfig::New();
  config->relight_enabled = true;
  runtime_options_.SetEffectsConfig(std::move(config));

  InitialiseStreamManipulator();
  ProcessFileThroughStreamManipulator(kSampleImagePath, base::FilePath(""), 1);
  WaitForEffectSetAndReset();
  ProcessFileThroughStreamManipulator(kSampleImagePath, base::FilePath(""),
                                      kNumFrames);

  ScopedBufferHandle ref_buffer = CameraBufferManager::AllocateScopedBuffer(
      yuv_720_stream.width, yuv_720_stream.height, yuv_720_stream.format,
      yuv_720_stream.usage);
  ReadFileIntoBuffer(*ref_buffer, kRelightImagePath);

  EXPECT_TRUE(CompareFrames(ref_buffer, output_buffer_));
}

TEST_F(EffectsStreamManipulatorTest, NoneEffectApplied) {
  InitialiseStreamManipulator();
  ProcessFileThroughStreamManipulator(kSampleImagePath, base::FilePath(""),
                                      kNumFrames);

  ScopedBufferHandle ref_buffer = CameraBufferManager::AllocateScopedBuffer(
      yuv_720_stream.width, yuv_720_stream.height, yuv_720_stream.format,
      yuv_720_stream.usage);
  ReadFileIntoBuffer(*ref_buffer, kSampleImagePath);

  EXPECT_TRUE(CompareFrames(ref_buffer, output_buffer_));
}

TEST_F(EffectsStreamManipulatorTest,
       RotateThroughEffectsWhileProcessingFrames) {
  InitialiseStreamManipulator();
  ScopedBufferHandle ref_buffer = CameraBufferManager::AllocateScopedBuffer(
      yuv_720_stream.width, yuv_720_stream.height, yuv_720_stream.format,
      yuv_720_stream.usage);

  mojom::EffectsConfigPtr config1 = mojom::EffectsConfig::New();
  config1->relight_enabled = true;
  runtime_options_.SetEffectsConfig(std::move(config1));
  ProcessFileThroughStreamManipulator(kSampleImagePath, base::FilePath(""), 1);
  WaitForEffectSetAndReset();
  ProcessFileThroughStreamManipulator(kSampleImagePath, base::FilePath(""),
                                      kNumFrames);
  ReadFileIntoBuffer(*ref_buffer, kRelightImagePath);
  EXPECT_TRUE(CompareFrames(ref_buffer, output_buffer_));

  mojom::EffectsConfigPtr config2 = mojom::EffectsConfig::New();
  config2->blur_enabled = true;
  runtime_options_.SetEffectsConfig(std::move(config2));
  ProcessFileThroughStreamManipulator(kSampleImagePath, base::FilePath(""), 1);
  WaitForEffectSetAndReset();
  ProcessFileThroughStreamManipulator(kSampleImagePath, base::FilePath(""),
                                      kNumFrames);
  ReadFileIntoBuffer(*ref_buffer, kBlurImagePath);
  EXPECT_TRUE(CompareFrames(ref_buffer, output_buffer_));

  mojom::EffectsConfigPtr config3 = mojom::EffectsConfig::New();
  config3->replace_enabled = true;
  runtime_options_.SetEffectsConfig(std::move(config3));
  ProcessFileThroughStreamManipulator(kSampleImagePath, base::FilePath(""), 1);
  WaitForEffectSetAndReset();
  ProcessFileThroughStreamManipulator(kSampleImagePath, base::FilePath(""),
                                      kNumFrames);
  ReadFileIntoBuffer(*ref_buffer, kReplaceImagePath);
  EXPECT_TRUE(CompareFrames(ref_buffer, output_buffer_));

  mojom::EffectsConfigPtr config4 = mojom::EffectsConfig::New();
  runtime_options_.SetEffectsConfig(std::move(config4));
  ProcessFileThroughStreamManipulator(kSampleImagePath, base::FilePath(""), 1);
  WaitForEffectSetAndReset();
  ProcessFileThroughStreamManipulator(kSampleImagePath, base::FilePath(""),
                                      kNumFrames);
  ReadFileIntoBuffer(*ref_buffer, kSampleImagePath);
  EXPECT_TRUE(CompareFrames(ref_buffer, output_buffer_));
}

TEST_F(EffectsStreamManipulatorTest, OpenCLCacheStartup) {
  mojom::EffectsConfigPtr config = mojom::EffectsConfig::New();
  config->blur_enabled = true;
  config->replace_enabled = true;
  runtime_options_.SetEffectsConfig(std::move(config));
  InitialiseStreamManipulator();
  ProcessFileThroughStreamManipulator(kSampleImagePath, base::FilePath(""), 1);
  WaitForEffectSetAndReset();
}
}  // namespace cros::tests

int main(int argc, char** argv) {
  base::CommandLine::Init(argc, argv);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  if (cl->HasSwitch("nodlc")) {
    dlc_path = base::FilePath("/usr/local/lib64");
  } else {
    cros::DlcLoader client;
    client.Run();
    if (!client.DlcLoaded()) {
      LOG(ERROR) << "Failed to load DLC";
      return -1;
    }
    dlc_path = client.GetDlcRootPath();
  }
  ::testing::InitGoogleTest(&argc, argv);
  TestTimeouts::Initialize();
  return RUN_ALL_TESTS();
}
