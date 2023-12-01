// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <EGL/egl.h>
#include <GLES3/gl3.h>

#include <stdlib.h>

#include <base/command_line.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/synchronization/waitable_event.h>
#include <base/values.h>
#include <gtest/gtest.h>

#include "ml_core/dlc/dlc_loader.h"
#include "ml_core/effects_pipeline.h"
#include "ml_core/tests/png_io.h"
#include "ml_core/tests/test_utilities.h"

namespace {

std::atomic<bool> effect_set_success = false;
base::WaitableEvent waitable(base::WaitableEvent::ResetPolicy::MANUAL,
                             base::WaitableEvent::InitialState::NOT_SIGNALED);

base::FilePath DlcPath;
EGLContext context;
bool use_opengl = false;

class EffectsPipelineTest : public ::testing::Test {
 protected:
  void SetUp() override {
    waitable.Reset();
    effect_set_success = false;
    pipeline_ = cros::EffectsPipeline::Create(DlcPath, context);
    if (use_opengl) {
      config_.segmentation_gpu_api = cros::GpuApi::kOpenGL;
      config_.relighting_gpu_api = cros::GpuApi::kOpenGL;
    }
  }

  std::unique_ptr<cros::EffectsPipeline> pipeline_;

  cros::EffectsConfig config_{.relight_enabled = false,
                              .blur_enabled = false,
                              .replace_enabled = false,
                              .blur_level = cros::BlurLevel::kHeavy,
                              .segmentation_gpu_api = cros::GpuApi::kOpenCL,
                              .relighting_gpu_api = cros::GpuApi::kOpenCL,
                              .graph_max_frames_in_flight = 2};
};

void SetEffectCallback(bool success) {
  if (success)
    effect_set_success = true;
  waitable.Signal();
}

bool WaitForEffectSetAndReset() {
  waitable.Wait();
  bool tmp = effect_set_success;
  waitable.Reset();
  effect_set_success = false;
  return tmp;
}

TEST_F(EffectsPipelineTest, SetEffectWithCallback) {
  config_.blur_enabled = true;
  pipeline_->SetEffect(&config_, SetEffectCallback);

  EXPECT_TRUE(WaitForEffectSetAndReset());
}

TEST_F(EffectsPipelineTest, RotateThroughAllEffects) {
  // enabling background blur effect
  config_.blur_enabled = true;
  pipeline_->SetEffect(&config_, SetEffectCallback);
  ASSERT_TRUE(WaitForEffectSetAndReset());

  // enabling relight here so the effect should be
  // blur+relight
  config_.relight_enabled = true;
  pipeline_->SetEffect(&config_, SetEffectCallback);
  ASSERT_TRUE(WaitForEffectSetAndReset());

  // disabling blur so the effect is just relight
  config_.blur_enabled = false;
  pipeline_->SetEffect(&config_, SetEffectCallback);
  ASSERT_TRUE(WaitForEffectSetAndReset());

  // all effects disabled
  config_.relight_enabled = false;
  pipeline_->SetEffect(&config_, SetEffectCallback);
  ASSERT_TRUE(WaitForEffectSetAndReset());

  // enabling background replace effect
  config_.replace_enabled = true;
  pipeline_->SetEffect(&config_, SetEffectCallback);
  ASSERT_TRUE(WaitForEffectSetAndReset());
}

}  // namespace

int main(int argc, char* argv[]) {
  base::CommandLine::Init(argc, argv);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  if (cl->HasSwitch("nodlc")) {
    DlcPath = base::FilePath("/usr/local/lib64");
  } else {
    cros::DlcLoader client;
    client.Run();
    if (!client.DlcLoaded()) {
      LOG(ERROR) << "Failed to load DLC";
      return -1;
    }
    DlcPath = client.GetDlcRootPath();
  }
  use_opengl = cl->HasSwitch("use_opengl");

  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
