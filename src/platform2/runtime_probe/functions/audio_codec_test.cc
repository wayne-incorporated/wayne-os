// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/strings/string_util.h>

#include "runtime_probe/functions/audio_codec.h"
#include "runtime_probe/utils/function_test_utils.h"

namespace runtime_probe {
namespace {

class AudioCodecTest : public BaseFunctionTest {};

TEST_F(AudioCodecTest, Succeed) {
  SetFile(kAsocPaths[1], "codec1\ncodec2\ncodec3\n");
  auto ans = CreateProbeResultFromJson(R"JSON(
    [
      { "name": "codec1" },
      { "name": "codec2" },
      { "name": "codec3" }
    ]
  )JSON");

  auto probe_function = CreateProbeFunction<AudioCodecFunction>();
  auto result = probe_function->Eval();
  EXPECT_EQ(result, ans);
}

TEST_F(AudioCodecTest, SucceedPreKernel4_4) {
  SetFile(kAsocPaths[0], "codec1\ncodec2\ncodec3\n");
  auto ans = CreateProbeResultFromJson(R"JSON(
    [
      { "name": "codec1" },
      { "name": "codec2" },
      { "name": "codec3" }
    ]
  )JSON");

  auto probe_function = CreateProbeFunction<AudioCodecFunction>();
  auto result = probe_function->Eval();
  EXPECT_EQ(result, ans);
}

TEST_F(AudioCodecTest, NoCodecFile) {
  auto ans = CreateProbeResultFromJson(R"JSON(
    []
  )JSON");

  auto probe_function = CreateProbeFunction<AudioCodecFunction>();
  auto result = probe_function->Eval();
  EXPECT_EQ(result, ans);
}

TEST_F(AudioCodecTest, IgnoreInvalidCodec) {
  SetFile(kAsocPaths[1], base::JoinString(kKnownInvalidCodecNames, "\n"));
  auto ans = CreateProbeResultFromJson(R"JSON(
    []
  )JSON");

  auto probe_function = CreateProbeFunction<AudioCodecFunction>();
  auto result = probe_function->Eval();
  EXPECT_EQ(result, ans);
}

}  // namespace
}  // namespace runtime_probe
