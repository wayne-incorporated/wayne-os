/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "camera/features/auto_framing/tests/auto_framing_test_fixture.h"

#include <base/timer/elapsed_timer.h>
#include <brillo/flag_helper.h>

// gtest's internal typedef of None and Bool conflicts with the None and Bool
// macros in X11/X.h (https://github.com/google/googletest/issues/371).
// X11/X.h is pulled in by the GL headers we include.
#pragma push_macro("None")
#pragma push_macro("Bool")
#undef None
#undef Bool
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#pragma pop_macro("None")
#pragma pop_macro("Bool")

#include "common/test_support/fake_still_capture_processor.h"

namespace cros::tests {

namespace {

// Describes an interval [start + t1, start + t2] on the virtual timeline during
// test.
using TimeInterval = std::pair<base::TimeDelta, base::TimeDelta>;

std::optional<TimeInterval> Contains(const std::vector<TimeInterval>& intervals,
                                     base::TimeDelta t) {
  for (auto& interval : intervals) {
    if (t >= interval.first && t <= interval.second) {
      return interval;
    }
  }
  return std::nullopt;
}

}  // namespace

base::FilePath g_test_image_path;
float g_frame_rate = 30.0f;
base::TimeDelta g_duration = base::Seconds(4);
base::TimeDelta g_max_detection_time = base::Seconds(0.3);
base::TimeDelta g_max_transition_time = base::Seconds(1.1);

struct TestSizes {
  Size full_yuv;
  Size full_blob;
  Size client_yuv;
  Size client_blob;
};

void TestAutoFramingPipeline(
    const TestSizes& sizes,
    const std::vector<TestStreamConfig>& test_stream_configs,
    const AutoFramingStreamManipulator::Options& options,
    std::vector<TimeInterval> enabled_intervals,
    std::optional<base::TimeDelta> still_shot_period,
    std::vector<TimeInterval> expected_face_detected_intervals,
    std::vector<TimeInterval> expected_crop_fixed_intervals,
    std::vector<TimeInterval> expected_crop_full_intervals) {
  const base::TimeDelta frame_duration = base::Seconds(1.0f / g_frame_rate);
  const int num_still_shots =
      still_shot_period.has_value() ? g_duration / *still_shot_period : 0;

  AutoFramingTestFixture fixture;
  ASSERT_TRUE(fixture.LoadTestImage(g_test_image_path));
  ASSERT_TRUE(fixture.SetUp(sizes.full_yuv, sizes.full_blob, sizes.client_yuv,
                            sizes.client_blob, g_frame_rate,
                            test_stream_configs, options,
                            std::make_unique<FakeStillCaptureProcessor>()));

  std::map<TimeInterval, bool> face_detected;
  for (auto& interval : expected_face_detected_intervals) {
    face_detected[interval] = false;
  }

  base::ElapsedTimer timer;
  base::TimeDelta frame_timestamp = base::Seconds(0);
  base::TimeDelta frame_start = base::Seconds(0);
  base::TimeDelta last_still_shot = base::Seconds(0);
  for (auto& cfg : test_stream_configs) {
    while (frame_timestamp <= frame_start + cfg.duration) {
      frame_timestamp = timer.Elapsed();
      const bool is_enabled =
          Contains(enabled_intervals, frame_timestamp).has_value();
      bool is_still_shot = false;
      if (still_shot_period.has_value() &&
          frame_timestamp - last_still_shot >= *still_shot_period) {
        is_still_shot = true;
        last_still_shot = frame_timestamp;
      }
      FramingResult result;
      ASSERT_TRUE(fixture.ProcessFrame(frame_timestamp.InNanoseconds(),
                                       is_enabled, /*has_yuv=*/!is_still_shot,
                                       /*has_blob=*/is_still_shot, &result));
      const base::TimeDelta process_time = timer.Elapsed() - frame_timestamp;
      if (!is_still_shot) {
        EXPECT_LT(process_time, frame_duration);
      }

      const auto fd_interval =
          Contains(expected_face_detected_intervals, frame_timestamp);
      if (fd_interval.has_value()) {
        face_detected.at(*fd_interval) |= result.is_face_detected;
      }

      if (Contains(expected_crop_fixed_intervals, frame_timestamp)
              .has_value()) {
        EXPECT_FALSE(result.is_crop_window_moving)
            << "Crop window should be fixed at " << frame_timestamp;
      }
      if (Contains(expected_crop_full_intervals, frame_timestamp).has_value()) {
        EXPECT_TRUE(result.is_crop_window_full)
            << "Crop window should be full frame at " << frame_timestamp;
      }

      if (frame_duration > process_time) {
        base::PlatformThread::Sleep(frame_duration - process_time);
      }
    }
    frame_start += cfg.duration;
  }

  for (auto& interval : expected_face_detected_intervals) {
    EXPECT_TRUE(face_detected.at(interval))
        << "Face not detected in (" << interval.first << ", " << interval.second
        << ")";
  }

  // Wait for the last still capture.
  if (num_still_shots > 0) {
    constexpr base::TimeDelta kMaxShutterLag = base::Seconds(1);
    base::PlatformThread::Sleep(kMaxShutterLag);
  }
}

class AutoFramingTest : public ::testing::TestWithParam<TestSizes> {};

INSTANTIATE_TEST_SUITE_P(,
                         AutoFramingTest,
                         ::testing::Values(
                             TestSizes{
                                 .full_yuv = Size(1600, 1200),
                                 .full_blob = Size(2560, 1920),
                                 .client_yuv = Size(1600, 1200),
                                 .client_blob = Size(2560, 1920),
                             },
                             TestSizes{
                                 .full_yuv = Size(1600, 1200),
                                 .full_blob = Size(2560, 1920),
                                 .client_yuv = Size(960, 540),
                                 .client_blob = Size(1280, 720),
                             },
                             TestSizes{
                                 .full_yuv = Size(1920, 1080),
                                 .full_blob = Size(1920, 1080),
                                 .client_yuv = Size(1920, 1080),
                                 .client_blob = Size(1920, 1080),
                             },
                             TestSizes{
                                 .full_yuv = Size(1920, 1080),
                                 .full_blob = Size(1920, 1080),
                                 .client_yuv = Size(960, 720),
                                 .client_blob = Size(1280, 960),
                             }));

// Checks no-op when auto-framing is disabled.
TEST_P(AutoFramingTest, Disabled) {
  const TestSizes& sizes = GetParam();
  const std::vector<TestStreamConfig> test_stream_configs = {
      {
          .duration = g_duration,
          .face_rect = Rect<float>(0.4f, 0.4f, 0.12f, 0.2f),
      },
  };
  const AutoFramingStreamManipulator::Options options = {
      .detection_rate = g_frame_rate,
      .enable_delay = base::Seconds(0),
  };
  const base::TimeDelta still_shot_period = base::Seconds(1);
  const std::vector<TimeInterval> expected_crop_fixed_intervals = {
      {base::Seconds(0), g_duration},
  };
  const std::vector<TimeInterval> expected_crop_full_intervals = {
      {base::Seconds(0), g_duration},
  };

  TestAutoFramingPipeline(sizes, test_stream_configs, options,
                          /*enabled_intervals=*/{}, still_shot_period,
                          /*expected_face_detected_intervals=*/{},
                          expected_crop_fixed_intervals,
                          expected_crop_full_intervals);
}

// Exercises one-shot framing for OFF->ON and ON->OFF transitions.
TEST_P(AutoFramingTest, OneShotFraming) {
  const TestSizes& sizes = GetParam();
  const std::vector<TestStreamConfig> test_stream_configs = {
      {
          .duration = g_duration,
          .face_rect = Rect<float>(0.4f, 0.4f, 0.12f, 0.2f),
      },
  };
  const AutoFramingStreamManipulator::Options options = {
      .detection_rate = 0.0f,
      .enable_delay = base::Seconds(0.1),
      .disable_delay = base::Seconds(0.1),
  };
  const std::vector<TimeInterval> enabled_intervals = {
      {g_duration / 8, g_duration / 8 * 5},
  };
  const std::vector<TimeInterval> expected_face_detected_intervals = {
      {g_duration / 8 + options.enable_delay,
       g_duration / 8 + options.enable_delay + g_max_detection_time},
  };
  ASSERT_LT(options.enable_delay + g_max_detection_time + g_max_transition_time,
            g_duration / 2);
  ASSERT_LT(options.disable_delay + g_max_transition_time, g_duration / 8 * 3);
  const std::vector<TimeInterval> expected_crop_fixed_intervals = {
      {base::Seconds(0), g_duration / 8 + options.enable_delay},
      {g_duration / 8 + options.enable_delay + g_max_detection_time +
           g_max_transition_time,
       g_duration / 8 * 5 + options.disable_delay},
      {g_duration / 8 * 5 + options.disable_delay + g_max_transition_time,
       g_duration},
  };
  const std::vector<TimeInterval> expected_crop_full_intervals = {
      {base::Seconds(0), g_duration / 8 + options.enable_delay},
      {g_duration / 8 * 5 + options.disable_delay + g_max_transition_time,
       g_duration},
  };

  TestAutoFramingPipeline(
      sizes, test_stream_configs, options, enabled_intervals,
      /*still_shot_period=*/std::nullopt, expected_face_detected_intervals,
      expected_crop_fixed_intervals, expected_crop_full_intervals);
}

// Exercises one-shot framing when toggling the switch ON->OFF->ON quickly to
// reframe to another face position.
TEST_P(AutoFramingTest, OneShotReframing) {
  const TestSizes& sizes = GetParam();
  const std::vector<TestStreamConfig> test_stream_configs = {
      {
          .duration = g_duration / 2,
          .face_rect = Rect<float>(0.4f, 0.4f, 0.12f, 0.2f),
      },
      {
          .duration = g_duration / 2,
          .face_rect = Rect<float>(0.7f, 0.7f, 0.144f, 0.24f),
      },
  };
  const AutoFramingStreamManipulator::Options options = {
      .detection_rate = 0.0f,
      .enable_delay = base::Seconds(0.1),
      .disable_delay = base::Seconds(0.1),
  };
  const std::vector<TimeInterval> enabled_intervals = {
      {base::Seconds(0), g_duration / 2 - options.disable_delay},
      {g_duration / 2, g_duration},
  };
  const std::vector<TimeInterval> expected_face_detected_intervals = {
      {options.enable_delay, options.enable_delay + g_max_detection_time},
      {g_duration / 2 + options.enable_delay,
       g_duration / 2 + options.enable_delay + g_max_detection_time},
  };
  ASSERT_LT(options.enable_delay + g_max_detection_time + g_max_transition_time,
            g_duration / 2);
  const std::vector<TimeInterval> expected_crop_fixed_intervals = {
      {base::Seconds(0), options.enable_delay},
      {options.enable_delay + g_max_detection_time + g_max_transition_time,
       g_duration / 2},
      {g_duration / 2 + options.enable_delay + g_max_detection_time +
           g_max_transition_time,
       g_duration},
  };
  const std::vector<TimeInterval> expected_crop_full_intervals = {
      {base::Seconds(0), options.enable_delay},
  };

  TestAutoFramingPipeline(
      sizes, test_stream_configs, options, enabled_intervals,
      /*still_shot_period=*/std::nullopt, expected_face_detected_intervals,
      expected_crop_fixed_intervals, expected_crop_full_intervals);
}

// Exercises continuous framing when the scene contains a face at fixed
// position.
TEST_P(AutoFramingTest, ContinuousFramingInStillScene) {
  const TestSizes& sizes = GetParam();
  const std::vector<TestStreamConfig> test_stream_configs = {
      {
          .duration = g_duration,
          .face_rect = Rect<float>(0.3f, 0.45f, 0.06f, 0.1f),
      },
  };
  const AutoFramingStreamManipulator::Options options = {
      .detection_rate = g_frame_rate,
      .enable_delay = base::Seconds(0),
  };
  const std::vector<TimeInterval> enabled_intervals = {
      {base::Seconds(0), g_duration},
  };
  const std::vector<TimeInterval> expected_face_detected_intervals = {
      {base::Seconds(0), g_max_detection_time},
  };
  const std::vector<TimeInterval> expected_crop_fixed_intervals = {
      {g_max_detection_time + g_max_transition_time, g_duration},
  };

  TestAutoFramingPipeline(
      sizes, test_stream_configs, options, enabled_intervals,
      /*still_shot_period=*/std::nullopt, expected_face_detected_intervals,
      expected_crop_fixed_intervals,
      /*expected_crop_full_intervals=*/{});
}

// Exercises continuous framing when the scene contains a face moving around.
TEST_P(AutoFramingTest, ContinuousFramingInMovingScene) {
  const TestSizes& sizes = GetParam();
  const std::vector<TestStreamConfig> test_stream_configs = {
      {
          .duration = g_duration / 4,
          .face_rect = Rect<float>(0.3f, 0.45f, 0.06f, 0.1f),
      },
      {
          .duration = g_duration / 4,
          .face_rect = Rect<float>(0.6f, 0.65f, 0.08f, 0.13f),
      },
      {
          .duration = g_duration / 4,
          .face_rect = Rect<float>(0.5f, 0.65f, 0.09f, 0.15f),
      },
      {
          .duration = g_duration / 4,
          .face_rect = Rect<float>(0.4f, 0.6f, 0.07f, 0.12f),
      },
  };
  const AutoFramingStreamManipulator::Options options = {
      .detection_rate = g_frame_rate,
      .enable_delay = base::Seconds(0),
  };
  const std::vector<TimeInterval> enabled_intervals = {
      {base::Seconds(0), g_duration},
  };
  const std::vector<TimeInterval> expected_face_detected_intervals = {
      {g_duration / 4 * 0, g_duration / 4 * 0 + g_max_detection_time},
      {g_duration / 4 * 1, g_duration / 4 * 1 + g_max_detection_time},
      {g_duration / 4 * 2, g_duration / 4 * 2 + g_max_detection_time},
      {g_duration / 4 * 3, g_duration / 4 * 3 + g_max_detection_time},
  };

  TestAutoFramingPipeline(
      sizes, test_stream_configs, options, enabled_intervals,
      /*still_shot_period=*/std::nullopt, expected_face_detected_intervals,
      /*expected_crop_fixed_intervals=*/{},
      /*expected_crop_full_intervals=*/{});
}

// Exercises taking pictures.
TEST_P(AutoFramingTest, StillCapture) {
  const TestSizes& sizes = GetParam();
  const std::vector<TestStreamConfig> test_stream_configs = {
      {
          .duration = g_duration,
          .face_rect = Rect<float>(0.3f, 0.45f, 0.06f, 0.1f),
      },
  };
  const AutoFramingStreamManipulator::Options options = {
      .detection_rate = g_frame_rate,
      .enable_delay = base::Seconds(0),
  };
  const std::vector<TimeInterval> enabled_intervals = {
      {base::Seconds(0), g_duration},
  };
  const base::TimeDelta still_shot_period = base::Seconds(1);
  const std::vector<TimeInterval> expected_face_detected_intervals = {
      {base::Seconds(0), g_max_detection_time},
  };
  const std::vector<TimeInterval> expected_crop_fixed_intervals = {
      {g_max_detection_time + g_max_transition_time, g_duration},
  };

  TestAutoFramingPipeline(
      sizes, test_stream_configs, options, enabled_intervals, still_shot_period,
      expected_face_detected_intervals, expected_crop_fixed_intervals,
      /*expected_crop_full_intervals=*/{});
}

// Exercises out-of-order timestamps for external cameras.
TEST_F(AutoFramingTest, OutOfOrderTimestamps) {
  const base::TimeDelta frame_duration = base::Seconds(1.0f / g_frame_rate);
  const Size full_size(1280, 720);
  const Size client_size(320, 240);
  const TestStreamConfig test_stream_config = {
      .duration = g_duration,
      .face_rect = Rect<float>(0.4f, 0.4f, 0.12f, 0.2f),
  };
  const AutoFramingStreamManipulator::Options options = {
      .detection_rate = g_frame_rate,
  };

  AutoFramingTestFixture fixture;
  ASSERT_TRUE(fixture.LoadTestImage(g_test_image_path));
  ASSERT_TRUE(fixture.SetUp(full_size, full_size, client_size, client_size,
                            g_frame_rate, {test_stream_config}, options,
                            std::make_unique<FakeStillCaptureProcessor>()));

  base::ElapsedTimer timer;
  int frame_count = 0;
  int64_t timestamp = 0;
  const int64_t step = frame_duration.InNanoseconds();
  while (timer.Elapsed() <= test_stream_config.duration) {
    ++frame_count;
    timestamp += frame_count % 10 == 0 ? -step : step;
    ASSERT_TRUE(fixture.ProcessFrame(timestamp, /*is_enabled=*/true,
                                     /*has_yuv=*/true,
                                     /*has_blob=*/false,
                                     /*framing_result=*/nullptr));
    base::PlatformThread::Sleep(frame_duration);
  }
}

}  // namespace cros::tests

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  base::CommandLine::Init(argc, argv);

  logging::LoggingSettings settings;
  logging::InitLogging(settings);

  DEFINE_string(test_image_path, "", "Test image file path");
  DEFINE_double(frame_rate, 30.0, "Frame rate (fps)");
  DEFINE_double(duration, 4.0, "Duration for each test case (seconds)");
  DEFINE_double(max_detection_time, 0.3,
                "Maximum allowed time for a face to be detected (seconds)");
  DEFINE_double(max_transition_time, 1.1,
                "Maximum time for crop window transition (seconds)");
  brillo::FlagHelper::Init(argc, argv, "Auto-framing pipeline unit tests");

  LOG_ASSERT(!FLAGS_test_image_path.empty());
  LOG_ASSERT(FLAGS_frame_rate > 0.0);
  LOG_ASSERT(FLAGS_duration > 0.0);
  LOG_ASSERT(FLAGS_max_detection_time > 0.0);
  cros::tests::g_test_image_path = base::FilePath(FLAGS_test_image_path);
  cros::tests::g_frame_rate = static_cast<float>(FLAGS_frame_rate);
  cros::tests::g_duration = base::Seconds(FLAGS_duration);
  cros::tests::g_max_detection_time = base::Seconds(FLAGS_max_detection_time);
  cros::tests::g_max_transition_time = base::Seconds(FLAGS_max_transition_time);

  return RUN_ALL_TESTS();
}
