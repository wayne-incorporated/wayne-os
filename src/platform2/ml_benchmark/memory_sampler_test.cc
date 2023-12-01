// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml_benchmark/memory_sampler.h"

#include <base/test/task_environment.h>
#include <gtest/gtest.h>

namespace ml_benchmark {

class PeakMemorySamplerTest : public ::testing::Test {
 public:
  PeakMemorySamplerTest() = default;

 protected:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  base::TimeDelta sampling_interval_ = base::Seconds(1);
};

TEST_F(PeakMemorySamplerTest, BasicFunctions) {
  scoped_refptr<PeakMemorySampler> sampler = new PeakMemorySampler();

  // No samples should mean zero
  EXPECT_EQ(sampler->GetMaxSample(), 0);
  EXPECT_EQ(sampler->sample_counter_, 0);

  PeakMemorySampler::StartSampling(sampler);
  task_environment_.FastForwardBy(sampling_interval_);
  const int64_t initial_peak = sampler->GetMaxSample();
  // StartSampling causes a sample, plus the interval is two samples.
  EXPECT_EQ(sampler->sample_counter_, 2);

  task_environment_.FastForwardBy(sampling_interval_ * 2);

  // Allocate 100MB
  const int hundred_mb_bytes = 1024 * 1024 * 100;
  char* allocate = new char[hundred_mb_bytes];
  // Zero it out and read so the compiler doesn't optimize the variable away.
  memset(allocate, 0, hundred_mb_bytes);
  EXPECT_EQ(allocate[hundred_mb_bytes - 1], 0);

  task_environment_.FastForwardBy(sampling_interval_);
  const int64_t higher_peak = sampler->GetMaxSample();
  EXPECT_GT(higher_peak, initial_peak);

  // Free the memory and make sure the peak doesn't drop
  delete[] allocate;
  task_environment_.FastForwardBy(sampling_interval_);
  EXPECT_EQ(higher_peak, sampler->GetMaxSample());

  // Stop sampling, allocate a bunch more memory
  PeakMemorySampler::StopSampling(sampler);
  EXPECT_EQ(sampler->sample_counter_, 6);

  // Allocate 200MB
  const int two_hundred_mb_bytes = 1024 * 1024 * 200;
  allocate = new char[two_hundred_mb_bytes];
  // Zero it out and read so the compiler doesn't optimize the variable away.
  memset(allocate, 0, two_hundred_mb_bytes);
  EXPECT_EQ(allocate[two_hundred_mb_bytes - 1], 0);

  // We're not sampling so the peak should stay the same.
  task_environment_.FastForwardBy(sampling_interval_ * 2);
  EXPECT_EQ(higher_peak, sampler->GetMaxSample());
  EXPECT_EQ(sampler->sample_counter_, 6);

  // Start sampling again and check it grows
  PeakMemorySampler::StartSampling(sampler);
  task_environment_.FastForwardBy(sampling_interval_);
  EXPECT_GT(sampler->GetMaxSample(), higher_peak);

  // StartSampling causes a sample, plus the interval is two samples.
  EXPECT_EQ(sampler->sample_counter_, 8);

  delete[] allocate;
}

TEST_F(PeakMemorySamplerTest, LifeCycle) {
  scoped_refptr<PeakMemorySampler> sampler = new PeakMemorySampler();

  PeakMemorySampler::StartSampling(sampler);
  task_environment_.FastForwardBy(sampling_interval_);
  EXPECT_GT(sampler->GetMaxSample(), 0);

  // At this point another task has been scheduled in t+1, so
  // delete the object and move forward in time. We expect this
  // to 'just work' and not crash due to some dangling pointer.
  sampler.reset();
  task_environment_.FastForwardBy(sampling_interval_ * 2);
}

}  // namespace ml_benchmark
