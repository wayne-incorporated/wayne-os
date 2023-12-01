// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_BENCHMARK_MEMORY_SAMPLER_H_
#define ML_BENCHMARK_MEMORY_SAMPLER_H_

#include <base/memory/ref_counted.h>
#include <base/synchronization/lock.h>
#include <base/task/thread_pool.h>
#include <base/time/time.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

namespace ml_benchmark {

class PeakMemorySampler : public base::RefCountedThreadSafe<PeakMemorySampler> {
 public:
  PeakMemorySampler();

  static void StartSampling(scoped_refptr<PeakMemorySampler> sampler);
  static void StopSampling(scoped_refptr<PeakMemorySampler> sampler);
  int64_t GetMaxSample();

 protected:
  ~PeakMemorySampler();
  friend class base::RefCountedThreadSafe<PeakMemorySampler>;

 private:
  static void SampleMemory(scoped_refptr<PeakMemorySampler> sampler);
  void SetRunning(bool is_running);

  base::Location from_here_;
  bool running_ = false;
  base::Lock lock_;
  base::TimeDelta sampling_interval_ = base::Seconds(1);
  int64_t max_sample_ = 0;
  scoped_refptr<base::SequencedTaskRunner> task_runner_;

  // For testing purposes
  int sample_counter_ = 0;
  FRIEND_TEST(PeakMemorySamplerTest, BasicFunctions);
};
}  // namespace ml_benchmark

#endif  // ML_BENCHMARK_MEMORY_SAMPLER_H_
