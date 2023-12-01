// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml_benchmark/memory_sampler.h"

#include <base/task/task_traits.h>
#include <base/task/thread_pool.h>

#include <algorithm>

#include "ml_benchmark/sysmetrics.h"

namespace ml_benchmark {

PeakMemorySampler::PeakMemorySampler() : from_here_(FROM_HERE) {
  task_runner_ = base::ThreadPool::CreateSequencedTaskRunner(
      {base::MayBlock(), base::TaskPriority::BEST_EFFORT,
       base::TaskShutdownBehavior::SKIP_ON_SHUTDOWN});
}

PeakMemorySampler::~PeakMemorySampler() {
  SetRunning(false);
}

void PeakMemorySampler::SetRunning(bool is_running) {
  base::AutoLock auto_lock(lock_);
  running_ = is_running;
}

void PeakMemorySampler::StartSampling(
    scoped_refptr<PeakMemorySampler> sampler) {
  sampler->SetRunning(true);
  SampleMemory(sampler);
}

void PeakMemorySampler::StopSampling(scoped_refptr<PeakMemorySampler> sampler) {
  sampler->SetRunning(false);
}

int64_t PeakMemorySampler::GetMaxSample() {
  // Writing to max_sample_ is protected by this lock as well.
  base::AutoLock auto_lock(lock_);
  return max_sample_;
}

void PeakMemorySampler::SampleMemory(scoped_refptr<PeakMemorySampler> sampler) {
  base::AutoLock auto_lock(sampler->lock_);
  if (!sampler->running_)
    return;

  sampler->sample_counter_++;
  sampler->max_sample_ = std::max(sampler->max_sample_, GetSwapAndRSSBytes());
  sampler->task_runner_->PostDelayedTask(
      sampler->from_here_,
      base::BindRepeating(&PeakMemorySampler::SampleMemory, sampler),
      sampler->sampling_interval_);
}

}  // namespace ml_benchmark
