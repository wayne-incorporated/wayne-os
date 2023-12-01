// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "metrics/structured/recorder_singleton.h"

#include <utility>

namespace metrics {
namespace structured {
namespace {

constexpr char kEventsPath[] = "/var/lib/metrics/structured/events";

constexpr char kKeysPath[] = "/var/lib/metrics/structured/keys";

}  // namespace

std::unique_ptr<Recorder> RecorderSingleton::recorder_ = nullptr;

RecorderSingleton* RecorderSingleton::GetInstance() {
  static base::NoDestructor<RecorderSingleton> recorder_singleton{};
  return recorder_singleton.get();
}

Recorder* RecorderSingleton::GetRecorder() {
  if (!recorder_) {
    recorder_ = std::make_unique<RecorderImpl>(kEventsPath, kKeysPath);
  }
  return recorder_.get();
}

void RecorderSingleton::SetRecorderForTest(std::unique_ptr<Recorder> recorder) {
  recorder_ = std::move(recorder);
}

void RecorderSingleton::DestroyRecorderForTest() {
  recorder_ = nullptr;
}

RecorderSingleton::RecorderSingleton() = default;

RecorderSingleton::~RecorderSingleton() = default;

}  // namespace structured
}  // namespace metrics
