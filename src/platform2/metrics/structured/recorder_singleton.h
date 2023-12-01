// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_STRUCTURED_RECORDER_SINGLETON_H_
#define METRICS_STRUCTURED_RECORDER_SINGLETON_H_

#include "metrics/structured/recorder_impl.h"

#include <memory>

#include <base/no_destructor.h>
#include <brillo/brillo_export.h>

namespace metrics {
namespace structured {

// RecorderSingleton provides a way to set MockRecorder or FakeRecorder for
// testing. This is used internally by events, but shouldn't need to be
// explicitly called by clients in non-test code.
//
// Example Usage:
//   RecorderSingleton::GetInstance()->SetRecorderForTest(
//         std::move(your_mock_recorder));
class BRILLO_EXPORT RecorderSingleton {
 public:
  RecorderSingleton();
  ~RecorderSingleton();
  RecorderSingleton(const RecorderSingleton&) = delete;
  RecorderSingleton& operator=(const RecorderSingleton&) = delete;

  static RecorderSingleton* GetInstance();
  Recorder* GetRecorder();
  void SetRecorderForTest(std::unique_ptr<Recorder> recorder);
  void DestroyRecorderForTest();

 private:
  friend class base::NoDestructor<RecorderSingleton>;

  static std::unique_ptr<Recorder> recorder_;
};

}  // namespace structured
}  // namespace metrics

#endif  // METRICS_STRUCTURED_RECORDER_SINGLETON_H_
