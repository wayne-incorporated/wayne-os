// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_STRUCTURED_FAKE_RECORDER_H_
#define METRICS_STRUCTURED_FAKE_RECORDER_H_

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <base/time/time.h>
#include <brillo/brillo_export.h>
#include <metrics/structured/key_data.h>
#include <metrics/structured/recorder_impl.h>
#include <metrics/metrics_library.h>

namespace metrics {
namespace structured {

// FakeRecorder deletes keys and events on construction. It writes metrics to
// disk by calling its superclass RecorderImpl's Record() method.
class BRILLO_EXPORT FakeRecorder : public RecorderImpl {
 public:
  FakeRecorder();
  FakeRecorder(const std::string& events_directory,
               const std::string& keys_path);
  ~FakeRecorder() override;
  FakeRecorder(const FakeRecorder&) = delete;
  FakeRecorder& operator=(const FakeRecorder&) = delete;

  // Create the events directory for testing.
  static bool CreateEventsDir(const std::string& events_dir);
  // Delete the keys file and events directory for testing.
  static bool ClearEventsData(const std::string& events_dir,
                              const std::string& keys_path);

 private:
  // Where to save event protos.
  const std::string events_directory_;

  // Used for checking the UMA consent.
  MetricsLibrary metrics_library_;

  KeyData key_data_;
};

}  // namespace structured
}  // namespace metrics

#endif  // METRICS_STRUCTURED_FAKE_RECORDER_H_
