// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "metrics/structured/fake_recorder.h"

#include <base/files/file_util.h>
#include <base/logging.h>

namespace metrics {
namespace structured {
namespace {

constexpr char kEventsPathForTesting[] = "structuredMetricsEventsForTesting";

constexpr char kKeysPathForTesting[] = "structuredMetricsKeysForTesting";

}  // namespace

bool FakeRecorder::CreateEventsDir(const std::string& events_dir) {
  base::FilePath filepath = base::FilePath(events_dir);
  if (!base::CreateDirectory(filepath)) {
    PLOG(ERROR) << "Could not create directory " << filepath.value();
    return false;
  }
  return true;
}

bool FakeRecorder::ClearEventsData(const std::string& events_dir,
                                   const std::string& keys_path) {
  // Delete events directory for testing.
  base::FilePath filepath = base::FilePath(events_dir);
  if (!base::DeletePathRecursively(filepath)) {
    PLOG(ERROR) << "Could not delete " << filepath.value();
    return false;
  }

  // Delete keys file for testing.
  filepath = base::FilePath(keys_path);
  if (!base::DeleteFile(filepath)) {
    PLOG(ERROR) << "Could not delete " << filepath.value();
    return false;
  }

  return true;
}

FakeRecorder::FakeRecorder()
    : FakeRecorder(kEventsPathForTesting, kKeysPathForTesting) {}

FakeRecorder::FakeRecorder(const std::string& events_directory,
                           const std::string& keys_path)
    : RecorderImpl(events_directory, keys_path),
      events_directory_(events_directory),
      key_data_(keys_path) {
  FakeRecorder::ClearEventsData(events_directory, keys_path);
  FakeRecorder::CreateEventsDir(events_directory);
}

FakeRecorder::~FakeRecorder() = default;

}  // namespace structured
}  // namespace metrics
