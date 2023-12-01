/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_METADATA_LOGGER_H_
#define CAMERA_COMMON_METADATA_LOGGER_H_

#include <map>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/synchronization/lock.h>
#include <base/values.h>

#include "cros-camera/camera_metadata_utils.h"
#include "cros-camera/export.h"

namespace cros {

// A helper class for logging and storing camera metadata.  The metadata can be
// stored in (key, value) pairs but must be associated with a frame number.  The
// metadata are stored and dumped in JSON format.
class CROS_CAMERA_EXPORT MetadataLogger {
 public:
  struct Options {
    // Capacity of the metadata ring buffer. The logger only stores the last
    // |ring_buffer_capacity| frames of metadata.
    int ring_buffer_capacity = 512;

    // Automatically dumps the logged metadata into |dump_path| when the logger
    // is destroyed.
    bool auto_dump_on_destruction = true;

    // The file path to dump the frame metadata into.
    base::FilePath dump_path;
  };

  explicit MetadataLogger(Options options);
  ~MetadataLogger();

  MetadataLogger(const MetadataLogger& other) = delete;
  MetadataLogger& operator=(const MetadataLogger& other) = delete;

  // Logs the (|key|, |value|) pair for frame specified by |frame_number|.  The
  // method has specialization for the types in the following list.  Due to
  // lack of support for int64_t and unsigned integers, we store unsigned
  // integers as int and int64_t as double.
  //
  // - uint8_t  / base::span<uint8_t>
  // - int32_t  / base::span<int32_t>
  // - float    / base::span<float>
  // - int64_t  / base::span<int64_t>
  // - double   / base::span<double>
  // - Rational / base::span<Rational>
  template <typename T>
  void Log(int frame_number, std::string key, T value);

  // Dumps the logged frame metadata into the dump file.
  //
  // Returns true if the metadata are dumped successfully; false otherwise.
  bool DumpMetadata();

  // Clears the logged frame metadata.
  void Clear();

 private:
  base::Value::Dict& GetOrCreateEntryLocked(int frame_number);

  Options options_;
  base::Lock frame_metadata_lock_;
  std::map<int, base::Value::Dict> frame_metadata_
      GUARDED_BY(frame_metadata_lock_);
};

// Template specializations don't always get exported, so we need to be explicit
// here.
template <>
CROS_CAMERA_EXPORT void MetadataLogger::Log(int frame_number,
                                            std::string key,
                                            uint8_t value);
template <>
CROS_CAMERA_EXPORT void MetadataLogger::Log(int frame_number,
                                            std::string key,
                                            int32_t value);
template <>
CROS_CAMERA_EXPORT void MetadataLogger::Log(int frame_number,
                                            std::string key,
                                            float value);
template <>
CROS_CAMERA_EXPORT void MetadataLogger::Log(int frame_number,
                                            std::string key,
                                            int64_t value);
template <>
CROS_CAMERA_EXPORT void MetadataLogger::Log(int frame_number,
                                            std::string key,
                                            double value);
template <>
CROS_CAMERA_EXPORT void MetadataLogger::Log(int frame_number,
                                            std::string key,
                                            Rational value);
template <>
CROS_CAMERA_EXPORT void MetadataLogger::Log(int frame_number,
                                            std::string key,
                                            base::span<const uint8_t> values);
template <>
CROS_CAMERA_EXPORT void MetadataLogger::Log(int frame_number,
                                            std::string key,
                                            base::span<const int32_t> values);
template <>
CROS_CAMERA_EXPORT void MetadataLogger::Log(int frame_number,
                                            std::string key,
                                            base::span<const float> values);
template <>
CROS_CAMERA_EXPORT void MetadataLogger::Log(int frame_number,
                                            std::string key,
                                            base::span<const int64_t> values);
template <>
CROS_CAMERA_EXPORT void MetadataLogger::Log(int frame_number,
                                            std::string key,
                                            base::span<const double> values);
template <>
CROS_CAMERA_EXPORT void MetadataLogger::Log(int frame_number,
                                            std::string key,
                                            base::span<const Rational> values);

template <>
CROS_CAMERA_EXPORT void MetadataLogger::Log(
    int frame_number,
    std::string key,
    base::span<const camera_metadata_rational_t> values);

}  // namespace cros

#endif  // CAMERA_COMMON_METADATA_LOGGER_H_
