/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common/metadata_logger.h"

#include <utility>

#include <base/files/file_util.h>
#include <base/json/json_writer.h>

#include "cros-camera/common.h"

namespace cros {

namespace {

constexpr char kKeyFrameNumber[] = "frame_number";

}  // namespace

MetadataLogger::MetadataLogger(Options options) : options_(options) {}

MetadataLogger::~MetadataLogger() {
  if (options_.auto_dump_on_destruction) {
    DumpMetadata();
  }
}

template <>
void MetadataLogger::Log(int frame_number, std::string key, uint8_t value) {
  base::AutoLock lock(frame_metadata_lock_);
  base::Value::Dict& entry = GetOrCreateEntryLocked(frame_number);
  entry.Set(key, value);
}

template <>
void MetadataLogger::Log(int frame_number, std::string key, int32_t value) {
  base::AutoLock lock(frame_metadata_lock_);
  base::Value::Dict& entry = GetOrCreateEntryLocked(frame_number);
  entry.Set(key, value);
}

template <>
void MetadataLogger::Log(int frame_number, std::string key, float value) {
  base::AutoLock lock(frame_metadata_lock_);
  base::Value::Dict& entry = GetOrCreateEntryLocked(frame_number);
  entry.Set(key, value);
}

template <>
void MetadataLogger::Log(int frame_number, std::string key, int64_t value) {
  base::AutoLock lock(frame_metadata_lock_);
  base::Value::Dict& entry = GetOrCreateEntryLocked(frame_number);
  // JSON does not support int64, so let's use double instead.
  entry.Set(key, static_cast<double>(value));
}

template <>
void MetadataLogger::Log(int frame_number, std::string key, double value) {
  base::AutoLock lock(frame_metadata_lock_);
  base::Value::Dict& entry = GetOrCreateEntryLocked(frame_number);
  entry.Set(key, value);
}

template <>
void MetadataLogger::Log(int frame_number, std::string key, Rational value) {
  base::AutoLock lock(frame_metadata_lock_);
  base::Value::Dict& entry = GetOrCreateEntryLocked(frame_number);
  entry.Set(key, static_cast<double>(value.numerator) / value.denominator);
}

template <>
void MetadataLogger::Log(int frame_number,
                         std::string key,
                         base::span<const uint8_t> values) {
  base::AutoLock lock(frame_metadata_lock_);
  base::Value::Dict& entry = GetOrCreateEntryLocked(frame_number);
  base::Value::List value_list;
  for (const auto& v : values) {
    value_list.Append(static_cast<int>(v));
  }
  entry.Set(key, std::move(value_list));
}

template <>
void MetadataLogger::Log(int frame_number,
                         std::string key,
                         base::span<const int32_t> values) {
  base::AutoLock lock(frame_metadata_lock_);
  base::Value::Dict& entry = GetOrCreateEntryLocked(frame_number);
  base::Value::List value_list;
  for (const auto& v : values) {
    value_list.Append(v);
  }
  entry.Set(key, std::move(value_list));
}

template <>
void MetadataLogger::Log(int frame_number,
                         std::string key,
                         base::span<const float> values) {
  base::AutoLock lock(frame_metadata_lock_);
  base::Value::Dict& entry = GetOrCreateEntryLocked(frame_number);
  base::Value::List value_list;
  for (const auto& v : values) {
    value_list.Append(static_cast<double>(v));
  }
  entry.Set(key, std::move(value_list));
}

template <>
void MetadataLogger::Log(int frame_number,
                         std::string key,
                         base::span<const int64_t> values) {
  base::AutoLock lock(frame_metadata_lock_);
  base::Value::Dict& entry = GetOrCreateEntryLocked(frame_number);
  base::Value::List value_list;
  for (const auto& v : values) {
    value_list.Append(static_cast<double>(v));
  }
  entry.Set(key, std::move(value_list));
}

template <>
void MetadataLogger::Log(int frame_number,
                         std::string key,
                         base::span<const double> values) {
  base::AutoLock lock(frame_metadata_lock_);
  base::Value::Dict& entry = GetOrCreateEntryLocked(frame_number);
  base::Value::List value_list;
  for (const auto& v : values) {
    value_list.Append(v);
  }
  entry.Set(key, std::move(value_list));
}

template <>
void MetadataLogger::Log(int frame_number,
                         std::string key,
                         base::span<const Rational> values) {
  base::AutoLock lock(frame_metadata_lock_);
  base::Value::Dict& entry = GetOrCreateEntryLocked(frame_number);
  base::Value::List value_list;
  for (const auto& v : values) {
    value_list.Append(static_cast<double>(v.numerator) / v.denominator);
  }
  entry.Set(key, std::move(value_list));
}

template <>
void MetadataLogger::Log(int frame_number,
                         std::string key,
                         base::span<const camera_metadata_rational_t> values) {
  base::AutoLock lock(frame_metadata_lock_);
  base::Value::Dict& entry = GetOrCreateEntryLocked(frame_number);
  base::Value::List value_list;
  for (const auto& v : values) {
    value_list.Append(static_cast<double>(v.numerator) / v.denominator);
  }
  entry.Set(key, std::move(value_list));
}

bool MetadataLogger::DumpMetadata() {
  base::Value::List metadata_to_dump;
  {
    base::AutoLock lock(frame_metadata_lock_);
    for (const auto& entry : frame_metadata_) {
      metadata_to_dump.Append(entry.second.Clone());
    }
  }
  std::string json_string;
  if (!base::JSONWriter::WriteWithOptions(
          metadata_to_dump, base::JSONWriter::OPTIONS_PRETTY_PRINT,
          &json_string)) {
    LOGF(WARNING) << "Can't jsonify frame metadata";
    return false;
  }
  if (!base::WriteFile(options_.dump_path, json_string)) {
    LOGF(WARNING) << "Can't write frame metadata";
    return false;
  }
  return true;
}

void MetadataLogger::Clear() {
  base::AutoLock lock(frame_metadata_lock_);
  frame_metadata_.clear();
}

base::Value::Dict& MetadataLogger::GetOrCreateEntryLocked(int frame_number) {
  frame_metadata_lock_.AssertAcquired();
  if (frame_metadata_.count(frame_number) == 0) {
    if (frame_metadata_.size() == options_.ring_buffer_capacity) {
      frame_metadata_.erase(frame_metadata_.begin());
    }
    base::Value::Dict entry;
    entry.Set(kKeyFrameNumber, frame_number);
    frame_metadata_.insert({frame_number, std::move(entry)});
  }
  return frame_metadata_[frame_number];
}

}  // namespace cros
