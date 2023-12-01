// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MEDIA_PERCEPTION_SERIALIZED_PROTO_H_
#define MEDIA_PERCEPTION_SERIALIZED_PROTO_H_

#include <stdint.h>
#include <utility>
#include <vector>

#include <google/protobuf/message_lite.h>

#include <base/check.h>

template <typename Proto>
class Serialized {
 public:
  explicit Serialized(std::vector<uint8_t> bytes) { bytes_ = std::move(bytes); }

  explicit Serialized(const Proto& p) : bytes_(p.ByteSizeLong(), 0) {
    CHECK(p.SerializeToArray(bytes_.data(), bytes_.size()))
        << "Failed to serialize proto: " << p.DebugString();
  }

  std::vector<uint8_t> GetBytes() const { return bytes_; }

  Proto Deserialize() const {
    Proto p;
    CHECK(p.ParseFromArray(bytes_.data(), bytes_.size()))
        << "Failed to deserialize proto: " << p.DebugString();
    return p;
  }

 private:
  std::vector<uint8_t> bytes_;
};

#endif  // MEDIA_PERCEPTION_SERIALIZED_PROTO_H_
