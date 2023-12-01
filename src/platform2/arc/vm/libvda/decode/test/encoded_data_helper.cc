// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/libvda/decode/test/encoded_data_helper.h"

#include <base/logging.h>
#include <base/notreached.h>
#include <base/stl_util.h>

namespace {
constexpr uint32_t kNalUnitTypeSPS = 7;
}  // namespace

EncodedDataHelper::EncodedDataHelper(const std::string& data,
                                     vda_profile_t profile)
    : data_(data), profile_(profile) {}

EncodedDataHelper::EncodedDataHelper(const std::vector<uint8_t>& stream,
                                     vda_profile_t profile)
    : EncodedDataHelper(
          std::string(reinterpret_cast<const char*>(stream.data()),
                      stream.size()),
          profile) {}

bool EncodedDataHelper::IsNALHeader(const std::string& data, size_t pos) {
  return data[pos] == 0 && data[pos + 1] == 0 && data[pos + 2] == 0 &&
         data[pos + 3] == 1;
}

std::string EncodedDataHelper::GetBytesForNextData() {
  switch (profile_) {
    case H264PROFILE_BASELINE:
    case H264PROFILE_MAIN:
    case H264PROFILE_EXTENDED:
    case H264PROFILE_HIGH:
    case H264PROFILE_HIGH10PROFILE:
    case H264PROFILE_HIGH422PROFILE:
    case H264PROFILE_HIGH444PREDICTIVEPROFILE:
    case H264PROFILE_SCALABLEBASELINE:
    case H264PROFILE_SCALABLEHIGH:
    case H264PROFILE_STEREOHIGH:
    case H264PROFILE_MULTIVIEWHIGH:
      return GetBytesForNextFragment();
    case VP8PROFILE_ANY:
    case VP9PROFILE_PROFILE0:
    case VP9PROFILE_PROFILE1:
    case VP9PROFILE_PROFILE2:
    case VP9PROFILE_PROFILE3:
      return GetBytesForNextFrame();
    default:
      NOTREACHED();
      return std::string();
  }
}

std::string EncodedDataHelper::GetBytesForNextFragment() {
  if (next_pos_to_decode_ == 0) {
    size_t skipped_fragments_count = 0;
    if (!LookForSPS(&skipped_fragments_count)) {
      next_pos_to_decode_ = 0;
      return std::string();
    }
    num_skipped_fragments_ += skipped_fragments_count;
  }

  size_t start_pos = next_pos_to_decode_;
  size_t next_nalu_pos = GetBytesForNextNALU(start_pos);

  next_pos_to_decode_ = next_nalu_pos;
  return data_.substr(start_pos, next_nalu_pos - start_pos);
}

size_t EncodedDataHelper::GetBytesForNextNALU(size_t start_pos) {
  size_t pos = start_pos;
  if (pos + 4 > data_.size())
    return pos;
  LOG_ASSERT(IsNALHeader(data_, pos));
  pos += 4;
  while (pos + 4 <= data_.size() && !IsNALHeader(data_, pos))
    ++pos;
  if (pos + 3 >= data_.size())
    pos = data_.size();
  return pos;
}

bool EncodedDataHelper::LookForSPS(size_t* skipped_fragments_count) {
  *skipped_fragments_count = 0;
  while (next_pos_to_decode_ + 4 < data_.size()) {
    if ((data_[next_pos_to_decode_ + 4] & 0x1f) == kNalUnitTypeSPS)
      return true;
    *skipped_fragments_count += 1;
    next_pos_to_decode_ = GetBytesForNextNALU(next_pos_to_decode_);
  }
  return false;
}

std::string EncodedDataHelper::GetBytesForNextFrame() {
  // Helpful description: http://wiki.multimedia.cx/index.php?title=IVF
  size_t pos = next_pos_to_decode_;
  std::string bytes;
  if (pos == 0)
    pos = 32;  // Skip IVF header.

  uint32_t frame_size = *reinterpret_cast<uint32_t*>(&data_[pos]);
  pos += 12;  // Skip frame header.
  bytes.append(data_.substr(pos, frame_size));

  next_pos_to_decode_ = pos + frame_size;
  return bytes;
}
