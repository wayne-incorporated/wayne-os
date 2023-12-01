// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hermes/apdu.h"

#include <algorithm>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>

namespace {

// Max data bytes for standard APDUs and extended APDUs.
// Note that the length limit for extended APDUs is not 65536 due
// to a limitation imposed by the Java Card platform.
constexpr size_t kMaxStandardDataSize = 255;
constexpr size_t kMaxExtendedDataSize = 32767;

// Number of bytes Lc and Le fields are in standard and extended APDUs.
// Note: Lc and Le must either both or neither be in extended form.
constexpr size_t kStandardLengthBytes = 1;
constexpr size_t kExtendedLengthBytes = 3;

constexpr size_t kHeaderSize = 4;  // CLA + INS + P1 + P2
constexpr size_t kNumStatusBytes = 2;

}  // namespace

namespace hermes {

CommandApdu::CommandApdu(uint8_t cls,
                         uint8_t instruction,
                         bool is_extended_length,
                         uint16_t le)
    : cls_(cls),
      is_extended_length_(is_extended_length),
      has_more_fragments_(true),
      current_fragment_(0),
      le_(le),
      current_index_(0) {
  max_data_size_ =
      is_extended_length_ ? kMaxExtendedDataSize : kMaxStandardDataSize;
  // Note that 256 is valid for standard APDUs because an Le field of 0 is
  // interpreted to mean that Ne=256.
  if (!is_extended_length_ && 256 < le_) {
    LOG(INFO) << "CommandApdu created with Le of " << le_
              << ", but is not an extended length APDU. Setting Le to 256.";
    le_ = 256;
  } else if (kMaxExtendedDataSize < le_) {
    LOG(INFO) << "CommandApdu created with Le of " << le_
              << " but restrictions imposed by the Java Card platform requires "
              << "Le to fit into a signed 16 bit integer. Setting Le to 32767.";
    le_ = kMaxExtendedDataSize;
  }

  // Create APDU header.
  data_.push_back(static_cast<uint8_t>(cls));          // CLS
  data_.push_back(static_cast<uint8_t>(instruction));  // INS
  data_.push_back(0);                                  // P1
  data_.push_back(0);                                  // P2
}

CommandApdu::CommandApdu(const std::vector<uint8_t>& data)
    : has_more_fragments_(true) {
  VLOG(2) << __func__ << " data:" << base::HexEncode(data.data(), data.size());
  data_ = data;
  cls_ = data[0];
  is_apdu_ready_ = true;
}

void CommandApdu::AddData(const std::initializer_list<uint8_t>& data) {
  DCHECK_EQ(current_index_, 0);
  EnsureLcExists();
  data_.insert(data_.end(), data.begin(), data.end());
}

void CommandApdu::AddData(const std::vector<uint8_t>& data) {
  DCHECK_EQ(current_index_, 0);
  EnsureLcExists();
  data_.insert(data_.end(), data.begin(), data.end());
}

bool CommandApdu::HasMoreFragments() const {
  VLOG(2) << __func__ << " has_more_fragments_: " << has_more_fragments_;
  return has_more_fragments_;
}

size_t CommandApdu::GetNextFragment(uint8_t** fragment) {
  DCHECK(fragment);
  VLOG(2) << __func__;
  if (!HasMoreFragments()) {
    return 0;
  }

  if (is_apdu_ready_) {
    VLOG(2) << __func__
            << " data_:" << base::HexEncode(data_.data(), data_.size());
    // We don't perform any fragmentation/lc logic if data_ already contains the
    // APDU.
    *fragment = &data_[0];
    has_more_fragments_ = false;
    return data_.size();
  }

  size_t header_size = kHeaderSize;
  size_t length_size =
      is_extended_length_ ? kExtendedLengthBytes : kStandardLengthBytes;
  size_t lc_size = 0;

  VLOG(2) << __func__ << " header_size:" << header_size
          << ", length_size:" << length_size;

  // The APDU contains an Lc if it has any data.
  if (data_.size() > kHeaderSize) {
    lc_size += length_size;
  }
  header_size += lc_size;

  bool is_first_fragment = (current_index_ == 0);
  // Do not include APDU header in bytes_left calculation.
  current_index_ += is_first_fragment ? header_size : 0;
  size_t bytes_left = data_.size() - current_index_;
  size_t current_size = std::min(bytes_left, max_data_size_);

  VLOG(2) << __func__ << " bytes_left:" << bytes_left
          << ", current_size:" << current_size;
  bool is_last_fragment = (bytes_left == current_size);
  has_more_fragments_ = !is_last_fragment;

  VLOG(2) << __func__ << " has_more_fragments_:" << has_more_fragments_;

  // Set up APDU header in-place.
  // If Lc is 0, the generated APDU should be either case 1 or 2.
  current_index_ -= header_size;
  data_[current_index_] = data_[0];
  data_[current_index_ + 1] = data_[1];
  data_[current_index_ + 2] =
      is_last_fragment ? kApduP1LastBlock : kApduP1MoreBlocks;
  data_[current_index_ + 3] = current_fragment_++;
  if (is_extended_length_) {
    data_[current_index_ + 4] = 0;
    data_[current_index_ + 5] = static_cast<uint8_t>(current_size & 0xFF);
    data_[current_index_ + 6] = static_cast<uint8_t>(current_size >> 8);
  } else {
    data_[current_index_ + 4] = static_cast<uint8_t>(current_size);
  }
  size_t le_size = 0;
  // Last fragment is the only one that will potentially have an Le field, as we
  // do not expect any response data until we send the entire command.
  if (is_last_fragment && le_) {
    le_size = length_size;
    data_.reserve(data_.size() + length_size);
    if (is_extended_length_) {
      data_.push_back(0);
      data_.push_back(static_cast<uint8_t>(le_ & 0xFF));
      data_.push_back(static_cast<uint8_t>(le_ >> 8));
    } else {
      data_.push_back(static_cast<uint8_t>(le_));
    }
  }
  // Add APDU header and (potentially) Le to size.
  current_size += header_size + le_size;
  *fragment = &data_[current_index_];
  current_index_ += current_size;
  VLOG(2) << "APDU fragment #" << current_fragment_ - 1 << " (" << current_size
          << " bytes): " << base::HexEncode(*fragment, current_size);
  return current_size;
}

void CommandApdu::EnsureLcExists() {
  if (data_.size() == kHeaderSize) {
    if (is_extended_length_) {
      data_.push_back(0);
      data_.push_back(0);
      data_.push_back(0);
    } else {
      data_.push_back(0);
    }
  }
}

//////////////////////////
// ResponseApdu Methods //
//////////////////////////

void ResponseApdu::AddStatusBytes(uint8_t sw1, uint8_t sw2) {
  data_.insert(data_.end(), {sw1, sw2});
}

void ResponseApdu::AddData(const uint8_t* data, size_t data_len) {
  // If AddData is called over multiple fragments, remove status bytes from the
  // previous fragment
  VLOG(2) << __func__;
  if (data_.size() >= kNumStatusBytes)
    ReleaseStatusBytes();
  data_.insert(data_.end(), data, data + data_len);
}

std::vector<uint8_t> ResponseApdu::ReleaseStatusBytes() {
  VLOG(2) << __func__ << " data_.size:" << data_.size();
  if (data_.size() < kNumStatusBytes) {
    LOG(ERROR) << "Cannot release status bytes.";
    return {};
  }
  std::vector<uint8_t> status_bytes(data_.end() - kNumStatusBytes, data_.end());
  data_.erase(data_.end() - kNumStatusBytes, data_.end());
  return status_bytes;
}

std::vector<uint8_t> ResponseApdu::Release() {
  return std::move(data_);
}

CommandApdu ResponseApdu::CreateGetMoreCommand(bool use_extended_length,
                                               uint8_t cls) const {
  VLOG(2) << __func__;
  uint8_t sw2 = 0;
  if (data_.size() >= kNumStatusBytes) {
    sw2 = data_[data_.size() - 1];
  }
  return CommandApdu(cls, ApduInstruction::INS_GET_MORE_RESPONSE,
                     use_extended_length, sw2);
}

bool ResponseApdu::IsSuccessful() const {
  VLOG(2) << __func__;
  if (data_.size() >= kNumStatusBytes) {
    return data_[data_.size() - kNumStatusBytes] == STATUS_OK;
  }
  LOG(WARNING) << "Called IsSuccessful() on an empty ResponseApdu";
  return true;
}

bool ResponseApdu::WaitingForNextFragment() const {
  VLOG(2) << __func__;
  return (data_.empty() || data_.size() == kNumStatusBytes) && IsSuccessful();
}

bool ResponseApdu::MorePayloadIncoming() const {
  VLOG(2) << __func__;

  if (data_.size() >= kNumStatusBytes) {
    return data_[data_.size() - kNumStatusBytes] == STATUS_MORE_RESPONSE;
  }

  LOG(WARNING) << "Called MorePayloadIncoming() on an empty ResponseApdu";
  return false;
}

}  // namespace hermes
