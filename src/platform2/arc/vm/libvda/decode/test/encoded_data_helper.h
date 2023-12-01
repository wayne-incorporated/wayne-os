// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_VM_LIBVDA_DECODE_TEST_ENCODED_DATA_HELPER_H_
#define ARC_VM_LIBVDA_DECODE_TEST_ENCODED_DATA_HELPER_H_

#include <stdint.h>

#include <string>
#include <vector>

#include "arc/vm/libvda/libvda_decode.h"

// This class is forked from Chromium's VDA testing helpers. See
// src/media/gpu/test/video_decode_accelerator_unittest_helpers.h.
class EncodedDataHelper {
 public:
  EncodedDataHelper(const std::string& encoded_data, vda_profile_t profile);
  EncodedDataHelper(const std::vector<uint8_t>& stream, vda_profile_t profile);
  EncodedDataHelper(const EncodedDataHelper&) = delete;
  EncodedDataHelper& operator=(const EncodedDataHelper&) = delete;

  // Compute and return the next fragment to be sent to the decoder, starting
  // from the current position in the stream, and advance the current position
  // to after the returned fragment.
  std::string GetBytesForNextData();

  void Rewind() { next_pos_to_decode_ = 0; }
  bool AtHeadOfStream() const { return next_pos_to_decode_ == 0; }
  bool ReachEndOfStream() const { return next_pos_to_decode_ == data_.size(); }

  size_t num_skipped_fragments() { return num_skipped_fragments_; }

 private:
  // For h.264.
  std::string GetBytesForNextFragment();
  // For VP8/9.
  std::string GetBytesForNextFrame();

  // Helpers for GetBytesForNextFragment above.
  size_t GetBytesForNextNALU(size_t pos);
  bool IsNALHeader(const std::string& data, size_t pos);
  bool LookForSPS(size_t* skipped_fragments_count);

  std::string data_;
  vda_profile_t profile_;
  size_t next_pos_to_decode_ = 0;
  size_t num_skipped_fragments_ = 0;
};

#endif  // ARC_VM_LIBVDA_DECODE_TEST_ENCODED_DATA_HELPER_H_
