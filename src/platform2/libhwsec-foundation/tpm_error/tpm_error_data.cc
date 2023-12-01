// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec-foundation/tpm_error/tpm_error_data.h"

#if defined(__cplusplus)

#include <arpa/inet.h>

#include <string>

#include <crypto/sha2.h>

namespace {

std::string TpmDataToString(const std::vector<struct TpmErrorData>& data_set) {
  std::vector<uint32_t> flatten_data;
  for (auto& data : data_set) {
    flatten_data.push_back(htonl(data.command));
    flatten_data.push_back(htonl(data.response));
  }
  const int data_size = flatten_data.size() * sizeof(uint32_t);
  const char* data_ptr = reinterpret_cast<const char*>(flatten_data.data());
  return std::string(data_ptr, data_size);
}

}  // namespace

bool operator==(const struct TpmErrorData& a, const struct TpmErrorData& b) {
  return a.command == b.command && a.response == b.response;
}

bool operator<(const struct TpmErrorData& a, const struct TpmErrorData& b) {
  return a.command < b.command ? true : a.response < b.response;
}

uint32_t GetHashFromTpmDataSet(
    const std::vector<struct TpmErrorData>& data_set) {
  const std::string data_string = TpmDataToString(data_set);
  uint32_t hash;
  crypto::SHA256HashString(data_string, reinterpret_cast<uint8_t*>(&hash),
                           sizeof(hash));
  return hash;
}

#endif  // defined(__cplusplus)
