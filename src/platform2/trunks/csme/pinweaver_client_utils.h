// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_CSME_PINWEAVER_CLIENT_UTILS_H_
#define TRUNKS_CSME_PINWEAVER_CLIENT_UTILS_H_

#include <string.h>
#include <string>

#include "trunks/csme/pinweaver_csme_types.h"

#include <base/logging.h>

// TODO(b/190621192): Support variable length request and response, and further
// refactor all the consumers into one single template.
namespace trunks {
namespace csme {

template <typename Type>
std::string SerializeToString(const Type& t) {
  const char* buffer = reinterpret_cast<const char*>(&t);
  return std::string(buffer, buffer + sizeof(t));
}

// Declared as inline to temporarily avoid duplicated definition.
inline bool CheckResponse(const pw_heci_header_req& req_header,
                          const pw_heci_header_res& resp_header) {
  if (req_header.pw_heci_seq != resp_header.pw_heci_seq) {
    LOG(ERROR) << __func__ << ": Mismatched sequence: expected "
               << req_header.pw_heci_seq << " got " << resp_header.pw_heci_seq;
    return false;
  }
  if (resp_header.pw_heci_rc) {
    LOG(ERROR) << __func__
               << ": CSME returns error: " << resp_header.pw_heci_rc;
    return false;
  }
  if (req_header.pw_heci_cmd != resp_header.pw_heci_cmd) {
    LOG(ERROR) << __func__ << ": Mismatched command: expected "
               << req_header.pw_heci_cmd << " got " << resp_header.pw_heci_cmd;
    return false;
  }
  return true;
}

// Implementation of deserialization of the packed data from CSME at recursion.
template <typename... OutputTypes>
class UnpackImpl;

// Unpacks the first data from the serialized payload, and invokes recursion.
template <typename FirstOutputType, typename... OutputTypes>
class UnpackImpl<FirstOutputType, OutputTypes...> {
 public:
  UnpackImpl() = default;
  bool Unpack(const std::string& serialized,
              FirstOutputType* first,
              OutputTypes*... outputs) {
    if (serialized.size() < sizeof(*first)) {
      LOG(ERROR) << __func__ << ": Serialized data too short; expected >= "
                 << sizeof(*first) << "; got " << serialized.size();
      return false;
    }
    memcpy(first, serialized.data(), sizeof(*first));
    return UnpackImpl<OutputTypes...>().Unpack(
        serialized.substr(sizeof(*first)), outputs...);
  }
};

// Unpacks the first data from the serialized payload, and invokes recursion.
#if 1
template <typename... OutputTypes>
class UnpackImpl<std::string, OutputTypes...> {
 public:
  UnpackImpl() = default;
  bool Unpack(const std::string& serialized,
              std::string* output_str,
              OutputTypes*... outputs) {
    // Report error as we don't have use case for empty string output.
    if (serialized.empty()) {
      LOG(ERROR) << __func__ << ": Expected empty string payload.";
      return false;
    }
    *output_str = serialized;
    // There isn't supposed to be any output parameters left; the recursive call
    // will verify.
    return UnpackImpl<OutputTypes...>().Unpack("", outputs...);
  }
};
#endif

// Special handling for cases that all the output data are unpacked.
template <>
class UnpackImpl<> {
 public:
  UnpackImpl() = default;
  bool Unpack(const std::string& serialized) {
    if (!serialized.empty()) {
      LOG(ERROR) << __func__ << ": Execessively long data; reminaing size="
                 << serialized.size();
      return false;
    }
    return true;
  }
};

// Deserializes the response from CSME, including the integrity check against
// the CSME command.
template <typename... OutputTypes>
bool UnpackFromResponse(const pw_heci_header_req& req_header,
                        const std::string& response,
                        OutputTypes*... outputs) {
  if (response.size() < sizeof(pw_heci_header_res)) {
    LOG(ERROR) << __func__ << ": response too short; size=" << response.size();
    return false;
  }
  const pw_heci_header_res* resp_header =
      reinterpret_cast<const pw_heci_header_res*>(response.data());

  if (!CheckResponse(req_header, *resp_header)) {
    LOG(ERROR) << __func__ << ": Failed to vlaidate response header.";
    return false;
  }

  const std::string serialized_outputs =
      response.substr(sizeof(pw_heci_header_res));
  if (resp_header->total_length != serialized_outputs.size()) {
    LOG(ERROR) << __func__ << ": Unexpected payload length; specified: "
               << resp_header->total_length << " actual "
               << serialized_outputs.size();
    return false;
  }
  if (!UnpackImpl<OutputTypes...>().Unpack(serialized_outputs, outputs...)) {
    LOG(ERROR) << __func__ << ": Unpacking error.";
    return false;
  }
  return true;
}

template <typename Type>
void BuildFixedSizedRequest(int cmd, int seq, Type* req) {
  req->header.pw_heci_cmd = cmd;
  req->header.pw_heci_seq = seq;
  req->header.total_length = sizeof(Type) - sizeof(req->header);
}

}  // namespace csme
}  // namespace trunks

#endif  // TRUNKS_CSME_PINWEAVER_CLIENT_UTILS_H_
