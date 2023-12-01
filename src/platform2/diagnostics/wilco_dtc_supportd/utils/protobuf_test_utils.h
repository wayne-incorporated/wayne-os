// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_WILCO_DTC_SUPPORTD_UTILS_PROTOBUF_TEST_UTILS_H_
#define DIAGNOSTICS_WILCO_DTC_SUPPORTD_UTILS_PROTOBUF_TEST_UTILS_H_

#include <string>
#include <vector>

#include <base/strings/string_util.h>
#include <google/protobuf/util/message_differencer.h>

namespace diagnostics {
namespace wilco {

// gmock matcher for protobufs, allowing to check protobuf arguments in mocks
// and test assertions.
MATCHER_P(ProtobufEquals,
          expected_message,
          "equals to {" + expected_message.ShortDebugString() + "}") {
  return google::protobuf::util::MessageDifferencer::Equals(arg,
                                                            expected_message);
}

// Given a range of protobuf messages, returns the human-readable representation
// of it (using protobuf::Message::ShortDebugString()).
template <typename Iterator>
inline std::string GetProtosRangeDebugString(Iterator protos_begin,
                                             Iterator protos_end) {
  std::vector<std::string> formatted_items;
  for (auto iterator = protos_begin; iterator != protos_end; ++iterator)
    formatted_items.push_back("{" + iterator->ShortDebugString() + "}");
  return "[" + base::JoinString(formatted_items, ", ") + "]";
}

}  // namespace wilco
}  // namespace diagnostics

#endif  // DIAGNOSTICS_WILCO_DTC_SUPPORTD_UTILS_PROTOBUF_TEST_UTILS_H_
