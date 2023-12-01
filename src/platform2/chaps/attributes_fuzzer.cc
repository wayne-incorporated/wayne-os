// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/logging.h>
#include <libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h>

#include "chaps/attributes.h"
#include "chaps/proto_bindings/attributes.pb.h"

class Environment {
 public:
  Environment() {
    // Disable logging.
    logging::SetMinLogLevel(logging::LOGGING_FATAL);
  }
};

DEFINE_PROTO_FUZZER(const chaps::AttributeList& input) {
  static Environment env;

  // This creates a fuzzed protobuf that we then attempt to parse, and if the
  // parse does succeed then we test serializing that back out w/ the fuzzed
  // data.
  chaps::Attributes attributes;
  std::string attribute_string = input.SerializeAsString();
  std::vector<uint8_t> attribute_data(attribute_string.begin(),
                                      attribute_string.end());
  if (!attributes.Parse(attribute_data))
    return;

  std::vector<uint8_t> serialized_data;
  attributes.Serialize(&serialized_data);

  // Since ParseAndFill requires that the newly-parsed data matches the size
  // of the existing data exactly, we can reuse the input to fuzz that logic.
  //
  // If this fails but Parse() succeeds, something's very fishy.
  if (!attributes.ParseAndFill(attribute_data))
    LOG(FATAL) << "Parse'able data can't be used with ParseAndFill?";

  serialized_data.clear();
  attributes.Serialize(&serialized_data);
}
