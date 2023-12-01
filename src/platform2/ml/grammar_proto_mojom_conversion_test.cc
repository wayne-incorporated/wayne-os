// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>
#include <string>

#include "ml/grammar_proto_mojom_conversion.h"

namespace ml {
namespace {

using ::chromeos::machine_learning::mojom::GrammarCheckerQueryPtr;

// Tests that proto->mojom->proto->mojom returns the same result as expected.
TEST(GrammarProtoMojomConversionTest, RequestProtoToQuery) {
  chrome_knowledge::GrammarCheckerRequest proto;
  proto.set_text("random test message.");
  proto.set_language("en-US");

  const GrammarCheckerQueryPtr query =
      GrammarCheckerQueryFromProtoForTesting(proto);

  const chrome_knowledge::GrammarCheckerRequest proto_constructed =
      GrammarCheckerQueryToProto(GrammarCheckerQueryFromProtoForTesting(proto));

  const GrammarCheckerQueryPtr query_constructed =
      GrammarCheckerQueryFromProtoForTesting(proto_constructed);

  EXPECT_TRUE(query.Equals(query_constructed));
  EXPECT_EQ(proto.SerializeAsString(), proto_constructed.SerializeAsString());
}

}  // namespace
}  // namespace ml
