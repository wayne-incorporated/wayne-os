// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/keymaster/context/crypto_operation.h"

#include <optional>

#include <gtest/gtest.h>

namespace arc {
namespace keymaster {
namespace context {

namespace {

const auto kMechanismA = MechanismDescription(OperationType::kSign,
                                              Algorithm::kRsa,
                                              Digest::kSha256,
                                              Padding::kPkcs7,
                                              BlockMode::kNone);

const auto kMechanismB = MechanismDescription(OperationType::kUnsupported,
                                              Algorithm::kRsa,
                                              Digest::kSha256,
                                              Padding::kPkcs7,
                                              BlockMode::kNone);

const auto kMechanismC = MechanismDescription(OperationType::kSign,
                                              Algorithm::kUnsupported,
                                              Digest::kSha256,
                                              Padding::kPkcs7,
                                              BlockMode::kNone);

// Concrete implementation of |CryptoOperation| for tests.
class TestOperation : public CryptoOperation {
 public:
  TestOperation() = default;
  ~TestOperation() = default;
  // Not copyable nor assignable.
  TestOperation(const TestOperation&) = delete;
  TestOperation& operator=(const TestOperation&) = delete;

  std::optional<uint64_t> Begin(MechanismDescription description) {
    return std::nullopt;
  }

  std::optional<brillo::Blob> Update(const brillo::Blob& input) {
    return std::nullopt;
  }

  std::optional<brillo::Blob> Finish() { return std::nullopt; }

  bool Abort() { return false; }

  bool IsSupportedMechanism(MechanismDescription description) const {
    return kMechanismA == description || kMechanismB == description;
  }
};

}  // anonymous namespace

TEST(CryptoOperation, IsSupportedMechanism) {
  TestOperation operation;
  EXPECT_TRUE(operation.IsSupportedMechanism(kMechanismA));

  EXPECT_TRUE(operation.IsSupportedMechanism(kMechanismB));

  EXPECT_FALSE(operation.IsSupportedMechanism(kMechanismC));
}

TEST(MechanismDescription, EqualsOperator) {
  EXPECT_EQ(kMechanismA, kMechanismA);

  MechanismDescription copyOfA(kMechanismA);
  EXPECT_EQ(kMechanismA, copyOfA);

  EXPECT_FALSE(kMechanismA == kMechanismC);
  EXPECT_FALSE(kMechanismB == kMechanismC);
  EXPECT_FALSE(copyOfA == kMechanismC);
}

TEST(MechanismDescription, LessOperator) {
  EXPECT_LT(kMechanismA, kMechanismB);
  EXPECT_LT(kMechanismA, kMechanismC);
  EXPECT_LT(kMechanismB, kMechanismC);
}

}  // namespace context
}  // namespace keymaster
}  // namespace arc
