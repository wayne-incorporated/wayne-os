// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/keymaster/context/cros_key.h"

#include <gtest/gtest.h>
#include <utility>
#include "keymaster/authorization_set.h"
#include "keymaster/operation.h"

namespace arc {
namespace keymaster {
namespace context {

namespace {

constexpr char kId[] = "some_id";
constexpr char kLabel[] = "some_label";

// Concrete implementation of |CrosKey| for tests.
class TestKey : public CrosKey {
 public:
  TestKey(::keymaster::AuthorizationSet&& hw_enforced,
          ::keymaster::AuthorizationSet&& sw_enforced,
          const CrosKeyFactory* key_factory,
          KeyData&& key_data)
      : CrosKey(std::move(hw_enforced),
                std::move(sw_enforced),
                key_factory,
                std::move(key_data)) {}

  ~TestKey() override = default;
  // Not copyable nor assignable.
  TestKey(const TestKey&) = delete;
  TestKey& operator=(const TestKey&) = delete;

  keymaster_error_t formatted_key_material(
      keymaster_key_format_t /* format */,
      ::keymaster::UniquePtr<uint8_t[]>* /* material */,
      size_t* /* size */) const override {
    return KM_ERROR_UNSUPPORTED_KEY_FORMAT;
  }
};

}  // anonymous namespace

TEST(CrosKeyFactory, SimpleInteraction) {
  CrosKeyFactory factory(/*context_adaptor=*/nullptr, KM_ALGORITHM_RSA);
  ::keymaster::OperationFactory* operation_factory =
      factory.GetOperationFactory(KM_PURPOSE_SIGN);
  ASSERT_TRUE(operation_factory);
}

TEST(CrosKey, SimpleInteraction) {
  CrosKeyFactory factory(/*context_adaptor=*/nullptr, KM_ALGORITHM_RSA);
  ::keymaster::AuthorizationSet hw_enforced, sw_enforced;
  KeyData data;

  TestKey key(std::move(hw_enforced), std::move(sw_enforced), &factory,
              std::move(data));
  ASSERT_EQ(key.cros_key_factory(), &factory);
}

TEST(ChapsKey, SimpleInteraction) {
  CrosKeyFactory factory(/*context_adaptor=*/nullptr, KM_ALGORITHM_RSA);
  ::keymaster::AuthorizationSet hw_enforced, sw_enforced;
  KeyData data;
  data.mutable_chaps_key()->set_id(kId);
  data.mutable_chaps_key()->set_label(kLabel);
  brillo::Blob id_blob(kId, kId + strlen(kId));

  ChapsKey key(std::move(hw_enforced), std::move(sw_enforced), &factory,
               std::move(data));
  EXPECT_EQ(key.cros_key_factory(), &factory);
  EXPECT_EQ(key.id(), id_blob);
  EXPECT_EQ(key.label(), kLabel);
}

TEST(CrosOperationFactory, SimpleInteraction) {
  CrosOperationFactory factory(KM_ALGORITHM_RSA, KM_PURPOSE_SIGN);
  ::keymaster::OperationFactory::KeyType type = factory.registry_key();
  ASSERT_EQ(type.algorithm, KM_ALGORITHM_RSA);
  ASSERT_EQ(type.purpose, KM_PURPOSE_SIGN);
}

TEST(CrosOperation, SimpleInteraction) {
  CrosKeyFactory keyFactory(/*context_adaptor=*/nullptr, KM_ALGORITHM_RSA);
  ::keymaster::AuthorizationSet hw_enforced, sw_enforced, begin_params;
  KeyData data;
  data.mutable_chaps_key()->set_label(kLabel);
  data.mutable_chaps_key()->set_id(kId);
  ChapsKey key(std::move(hw_enforced), std::move(sw_enforced), &keyFactory,
               std::move(data));

  CrosOperation operation(KM_PURPOSE_SIGN, std::move(key));
  ASSERT_EQ(operation.purpose(), KM_PURPOSE_SIGN);
}

}  // namespace context
}  // namespace keymaster
}  // namespace arc
