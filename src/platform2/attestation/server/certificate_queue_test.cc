// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "attestation/server/certificate_queue.h"

#include <string>

#include <base/functional/callback_helpers.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "attestation/common/attestation_interface.h"
#include "attestation/server/attestation_flow.h"

namespace attestation {

namespace {

using ::testing::ElementsAreArray;

constexpr size_t kAliasLimit = 10;
constexpr char kUsername1[] = "user1";
constexpr char kUsername2[] = "user2";
constexpr char kKeyLabel1[] = "label1";
constexpr char kKeyLabel2[] = "label2";

// Makes an |AttestationFlowData| with |request| and a callback.
std::shared_ptr<AttestationFlowData> MakeAttestationFlowData(
    const GetCertificateRequest& request) {
  return std::make_shared<AttestationFlowData>(request, base::DoNothing());
}

// Makes a |GetCertificateRequest| with |username| and |key_label|, and makes an
// |AttestationFlowData| with it and a callback.
std::shared_ptr<AttestationFlowData> MakeAttestationFlowData(
    ACAType aca_type,
    const std::string& username,
    const std::string& key_label) {
  GetCertificateRequest request;
  request.set_aca_type(aca_type);
  request.set_username(username);
  request.set_key_label(key_label);
  return std::make_shared<AttestationFlowData>(request, base::DoNothing());
}

std::shared_ptr<AttestationFlowData> MakeAttestationFlowDataForTesting() {
  return MakeAttestationFlowData(DEFAULT_ACA, "", "");
}

}  // namespace

TEST(CertificateQueueTest, PushSuccessUntilLimitPerAlias) {
  CertificateQueue certificate_queue(kAliasLimit);
  std::vector<std::shared_ptr<AttestationFlowData>> entries;

  // For each combination of aca type, username, and key_label, the size of the
  // queue should be independently up to |kAliasLimit|.
  for (ACAType aca_type : {DEFAULT_ACA, TEST_ACA}) {
    for (const char* username : {kUsername1, kUsername2}) {
      for (const char* key_label : {kKeyLabel1, kKeyLabel2}) {
        std::vector<std::shared_ptr<AttestationFlowData>> entries;
        for (int i = 0; i < kAliasLimit; ++i) {
          EXPECT_EQ(certificate_queue.Push(
                        MakeAttestationFlowData(aca_type, username, key_label)),
                    CertificateQueue::PushResult::kSuccess);
        }
        // Up to the limit, the push operation should fail.
        EXPECT_EQ(certificate_queue.Push(
                      MakeAttestationFlowData(aca_type, username, key_label)),
                  CertificateQueue::PushResult::kAliasLimit);
      }
    }
  }
}

TEST(CertificateQueueTest, ConsistentInputOutput) {
  CertificateQueue certificate_queue(kAliasLimit);
  std::vector<std::shared_ptr<AttestationFlowData>> entries;
  for (int i = 0; i < kAliasLimit; ++i) {
    entries.push_back(MakeAttestationFlowDataForTesting());
    EXPECT_EQ(certificate_queue.Push(entries.back()),
              CertificateQueue::PushResult::kSuccess);
  }
  // This should be |true| if the queue is not empty.
  EXPECT_TRUE(
      certificate_queue.HasAnyAlias(MakeAttestationFlowDataForTesting()));

  // Popped items should match the entries we push into the queue.
  EXPECT_THAT(
      certificate_queue.PopAllAliases(MakeAttestationFlowDataForTesting()),
      ElementsAreArray(entries));
  // Makes sure after popping the entries, the queue is empty.
  EXPECT_TRUE(
      certificate_queue.PopAllAliases(MakeAttestationFlowDataForTesting())
          .empty());
  // And this should be |false| if the queue is empty.
  EXPECT_FALSE(
      certificate_queue.HasAnyAlias(MakeAttestationFlowDataForTesting()));
}

TEST(CertificateQueueTest, InconsistentConfig) {
  CertificateQueue certificate_queue(kAliasLimit);
  auto first_entry = MakeAttestationFlowDataForTesting();
  EXPECT_EQ(certificate_queue.Push(first_entry),
            CertificateQueue::PushResult::kSuccess);
  GetCertificateRequest inconsistent_request;

  inconsistent_request = first_entry->get_certificate_request();
  inconsistent_request.set_certificate_profile(XTS_CERTIFICATE);
  EXPECT_EQ(
      certificate_queue.Push(MakeAttestationFlowData(inconsistent_request)),
      CertificateQueue::PushResult::kInconsistentConfig);

  inconsistent_request = first_entry->get_certificate_request();
  inconsistent_request.set_request_origin("inconsistent origin");
  EXPECT_EQ(
      certificate_queue.Push(MakeAttestationFlowData(inconsistent_request)),
      CertificateQueue::PushResult::kInconsistentConfig);

  inconsistent_request = first_entry->get_certificate_request();
  inconsistent_request.set_key_type(KEY_TYPE_ECC);
  ASSERT_NE(first_entry->get_certificate_request().key_type(),
            inconsistent_request.key_type());
  EXPECT_EQ(
      certificate_queue.Push(MakeAttestationFlowData(inconsistent_request)),
      CertificateQueue::PushResult::kInconsistentConfig);
}

}  // namespace attestation
