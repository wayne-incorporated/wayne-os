// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/pending_activation_store.h"

#include <utility>

#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

#include "shill/store/fake_store.h"

namespace {
const int kInvalid = -1;
// Invalid enum value other than -1
const int kUninitialized = -2;
}  // namespace

namespace shill {

class PendingActivationStoreTest : public ::testing::Test {
 public:
  PendingActivationStoreTest() = default;
  ~PendingActivationStoreTest() override = default;

  void SetUp() override {
    auto storage = std::make_unique<FakeStore>();
    storage_ = storage.get();
    store_.storage_ = std::move(storage);
  }

 protected:
  PendingActivationStore store_;
  FakeStore* storage_ = nullptr;
};

TEST_F(PendingActivationStoreTest, FileInteractions) {
  const char kEntry1[] = "1234";
  const char kEntry2[] = "4321";

  base::ScopedTempDir temp_dir;
  EXPECT_TRUE(temp_dir.CreateUniqueTempDir());

  EXPECT_TRUE(store_.InitStorage(temp_dir.GetPath()));

  EXPECT_EQ(PendingActivationStore::kStateUnknown,
            store_.GetActivationState(PendingActivationStore::kIdentifierICCID,
                                      kEntry1));
  EXPECT_EQ(PendingActivationStore::kStateUnknown,
            store_.GetActivationState(PendingActivationStore::kIdentifierICCID,
                                      kEntry2));
  EXPECT_EQ(PendingActivationStore::kStateUnknown,
            store_.GetActivationState(PendingActivationStore::kIdentifierMEID,
                                      kEntry1));
  EXPECT_EQ(PendingActivationStore::kStateUnknown,
            store_.GetActivationState(PendingActivationStore::kIdentifierMEID,
                                      kEntry2));

  EXPECT_TRUE(store_.SetActivationState(
      PendingActivationStore::kIdentifierICCID, kEntry1,
      PendingActivationStore::kStatePending));
  EXPECT_TRUE(store_.SetActivationState(
      PendingActivationStore::kIdentifierICCID, kEntry2,
      PendingActivationStore::kStateActivated));

  EXPECT_EQ(PendingActivationStore::kStatePending,
            store_.GetActivationState(PendingActivationStore::kIdentifierICCID,
                                      kEntry1));
  EXPECT_EQ(PendingActivationStore::kStateActivated,
            store_.GetActivationState(PendingActivationStore::kIdentifierICCID,
                                      kEntry2));
  EXPECT_EQ(PendingActivationStore::kStateUnknown,
            store_.GetActivationState(PendingActivationStore::kIdentifierMEID,
                                      kEntry1));
  EXPECT_EQ(PendingActivationStore::kStateUnknown,
            store_.GetActivationState(PendingActivationStore::kIdentifierMEID,
                                      kEntry2));

  EXPECT_TRUE(store_.SetActivationState(
      PendingActivationStore::kIdentifierMEID, kEntry1,
      PendingActivationStore::kStateActivated));

  EXPECT_EQ(PendingActivationStore::kStatePending,
            store_.GetActivationState(PendingActivationStore::kIdentifierICCID,
                                      kEntry1));
  EXPECT_EQ(PendingActivationStore::kStateActivated,
            store_.GetActivationState(PendingActivationStore::kIdentifierICCID,
                                      kEntry2));
  EXPECT_EQ(PendingActivationStore::kStateActivated,
            store_.GetActivationState(PendingActivationStore::kIdentifierMEID,
                                      kEntry1));

  EXPECT_TRUE(store_.SetActivationState(
      PendingActivationStore::kIdentifierICCID, kEntry1,
      PendingActivationStore::kStateActivated));
  EXPECT_TRUE(store_.SetActivationState(
      PendingActivationStore::kIdentifierICCID, kEntry2,
      PendingActivationStore::kStatePending));

  EXPECT_EQ(PendingActivationStore::kStateActivated,
            store_.GetActivationState(PendingActivationStore::kIdentifierICCID,
                                      kEntry1));
  EXPECT_EQ(PendingActivationStore::kStatePending,
            store_.GetActivationState(PendingActivationStore::kIdentifierICCID,
                                      kEntry2));

  // Close and reopen the file to verify that the entries persisted.
  EXPECT_TRUE(store_.InitStorage(temp_dir.GetPath()));

  EXPECT_EQ(PendingActivationStore::kStateActivated,
            store_.GetActivationState(PendingActivationStore::kIdentifierICCID,
                                      kEntry1));
  EXPECT_EQ(PendingActivationStore::kStatePending,
            store_.GetActivationState(PendingActivationStore::kIdentifierICCID,
                                      kEntry2));
  EXPECT_EQ(PendingActivationStore::kStateActivated,
            store_.GetActivationState(PendingActivationStore::kIdentifierMEID,
                                      kEntry1));

  EXPECT_TRUE(
      store_.RemoveEntry(PendingActivationStore::kIdentifierMEID, kEntry1));
  EXPECT_TRUE(
      store_.RemoveEntry(PendingActivationStore::kIdentifierICCID, kEntry2));

  EXPECT_EQ(PendingActivationStore::kStateUnknown,
            store_.GetActivationState(PendingActivationStore::kIdentifierMEID,
                                      kEntry1));
  EXPECT_EQ(PendingActivationStore::kStateUnknown,
            store_.GetActivationState(PendingActivationStore::kIdentifierICCID,
                                      kEntry2));
  EXPECT_EQ(PendingActivationStore::kStateActivated,
            store_.GetActivationState(PendingActivationStore::kIdentifierICCID,
                                      kEntry1));

  EXPECT_TRUE(
      store_.RemoveEntry(PendingActivationStore::kIdentifierICCID, kEntry1));
  EXPECT_FALSE(
      store_.RemoveEntry(PendingActivationStore::kIdentifierMEID, kEntry2));
  EXPECT_EQ(PendingActivationStore::kStateUnknown,
            store_.GetActivationState(PendingActivationStore::kIdentifierICCID,
                                      kEntry1));
  EXPECT_EQ(PendingActivationStore::kStateUnknown,
            store_.GetActivationState(PendingActivationStore::kIdentifierMEID,
                                      kEntry2));

  EXPECT_TRUE(store_.InitStorage(temp_dir.GetPath()));

  EXPECT_EQ(PendingActivationStore::kStateUnknown,
            store_.GetActivationState(PendingActivationStore::kIdentifierMEID,
                                      kEntry1));
  EXPECT_EQ(PendingActivationStore::kStateUnknown,
            store_.GetActivationState(PendingActivationStore::kIdentifierICCID,
                                      kEntry2));
  EXPECT_EQ(PendingActivationStore::kStateUnknown,
            store_.GetActivationState(PendingActivationStore::kIdentifierICCID,
                                      kEntry1));
  EXPECT_EQ(PendingActivationStore::kStateUnknown,
            store_.GetActivationState(PendingActivationStore::kIdentifierMEID,
                                      kEntry2));
}

TEST_F(PendingActivationStoreTest, GetActivationState) {
  const char kEntry[] = "12345689";

  // Value not found
  EXPECT_EQ(PendingActivationStore::kStateUnknown,
            store_.GetActivationState(PendingActivationStore::kIdentifierICCID,
                                      kEntry));

  // File contains invalid entry
  storage_->SetInt(PendingActivationStore::kMeidGroupId, kEntry,
                   PendingActivationStore::kStateMax);
  EXPECT_EQ(PendingActivationStore::kStateUnknown,
            store_.GetActivationState(PendingActivationStore::kIdentifierMEID,
                                      kEntry));

  storage_->SetInt(PendingActivationStore::kMeidGroupId, kEntry, 0);
  EXPECT_EQ(PendingActivationStore::kStateUnknown,
            store_.GetActivationState(PendingActivationStore::kIdentifierMEID,
                                      kEntry));

  // All enum values
  storage_->SetInt(PendingActivationStore::kIccidGroupId, kEntry, 1);
  EXPECT_EQ(PendingActivationStore::kStatePending,
            store_.GetActivationState(PendingActivationStore::kIdentifierICCID,
                                      kEntry));
  storage_->SetInt(PendingActivationStore::kIccidGroupId, kEntry, 2);
  EXPECT_EQ(PendingActivationStore::kStateActivated,
            store_.GetActivationState(PendingActivationStore::kIdentifierICCID,
                                      kEntry));
}

TEST_F(PendingActivationStoreTest, SetActivationState) {
  const char kEntry[] = "12345689";

  EXPECT_FALSE(
      store_.SetActivationState(PendingActivationStore::kIdentifierICCID,
                                kEntry, PendingActivationStore::kStateUnknown));

  storage_->set_writes_fail(true);
  EXPECT_FALSE(
      store_.SetActivationState(PendingActivationStore::kIdentifierICCID,
                                kEntry, PendingActivationStore::kStatePending));
  storage_->set_writes_fail(false);

  EXPECT_FALSE(store_.SetActivationState(
      PendingActivationStore::kIdentifierICCID, kEntry,
      static_cast<PendingActivationStore::State>(kInvalid)));

  int activation_state = kUninitialized;
  storage_->SetInt(PendingActivationStore::kIccidGroupId, kEntry, kInvalid);

  EXPECT_FALSE(
      store_.SetActivationState(PendingActivationStore::kIdentifierICCID,
                                kEntry, PendingActivationStore::kStateMax));
  EXPECT_TRUE(storage_->GetInt(PendingActivationStore::kIccidGroupId, kEntry,
                               &activation_state));
  EXPECT_EQ(activation_state, kInvalid);

  EXPECT_FALSE(
      store_.SetActivationState(PendingActivationStore::kIdentifierICCID,
                                kEntry, PendingActivationStore::kStateUnknown));
  EXPECT_TRUE(storage_->GetInt(PendingActivationStore::kIccidGroupId, kEntry,
                               &activation_state));
  EXPECT_EQ(activation_state, kInvalid);

  EXPECT_TRUE(
      store_.SetActivationState(PendingActivationStore::kIdentifierICCID,
                                kEntry, PendingActivationStore::kStatePending));
  EXPECT_TRUE(storage_->GetInt(PendingActivationStore::kIccidGroupId, kEntry,
                               &activation_state));
  EXPECT_EQ(activation_state, PendingActivationStore::kStatePending);

  EXPECT_TRUE(store_.SetActivationState(
      PendingActivationStore::kIdentifierICCID, kEntry,
      PendingActivationStore::kStateActivated));
  EXPECT_TRUE(storage_->GetInt(PendingActivationStore::kIccidGroupId, kEntry,
                               &activation_state));
  EXPECT_EQ(activation_state, PendingActivationStore::kStateActivated);
}

TEST_F(PendingActivationStoreTest, RemoveEntry) {
  const char kEntry[] = "12345689";

  EXPECT_FALSE(
      store_.RemoveEntry(PendingActivationStore::kIdentifierICCID, kEntry));

  storage_->SetInt(PendingActivationStore::kIccidGroupId, kEntry, 0);
  EXPECT_TRUE(
      store_.RemoveEntry(PendingActivationStore::kIdentifierICCID, kEntry));
  int activation_state = kUninitialized;
  EXPECT_FALSE(storage_->GetInt(PendingActivationStore::kIccidGroupId, kEntry,
                                &activation_state));
  EXPECT_EQ(activation_state, kUninitialized);
}

}  // namespace shill
