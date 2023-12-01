// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/backends/real_tpm_handle_manager.h"

#include <memory>
#include <string>
#include <utility>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <trunks/mock_response_serializer.h>
#include <trunks/mock_tpm.h>
#include <trunks/mock_tpm_utility.h>
#include <trunks/tpm_generated.h>
#include <trunks/trunks_factory_for_test.h>

#include <base/logging.h>

#include "vtpm/backends/fake_blob.h"
#include "vtpm/backends/mock_nv_space_manager.h"
#include "vtpm/backends/scoped_host_key_handle.h"

namespace vtpm {

namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::ElementsAre;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::StrictMock;
using ::testing::UnorderedElementsAreArray;

constexpr trunks::TPM_HANDLE kFakeHandle1 = trunks::PERSISTENT_FIRST + 10;
constexpr trunks::TPM_HANDLE kFakeHandle2 = trunks::PERSISTENT_FIRST + 100;
constexpr trunks::TPM_HANDLE kFakeHandle3 = trunks::PERSISTENT_FIRST + 1000;
constexpr char kFakeBlob1[] = "blob1";
constexpr char kFakeBlob2[] = "blob2";
constexpr char kFakeBlob3[] = "blob3";

static_assert(kFakeHandle1 < kFakeHandle2, "");
static_assert(kFakeHandle2 < kFakeHandle3, "");

}  // namespace

class RealTpmHandleManagerTest : public testing::Test {
 public:
  void SetUp() override {
    std::map<trunks::TPM_HANDLE, Blob*> table{
        {kFakeHandle1, &mock_blob_1_},
        {kFakeHandle2, &mock_blob_2_},
        {kFakeHandle3, &mock_blob_3_},
    };
    manager_ = std::make_unique<RealTpmHandleManager>(
        &trunks_factory_, &mock_nv_space_manager_, table);

    trunks_factory_.set_tpm_utility(&mock_tpm_utility_);
    trunks_factory_.set_tpm(&mock_tpm_);
    SetDefaultLoadFlushBehavior();
  }
  void TearDown() override {
    // Make sure no memory leak in any case.
    EXPECT_EQ(flushed_host_handles_.size(), loaded_host_handles_.size());
    EXPECT_THAT(flushed_host_handles_,
                UnorderedElementsAreArray(loaded_host_handles_));
  }

 protected:
  trunks::TPM_RC FakeLoadKey(const std::string& /*key_blob*/,
                             trunks::AuthorizationDelegate* /*delegate*/,
                             trunks::TPM_HANDLE* key_handle) {
    *key_handle = trunks::TRANSIENT_FIRST + loaded_host_handles_.size();
    loaded_host_handles_.push_back(*key_handle);
    return trunks::TPM_RC_SUCCESS;
  }
  trunks::TPM_RC FakeFlushKey(
      trunks::TPM_HANDLE key_handle,
      trunks::AuthorizationDelegate* /*authorization_delegate*/) {
    flushed_host_handles_.push_back(key_handle);
    return trunks::TPM_RC_SUCCESS;
  }
  void SetDefaultLoadFlushBehavior() {
    ON_CALL(mock_tpm_utility_, LoadKey(_, _, _))
        .WillByDefault(Invoke(this, &RealTpmHandleManagerTest::FakeLoadKey));
    ON_CALL(mock_tpm_, FlushContextSync(_, _))
        .WillByDefault(Invoke(this, &RealTpmHandleManagerTest::FakeFlushKey));
  }

  std::vector<trunks::TPM_HANDLE> loaded_host_handles_;
  std::vector<trunks::TPM_HANDLE> flushed_host_handles_;

  StrictMock<FakeBlob> mock_blob_1_{kFakeBlob1};
  StrictMock<FakeBlob> mock_blob_2_{kFakeBlob2};
  StrictMock<FakeBlob> mock_blob_3_{kFakeBlob3};
  trunks::TrunksFactoryForTest trunks_factory_;
  trunks::MockTpmUtility mock_tpm_utility_;
  trunks::MockTpm mock_tpm_;
  MockNvSpaceManager mock_nv_space_manager_;
  std::unique_ptr<RealTpmHandleManager> manager_;
};

namespace {

TEST_F(RealTpmHandleManagerTest, IsHandleTypeSuppoerted) {
  EXPECT_TRUE(manager_->IsHandleTypeSuppoerted(trunks::PERSISTENT_FIRST));
  EXPECT_TRUE(manager_->IsHandleTypeSuppoerted(trunks::PERSISTENT_FIRST + 1));
  EXPECT_TRUE(manager_->IsHandleTypeSuppoerted(trunks::TRANSIENT_FIRST));
  EXPECT_TRUE(manager_->IsHandleTypeSuppoerted(trunks::PERMANENT_FIRST));
  EXPECT_TRUE(manager_->IsHandleTypeSuppoerted(trunks::POLICY_SESSION_FIRST));
  EXPECT_TRUE(manager_->IsHandleTypeSuppoerted(trunks::NV_INDEX_FIRST));
  EXPECT_FALSE(manager_->IsHandleTypeSuppoerted(trunks::PCR_FIRST));
}

TEST_F(RealTpmHandleManagerTest, GetHandleListPersistentHandles) {
  EXPECT_CALL(mock_blob_1_, Get(_));
  EXPECT_CALL(mock_blob_2_, Get(_));
  EXPECT_CALL(mock_blob_3_, Get(_));
  std::vector<trunks::TPM_HANDLE> found_handles;
  EXPECT_EQ(manager_->GetHandleList(trunks::PERSISTENT_FIRST, &found_handles),
            trunks::TPM_RC_SUCCESS);
  EXPECT_THAT(found_handles,
              ElementsAre(kFakeHandle1, kFakeHandle2, kFakeHandle3));
}

TEST_F(RealTpmHandleManagerTest, GetHandleListPersistentHandlesSkipFirst) {
  EXPECT_CALL(mock_blob_2_, Get(_));
  EXPECT_CALL(mock_blob_3_, Get(_));
  std::vector<trunks::TPM_HANDLE> found_handles;
  EXPECT_EQ(manager_->GetHandleList(kFakeHandle1 + 1, &found_handles),
            trunks::TPM_RC_SUCCESS);
  EXPECT_THAT(found_handles, ElementsAre(kFakeHandle2, kFakeHandle3));
}

TEST_F(RealTpmHandleManagerTest, GetHandleListPersistentHandlesEmpty) {
  std::vector<trunks::TPM_HANDLE> found_handles;
  EXPECT_EQ(manager_->GetHandleList(kFakeHandle3 + 1, &found_handles),
            trunks::TPM_RC_SUCCESS);
  EXPECT_TRUE(found_handles.empty());
}

TEST_F(RealTpmHandleManagerTest, GetHandleListPersistentHandlesError) {
  EXPECT_CALL(mock_blob_1_, Get(_));
  EXPECT_CALL(mock_blob_2_, Get(_)).WillOnce(Return(trunks::TPM_RC_FAILURE));
  std::vector<trunks::TPM_HANDLE> found_handles;
  EXPECT_EQ(manager_->GetHandleList(trunks::PERSISTENT_FIRST, &found_handles),
            trunks::TPM_RC_FAILURE);
}

TEST_F(RealTpmHandleManagerTest, GetHandleListTransientHandles) {
  std::vector<trunks::TPM_HANDLE> found_handles;
  // Initially it should be empty.
  EXPECT_EQ(manager_->GetHandleList(trunks::TRANSIENT_FIRST, &found_handles),
            trunks::TPM_RC_SUCCESS);
  EXPECT_TRUE(found_handles.empty());

  // Simulate the loading of a transient object.
  constexpr trunks::TPM_HANDLE kFakeParent = trunks::TRANSIENT_FIRST;
  constexpr trunks::TPM_HANDLE kFakeChild = trunks::TRANSIENT_FIRST + 1;
  manager_->OnLoad(kFakeParent, kFakeChild);
  EXPECT_EQ(manager_->GetHandleList(trunks::TRANSIENT_FIRST, &found_handles),
            trunks::TPM_RC_SUCCESS);
  EXPECT_THAT(found_handles, ElementsAre(kFakeChild));
}

TEST_F(RealTpmHandleManagerTest,
       GetHandleListTransientHandlesStartingTooLarge) {
  std::vector<trunks::TPM_HANDLE> found_handles;
  // Initially it should be empty.
  EXPECT_EQ(manager_->GetHandleList(trunks::TRANSIENT_FIRST, &found_handles),
            trunks::TPM_RC_SUCCESS);
  EXPECT_TRUE(found_handles.empty());

  // Simulate the loading of a transient object.
  constexpr trunks::TPM_HANDLE kFakeParent = trunks::TRANSIENT_FIRST;
  constexpr trunks::TPM_HANDLE kFakeChild = trunks::TRANSIENT_FIRST + 1;
  manager_->OnLoad(kFakeParent, kFakeChild);
  EXPECT_EQ(manager_->GetHandleList(kFakeChild + 1, &found_handles),
            trunks::TPM_RC_SUCCESS);
  EXPECT_TRUE(found_handles.empty());
}

TEST_F(RealTpmHandleManagerTest, GetHandleListPermanentHandlesNotSupported) {
  std::vector<trunks::TPM_HANDLE> found_handles;
  EXPECT_EQ(manager_->GetHandleList(trunks::PERMANENT_FIRST, &found_handles),
            trunks::TPM_RC_HANDLE);
}

TEST_F(RealTpmHandleManagerTest,
       GetHandleListPolicySessionHandlesNotSupported) {
  std::vector<trunks::TPM_HANDLE> found_handles;
  EXPECT_EQ(
      manager_->GetHandleList(trunks::POLICY_SESSION_FIRST, &found_handles),
      trunks::TPM_RC_HANDLE);
}

TEST_F(RealTpmHandleManagerTest, GetHandleListNvramHandles) {
  std::vector<trunks::TPM_HANDLE> expect_result{kFakeHandle1, kFakeHandle3};

  EXPECT_CALL(mock_nv_space_manager_, ListHandles(_))
      .WillOnce(DoAll(testing::SetArgReferee<0>(expect_result),
                      Return(trunks::TPM_RC_SUCCESS)));

  std::vector<trunks::TPM_HANDLE> found_handles;
  EXPECT_EQ(manager_->GetHandleList(trunks::NV_INDEX_FIRST, &found_handles),
            trunks::TPM_RC_SUCCESS);
  EXPECT_THAT(found_handles, ElementsAre(kFakeHandle1, kFakeHandle3));
}

TEST_F(RealTpmHandleManagerTest, TranslateHandleSuccessPersistentHandles) {
  EXPECT_CALL(mock_blob_1_, Get(_));
  ScopedHostKeyHandle host_handle;
  EXPECT_CALL(mock_tpm_utility_, LoadKey(kFakeBlob1, _, _));
  EXPECT_EQ(manager_->TranslateHandle(kFakeHandle1, &host_handle),
            trunks::TPM_RC_SUCCESS);
  // NOTE that we don't validate the exact value of the returned handle because
  // it's up to implementation of the mocks.
  EXPECT_NE(host_handle.Get(), trunks::TPM_HANDLE());
  EXPECT_CALL(mock_tpm_, FlushContextSync(host_handle.Get(), _));
}

TEST_F(RealTpmHandleManagerTest, TranslateHandleSuccessPermanentHandles) {
  ScopedHostKeyHandle host_handle;
  constexpr trunks::TPM_HANDLE kPermanmentHandle = trunks::TPM_RH_ENDORSEMENT;
  EXPECT_EQ(manager_->TranslateHandle(kPermanmentHandle, &host_handle),
            trunks::TPM_RC_SUCCESS);
  // The handle should not be changed.
  EXPECT_EQ(host_handle.Get(), kPermanmentHandle);
}

TEST_F(RealTpmHandleManagerTest, TranslateHandleSuccessPolicySessionHandles) {
  ScopedHostKeyHandle host_handle;
  constexpr trunks::TPM_HANDLE kPolicySessionHandle =
      trunks::POLICY_SESSION_FIRST;
  EXPECT_EQ(manager_->TranslateHandle(kPolicySessionHandle, &host_handle),
            trunks::TPM_RC_SUCCESS);
  // The handle should not be changed.
  EXPECT_EQ(host_handle.Get(), kPolicySessionHandle);
}

TEST_F(RealTpmHandleManagerTest,
       TranslateHandleSuccessPersistentHandlesMovedScopedHostHandle) {
  EXPECT_CALL(mock_blob_1_, Get(_));
  ScopedHostKeyHandle host_handle;
  EXPECT_CALL(mock_tpm_utility_, LoadKey(kFakeBlob1, _, _));
  EXPECT_EQ(manager_->TranslateHandle(kFakeHandle1, &host_handle),
            trunks::TPM_RC_SUCCESS);
  // NOTE that we don't validate the exact value of the returned handle because
  // it's up to implementation of the mocks.
  EXPECT_NE(host_handle.Get(), trunks::TPM_HANDLE());
  EXPECT_CALL(mock_tpm_, FlushContextSync(host_handle.Get(), _));
  ScopedHostKeyHandle moved_host_handle = std::move(host_handle);
}

TEST_F(RealTpmHandleManagerTest, TranslateHandleTransientHandles) {
  // First, load a virtual persistent handle. Technically this is not necessary;
  // it is just to make sure we don't have memory leak in normal operation
  // flows.
  ScopedHostKeyHandle parent_host_handle;
  EXPECT_CALL(mock_blob_1_, Get(_));
  EXPECT_CALL(mock_tpm_utility_, LoadKey(kFakeBlob1, _, _));
  EXPECT_EQ(manager_->TranslateHandle(kFakeHandle1, &parent_host_handle),
            trunks::TPM_RC_SUCCESS);
  // NOTE that through the entire flow no flush of a virtual transient handle
  // should take place because the guest flushes the loaded object by their own
  // instead of vtpm loading/unloading them transparently. Strick mock will
  // verify.
  ScopedHostKeyHandle host_handle;
  const trunks::TPM_HANDLE fake_parent = parent_host_handle.Get();
  constexpr trunks::TPM_HANDLE kFakeChild1 = trunks::TRANSIENT_FIRST + 1;
  constexpr trunks::TPM_HANDLE kFakeChild2 = trunks::TRANSIENT_FIRST + 2;

  // Deny the unloaded handle.
  EXPECT_EQ(manager_->TranslateHandle(kFakeChild1, &host_handle),
            trunks::TPM_RC_HANDLE);
  EXPECT_EQ(manager_->TranslateHandle(kFakeChild2, &host_handle),
            trunks::TPM_RC_HANDLE);

  manager_->OnLoad(fake_parent, kFakeChild1);
  EXPECT_EQ(manager_->TranslateHandle(kFakeChild1, &host_handle),
            trunks::TPM_RC_SUCCESS);
  EXPECT_EQ(host_handle.Get(), kFakeChild1);
  EXPECT_EQ(manager_->TranslateHandle(kFakeChild2, &host_handle),
            trunks::TPM_RC_HANDLE);

  // Let go of the parent host handle. Note that it should not be flushed
  // because the child handles force the parent to be retained. Strict mock will
  // verify.
  parent_host_handle = ScopedHostKeyHandle();

  manager_->OnLoad(fake_parent, kFakeChild2);
  EXPECT_EQ(manager_->TranslateHandle(kFakeChild1, &host_handle),
            trunks::TPM_RC_SUCCESS);
  EXPECT_EQ(host_handle.Get(), kFakeChild1);
  EXPECT_EQ(manager_->TranslateHandle(kFakeChild2, &host_handle),
            trunks::TPM_RC_SUCCESS);
  EXPECT_EQ(host_handle.Get(), kFakeChild2);

  manager_->OnUnload(kFakeChild2);
  EXPECT_EQ(manager_->TranslateHandle(kFakeChild1, &host_handle),
            trunks::TPM_RC_SUCCESS);
  EXPECT_EQ(host_handle.Get(), kFakeChild1);
  EXPECT_EQ(manager_->TranslateHandle(kFakeChild2, &host_handle),
            trunks::TPM_RC_HANDLE);

  // Unlaoding the last child of the parent should flush the parent handle.
  EXPECT_CALL(mock_tpm_, FlushContextSync(fake_parent, _));

  manager_->OnUnload(kFakeChild1);
  EXPECT_EQ(manager_->TranslateHandle(kFakeChild1, &host_handle),
            trunks::TPM_RC_HANDLE);
  EXPECT_EQ(manager_->TranslateHandle(kFakeChild2, &host_handle),
            trunks::TPM_RC_HANDLE);
}

TEST_F(RealTpmHandleManagerTest, UnloadNoexistentHandle) {
  // Unloading a non-existent handle should not cause any consequence. In best
  // effort we ensure it doesn't crash.
  manager_->OnUnload(trunks::TRANSIENT_FIRST);
}

}  // namespace

}  // namespace vtpm
