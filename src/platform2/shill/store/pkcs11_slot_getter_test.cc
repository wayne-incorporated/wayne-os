// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/store/pkcs11_slot_getter.h"

#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <chaps/chaps_proxy_mock.h>
#include <chaps/token_manager_client_mock.h>

#include "shill/store/pkcs11_util.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;
using ::testing::DoAll;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::SetArgPointee;

namespace shill {

namespace {

constexpr char kUserHash[] = "a1b2c3d4";
constexpr char kUnknownUserHash[] = "ffffffff";
const base::FilePath kChapsSystemTokenPath("/var/lib/chaps");
const base::FilePath kChapsUserTokenPath("/run/daemon-store/chaps/a1b2c3d4");

}  // namespace

typedef chaps::ChapsProxyMock Pkcs11Mock;

class Pkcs11SlotGetterTest : public testing::Test {
 public:
  Pkcs11SlotGetterTest()
      : pkcs11_(false) {}  // Do not pre-initialize the mock PKCS #11 library.
                           // This just controls whether the first call to
                           // C_Initialize returns 'already initialized'.
  Pkcs11SlotGetterTest(const Pkcs11SlotGetterTest&) = delete;
  Pkcs11SlotGetterTest& operator=(const Pkcs11SlotGetterTest&) = delete;

  ~Pkcs11SlotGetterTest() override = default;

  void SetUp() override {
    std::vector<uint64_t> slot_list = {0, 1};
    ON_CALL(pkcs11_, GetSlotList)
        .WillByDefault(DoAll(SetArgPointee<2>(slot_list), Return(0)));
    slot_getter_ =
        std::make_unique<Pkcs11SlotGetter>(kUserHash, &token_manager_);
  }

 protected:
  NiceMock<Pkcs11Mock> pkcs11_;
  chaps::TokenManagerClientMock token_manager_;
  std::unique_ptr<Pkcs11SlotGetter> slot_getter_;
};

TEST_F(Pkcs11SlotGetterTest, GetSystemSlot) {
  EXPECT_CALL(token_manager_, GetTokenPath(_, /*slot_id=*/0, _))
      .WillOnce(DoAll(SetArgPointee<2>(kChapsSystemTokenPath), Return(true)));
  ASSERT_EQ(slot_getter_->GetPkcs11SlotId(pkcs11::Slot::kSystem), 0);

  // Slot is cached.
  EXPECT_CALL(token_manager_, GetTokenPath).Times(0);
  ASSERT_EQ(slot_getter_->GetPkcs11SlotId(pkcs11::Slot::kSystem), 0);
}

TEST_F(Pkcs11SlotGetterTest, GetUserSlot) {
  EXPECT_CALL(token_manager_, GetTokenPath(_, /*slot_id=*/0, _))
      .WillOnce(DoAll(SetArgPointee<2>(kChapsSystemTokenPath), Return(true)));
  EXPECT_CALL(token_manager_, GetTokenPath(_, /*slot_id=*/1, _))
      .WillOnce(DoAll(SetArgPointee<2>(kChapsUserTokenPath), Return(true)));
  ASSERT_EQ(slot_getter_->GetPkcs11SlotId(pkcs11::Slot::kUser), 1);

  // Slot is cached.
  EXPECT_CALL(token_manager_, GetTokenPath).Times(0);
  ASSERT_EQ(slot_getter_->GetPkcs11SlotId(pkcs11::Slot::kUser), 1);
}

TEST_F(Pkcs11SlotGetterTest, GetInvalidUserSlot) {
  EXPECT_CALL(token_manager_, GetTokenPath(_, /*slot_id=*/0, _))
      .WillOnce(DoAll(SetArgPointee<2>(kChapsSystemTokenPath), Return(true)));
  EXPECT_CALL(token_manager_, GetTokenPath(_, /*slot_id=*/1, _))
      .WillOnce(DoAll(SetArgPointee<2>(kChapsUserTokenPath), Return(true)));

  slot_getter_->user_hash_ = kUnknownUserHash;
  ASSERT_EQ(slot_getter_->GetPkcs11SlotId(pkcs11::Slot::kUser),
            pkcs11::kInvalidSlot);
}

TEST_F(Pkcs11SlotGetterTest, GetDefaultSlot_SystemSlot) {
  EXPECT_CALL(token_manager_, GetTokenPath(_, /*slot_id=*/0, _))
      .WillOnce(DoAll(SetArgPointee<2>(kChapsSystemTokenPath), Return(true)));

  slot_getter_->user_hash_ = "";
  ASSERT_EQ(slot_getter_->GetPkcs11DefaultSlotId(), 0);
}

TEST_F(Pkcs11SlotGetterTest, GetDefaultSlot_UserSlot) {
  EXPECT_CALL(token_manager_, GetTokenPath(_, /*slot_id=*/0, _))
      .WillOnce(DoAll(SetArgPointee<2>(kChapsSystemTokenPath), Return(true)));
  EXPECT_CALL(token_manager_, GetTokenPath(_, /*slot_id=*/1, _))
      .WillOnce(DoAll(SetArgPointee<2>(kChapsUserTokenPath), Return(true)));
  ASSERT_EQ(slot_getter_->GetPkcs11DefaultSlotId(), 1);
}

}  // namespace shill
