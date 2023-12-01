// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <base/dcheck_is_on.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include "base/test/bind.h"
#include <chromeos/dbus/service_constants.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_exported_object.h>
#include <dbus/mock_object_proxy.h>
#include <gtest/gtest.h>

#include "featured/mock_tmp_storage_impl.h"
#include "featured/service.h"
#include "featured/store_impl.h"
#include "featured/store_impl_mock.h"
#include "featured/store_interface.h"

using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::StrictMock;

namespace featured {

namespace {
void ResponseSenderCallback(const std::string& expected_message,
                            std::unique_ptr<dbus::Response> response) {
  EXPECT_EQ(expected_message, response->ToString());
}
}  // namespace

TEST(FeatureCommand, FileExistsTest) {
  base::FilePath file;
  ASSERT_TRUE(base::CreateTemporaryFile(&file));

  FileExistsCommand c(file.MaybeAsASCII());
  ASSERT_TRUE(c.Execute());

  FileNotExistsCommand c2(file.MaybeAsASCII());
  ASSERT_FALSE(c2.Execute());
}

TEST(FeatureCommand, FileNotExistsTest) {
  base::ScopedTempDir dir;
  ASSERT_TRUE(dir.CreateUniqueTempDir());

  base::FilePath file(dir.GetPath().Append("non-existent"));

  FileNotExistsCommand c(file.MaybeAsASCII());
  ASSERT_TRUE(c.Execute());

  FileExistsCommand c2(file.MaybeAsASCII());
  ASSERT_FALSE(c2.Execute());
}

TEST(FeatureCommand, MkdirTest) {
  if (base::PathExists(base::FilePath("/sys/kernel/tracing/instances/"))) {
    const std::string sys_path = "/sys/kernel/tracing/instances/unittest";
    EXPECT_FALSE(base::PathExists(base::FilePath(sys_path)));
    EXPECT_TRUE(featured::MkdirCommand(sys_path).Execute());
    EXPECT_TRUE(base::PathExists(base::FilePath(sys_path)));
    EXPECT_TRUE(base::DeleteFile(base::FilePath(sys_path)));
    EXPECT_FALSE(base::PathExists(base::FilePath(sys_path)));
  }

  if (base::PathExists(base::FilePath("/mnt"))) {
    const std::string mnt_path = "/mnt/notallowed";
    EXPECT_FALSE(base::PathExists(base::FilePath(mnt_path)));
    EXPECT_FALSE(featured::MkdirCommand(mnt_path).Execute());
    EXPECT_FALSE(base::PathExists(base::FilePath(mnt_path)));
  }
}

// A base class to set up dbus objects, etc, needed for all tests.
class DbusFeaturedServiceTestBase : public testing::Test {
 public:
  DbusFeaturedServiceTestBase(
      std::unique_ptr<MockStoreImpl> mock_store_impl,
      std::unique_ptr<MockTmpStorageImpl> mock_tmp_storage_impl)
      : mock_bus_(base::MakeRefCounted<dbus::MockBus>(dbus::Bus::Options{})),
        path_(chromeos::kChromeFeaturesServicePath),
        mock_proxy_(base::MakeRefCounted<dbus::MockObjectProxy>(
            mock_bus_.get(), chromeos::kChromeFeaturesServiceName, path_)),
        mock_exported_object_(base::MakeRefCounted<dbus::MockExportedObject>(
            mock_bus_.get(), path_)) {
    // This weird ownership structure is necessary to be able to run
    // EXPECT_CALLS/ON_CALLS in individual tests. The DbusFeaturedService class
    // will take ownership.
    mock_store_impl_ = mock_store_impl.get();
    mock_tmp_storage_impl_ = mock_tmp_storage_impl.get();
    service_ = std::make_shared<DbusFeaturedService>(
        std::move(mock_store_impl), std::move(mock_tmp_storage_impl));

    ON_CALL(*mock_bus_, GetExportedObject(_))
        .WillByDefault(Return(mock_exported_object_.get()));
    ON_CALL(*mock_bus_, Connect()).WillByDefault(Return(true));
    ON_CALL(*mock_bus_, GetObjectProxy(_, _))
        .WillByDefault(Return(mock_proxy_.get()));
    ON_CALL(*mock_bus_, RequestOwnershipAndBlock(_, _))
        .WillByDefault(Return(true));
    ON_CALL(*mock_exported_object_, ExportMethodAndBlock(_, _, _))
        .WillByDefault(Return(true));
  }

  void TearDown() override {
    mock_bus_->ShutdownAndBlock();
    feature::PlatformFeatures::ShutdownForTesting();
  }

 protected:
  void HandleSeedFetched(dbus::MethodCall* method_call,
                         dbus::ExportedObject::ResponseSender sender) {
    service_->HandleSeedFetched(method_call, std::move(sender));
  }

  scoped_refptr<dbus::MockBus> mock_bus_;
  dbus::ObjectPath path_;
  scoped_refptr<dbus::MockObjectProxy> mock_proxy_;
  scoped_refptr<dbus::MockExportedObject> mock_exported_object_;
  MockStoreImpl* mock_store_impl_;
  MockTmpStorageImpl* mock_tmp_storage_impl_;
  std::shared_ptr<DbusFeaturedService> service_;
};

class DbusFeaturedServiceTest : public DbusFeaturedServiceTestBase {
 public:
  DbusFeaturedServiceTest()
      : DbusFeaturedServiceTestBase(std::make_unique<MockStoreImpl>(),
                                    std::make_unique<MockTmpStorageImpl>()) {
    ON_CALL(*mock_store_impl_, SetLastGoodSeed(_)).WillByDefault(Return(true));
    ON_CALL(*mock_store_impl_, ClearBootAttemptsSinceLastUpdate())
        .WillByDefault(Return(true));
  }
};

// Checks that service start successfully increments the boot attempts counter
// on boot.
TEST_F(DbusFeaturedServiceTest, IncrementBootAttemptsOnStartup_Success) {
  EXPECT_CALL(*mock_store_impl_, IncrementBootAttemptsSinceLastUpdate())
      .WillOnce(Return(true));

  EXPECT_TRUE(service_->Start(mock_bus_.get(), service_));
}

// Checks that service start fails when incrementing the boot attempts counter
// on boot fails.
TEST_F(DbusFeaturedServiceTest, IncrementBootAttemptsOnStartup_Failure) {
  EXPECT_CALL(*mock_store_impl_, IncrementBootAttemptsSinceLastUpdate())
      .WillOnce(Return(false));

  EXPECT_FALSE(service_->Start(mock_bus_.get(), service_));
}

// Checks that an empty response is returned on success, and that the store's
// SetLastGoodSeed method is called when the used seed matches safe seed.
TEST_F(DbusFeaturedServiceTest, HandleSeedFetched_Success_MatchedSeed) {
  constexpr char kExpectedMessage[] = R"--(message_type: MESSAGE_METHOD_RETURN
reply_serial: 123

)--";

  SeedDetails used;
  used.set_compressed_data("fake");
  EXPECT_CALL(*mock_tmp_storage_impl_, GetUsedSeedDetails())
      .WillOnce(Return(used));
  EXPECT_CALL(*mock_store_impl_, SetLastGoodSeed(_)).WillOnce(Return(true));

  dbus::MethodCall method_call("com.example.Interface", "SomeMethod");
  dbus::MessageWriter writer(&method_call);
  // Should match |used|.
  SeedDetails seed;
  seed.set_compressed_data("fake");
  writer.AppendProtoAsArrayOfBytes(seed);
  // Not setting the serial causes a crash.
  method_call.SetSerial(123);

  HandleSeedFetched(&method_call,
                    base::BindOnce(&ResponseSenderCallback, kExpectedMessage));
}

// Checks that an empty response is returned on success, and that the store's
// SetLastGoodSeed method isn't called when used seed doesn't match safe seed.
TEST_F(DbusFeaturedServiceTest, HandleSeedFetched_Success_MismatchedSeed) {
  constexpr char kExpectedMessage[] = R"--(message_type: MESSAGE_METHOD_RETURN
reply_serial: 123

)--";

  SeedDetails used;
  used.set_compressed_data("fake");
  EXPECT_CALL(*mock_tmp_storage_impl_, GetUsedSeedDetails())
      .WillOnce(Return(used));
  EXPECT_CALL(*mock_store_impl_, SetLastGoodSeed(_)).Times(0);

  dbus::MethodCall method_call("com.example.Interface", "SomeMethod");
  dbus::MessageWriter writer(&method_call);
  // Should be different than |used|.
  SeedDetails seed;
  seed.set_compressed_data("different");
  writer.AppendProtoAsArrayOfBytes(seed);
  // Not setting the serial causes a crash.
  method_call.SetSerial(123);

  HandleSeedFetched(&method_call,
                    base::BindOnce(&ResponseSenderCallback, kExpectedMessage));
}

// Checks that HandleSeedFetched returns an error response when no arguments are
// passed in.
TEST_F(DbusFeaturedServiceTest, HandleSeedFetched_Failure_NoArgument) {
  constexpr char kExpectedMessage[] = R"--(message_type: MESSAGE_ERROR
error_name: org.freedesktop.DBus.Error.InvalidArgs
signature: s
reply_serial: 123

string "Could not parse seed argument"
)--";

  dbus::MethodCall method_call("com.example.Interface", "SomeMethod");
  // Not setting the serial causes a crash.
  method_call.SetSerial(123);

  HandleSeedFetched(&method_call,
                    base::BindOnce(&ResponseSenderCallback, kExpectedMessage));
}

// Checks that HandleSeedFetched returns an error response when a non-seed
// argument is passed in.
TEST_F(DbusFeaturedServiceTest, HandleSeedFetched_Failure_InvalidArgument) {
  constexpr char kExpectedMessage[] = R"--(message_type: MESSAGE_ERROR
error_name: org.freedesktop.DBus.Error.InvalidArgs
signature: s
reply_serial: 123

string "Could not parse seed argument"
)--";

  dbus::MethodCall method_call("com.example.Interface", "SomeMethod");
  dbus::MessageWriter writer(&method_call);
  writer.AppendString("string");
  // Not setting the serial causes a crash.
  method_call.SetSerial(123);

  HandleSeedFetched(&method_call,
                    base::BindOnce(&ResponseSenderCallback, kExpectedMessage));
}

// Checks that HandleSeedFetched returns an error response when saving the seed
// to disk fails.
TEST_F(DbusFeaturedServiceTest, HandleSeedFetched_Failure_SetSeedFailure) {
  EXPECT_CALL(*mock_store_impl_, SetLastGoodSeed(_)).WillOnce(Return(false));

  constexpr char kExpectedMessage[] = R"--(message_type: MESSAGE_ERROR
error_name: org.freedesktop.DBus.Error.Failed
signature: s
reply_serial: 123

string "Failed to write fetched seed to disk"
)--";

  dbus::MethodCall method_call("com.example.Interface", "SomeMethod");
  dbus::MessageWriter writer(&method_call);
  SeedDetails seed;
  writer.AppendProtoAsArrayOfBytes(seed);
  // Not setting the serial causes a crash.
  method_call.SetSerial(123);

  HandleSeedFetched(&method_call,
                    base::BindOnce(&ResponseSenderCallback, kExpectedMessage));
}

// Checks that HandleSeedFetched returns an error response when saving the seed
// to disk fails.
TEST_F(DbusFeaturedServiceTest,
       HandleSeedFetched_Failure_ClearBootCounterFailure) {
  EXPECT_CALL(*mock_store_impl_, ClearBootAttemptsSinceLastUpdate())
      .WillOnce(Return(false));

  constexpr char kExpectedMessage[] = R"--(message_type: MESSAGE_ERROR
error_name: org.freedesktop.DBus.Error.Failed
signature: s
reply_serial: 123

string "Failed to reset boot attempts counter"
)--";

  dbus::MethodCall method_call("com.example.Interface", "SomeMethod");
  dbus::MessageWriter writer(&method_call);
  SeedDetails seed;
  writer.AppendProtoAsArrayOfBytes(seed);
  // Not setting the serial causes a crash.
  method_call.SetSerial(123);

  HandleSeedFetched(&method_call,
                    base::BindOnce(&ResponseSenderCallback, kExpectedMessage));
}

class DbusFeaturedServiceNoLockboxTest : public DbusFeaturedServiceTestBase {
 public:
  DbusFeaturedServiceNoLockboxTest()
      : DbusFeaturedServiceTestBase(nullptr, nullptr) {}
};

TEST_F(DbusFeaturedServiceNoLockboxTest, Startup_Success) {
  EXPECT_TRUE(service_->Start(mock_bus_.get(), service_));
}

// Checks that an empty response is returned on missing store.
TEST_F(DbusFeaturedServiceNoLockboxTest, HandleSeedFetched_Success) {
  constexpr char kExpectedMessage[] = R"--(message_type: MESSAGE_METHOD_RETURN
reply_serial: 123

)--";

  dbus::MethodCall method_call("com.example.Interface", "SomeMethod");
  dbus::MessageWriter writer(&method_call);
  SeedDetails seed;
  writer.AppendProtoAsArrayOfBytes(seed);
  // Not setting the serial causes a crash.
  method_call.SetSerial(123);

  HandleSeedFetched(&method_call,
                    base::BindOnce(&ResponseSenderCallback, kExpectedMessage));
}

}  // namespace featured
