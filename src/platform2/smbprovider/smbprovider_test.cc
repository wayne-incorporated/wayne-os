// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/test/simple_test_tick_clock.h>
#include <dbus/mock_bus.h>
#include <dbus/object_path.h>
#include <dbus/smbprovider/dbus-constants.h>
#include <gtest/gtest.h>
#include <kerberos/proto_bindings/kerberos_service.pb.h>

#include "smbprovider/fake_kerberos_artifact_client.h"
#include "smbprovider/fake_samba_interface.h"
#include "smbprovider/fake_samba_proxy.h"
#include "smbprovider/iterator/directory_iterator.h"
#include "smbprovider/kerberos_artifact_synchronizer.h"
#include "smbprovider/metadata_cache.h"
#include "smbprovider/mount_config.h"
#include "smbprovider/mount_manager.h"
#include "smbprovider/netbios_packet_parser.h"
#include "smbprovider/proto_bindings/directory_entry.pb.h"
#include "smbprovider/smbprovider.h"
#include "smbprovider/smbprovider_helper.h"
#include "smbprovider/smbprovider_test_helper.h"
#include "smbprovider/temp_file_manager.h"

namespace smbprovider {
namespace {

using brillo::dbus_utils::DBusObject;

// Arbitrary D-Bus serial.
constexpr int32_t kDBusSerial = 123;

ErrorType CastError(int error) {
  EXPECT_GE(error, 0);
  return static_cast<ErrorType>(error);
}

DirectoryEntryListProto GetDirectoryEntryListProtoFromBlob(
    const ProtoBlob& blob) {
  DirectoryEntryListProto entries;
  EXPECT_TRUE(entries.ParseFromArray(blob.data(), blob.size()));

  return entries;
}

HostnamesProto GetHostnamesProtoFromBlob(const ProtoBlob& blob) {
  HostnamesProto hostnames_proto;
  EXPECT_TRUE(hostnames_proto.ParseFromArray(blob.data(), blob.size()));

  return hostnames_proto;
}

void ExpectKerberosCallback(bool expected_result,
                            std::unique_ptr<dbus::Response> response) {
  EXPECT_TRUE(response.get());
  dbus::MessageReader reader(response.get());
  bool result;
  EXPECT_TRUE(reader.PopBool(&result));
  EXPECT_EQ(expected_result, result);
}

}  // namespace

class SmbProviderTest : public testing::Test {
 public:
  std::unique_ptr<SambaInterface> SambaInterfaceFactoryFunction(
      FakeSambaInterface* fake_samba,
      MountManager* mount_manager,
      const MountConfig& mount_config) {
    enable_ntlm_ = mount_config.enable_ntlm;
    return std::make_unique<FakeSambaProxy>(fake_samba);
  }

  SmbProviderTest() { SetUpSmbProvider(false /* enable_metadata_cache */); }
  SmbProviderTest(const SmbProviderTest&) = delete;
  SmbProviderTest& operator=(const SmbProviderTest&) = delete;

 protected:
  using DirEntries = std::vector<smbc_dirent>;

  // Sets up SmbProvider with caching set to |enable_metadata_cache|. This is
  // called by default before each test with caching disabled. Pass true and
  // call as the first line in a test to enable caching.
  void SetUpSmbProvider(bool enable_metadata_cache) {
    fake_samba_ = std::make_unique<FakeSambaInterface>();

    auto tick_clock = std::make_unique<base::SimpleTestTickClock>();
    fake_tick_clock_ = tick_clock.get();

    auto mount_tracker = std::make_unique<MountTracker>(std::move(tick_clock),
                                                        enable_metadata_cache);

    auto samba_interface_factory =
        base::BindRepeating(&SmbProviderTest::SambaInterfaceFactoryFunction,
                            base::Unretained(this), fake_samba_.get());

    auto mount_manager_ptr = std::make_unique<MountManager>(
        std::move(mount_tracker), samba_interface_factory);

    mount_manager_ = mount_manager_ptr.get();

    auto fake_artifact_client = std::make_unique<FakeKerberosArtifactClient>();
    kerberos_client_ = fake_artifact_client.get();

    // Make sure there is a fresh directory in the case this is called more
    // than once.
    if (krb_temp_dir_.IsValid()) {
      EXPECT_TRUE(krb_temp_dir_.Delete());
    }
    EXPECT_TRUE(krb_temp_dir_.CreateUniqueTempDir());

    if (daemon_store_temp_dir_.IsValid()) {
      EXPECT_TRUE(daemon_store_temp_dir_.Delete());
    }
    EXPECT_TRUE(daemon_store_temp_dir_.CreateUniqueTempDir());

    krb5_conf_path_ = CreateKrb5ConfPath(krb_temp_dir_.GetPath());
    krb5_ccache_path_ = CreateKrb5CCachePath(krb_temp_dir_.GetPath());

    auto kerberos_artifact_synchronizer =
        std::make_unique<KerberosArtifactSynchronizer>(
            krb5_conf_path_, krb5_ccache_path_, std::move(fake_artifact_client),
            false /* allow_credentials_update */);
    kerberos_synchronizer_ = kerberos_artifact_synchronizer.get();

    const dbus::ObjectPath object_path("/object/path");
    smbprovider_ = std::make_unique<SmbProvider>(
        std::make_unique<DBusObject>(nullptr, mock_bus_, object_path),
        std::move(mount_manager_ptr), std::move(kerberos_artifact_synchronizer),
        daemon_store_temp_dir_.GetPath());

    metadata_cache_ = std::make_unique<MetadataCache>(
        fake_tick_clock_,
        base::Microseconds(kMetadataCacheLifetimeMicroseconds),
        MetadataCache::Mode::kDisabled);
  }

  // Helper method that asserts there are no entries that have not been
  // closed.
  void ExpectNoOpenEntries() { EXPECT_FALSE(fake_samba_->HasOpenEntries()); }

  bool GetRootPath(int32_t mount_id, std::string* mount_path) const {
    return mount_manager_->GetFullPath(mount_id, "" /* entry_path */,
                                       mount_path);
  }

  void CreateDaemonStoreForUser(const std::string& user_hash) {
    base::File::Error error = base::File::FILE_OK;
    EXPECT_TRUE(base::CreateDirectoryAndGetError(
        daemon_store_temp_dir_.GetPath().Append(base::FilePath(user_hash)),
        &error))
        << "CreateDaemonStoreForUser error: " << error;
  }

  std::string krb5_conf_path_;
  std::string krb5_ccache_path_;
  base::ScopedTempDir krb_temp_dir_;
  base::ScopedTempDir daemon_store_temp_dir_;
  scoped_refptr<dbus::MockBus> mock_bus_ =
      new dbus::MockBus(dbus::Bus::Options());
  std::unique_ptr<SmbProvider> smbprovider_;
  std::unique_ptr<FakeSambaInterface> fake_samba_;
  base::SimpleTestTickClock* fake_tick_clock_;
  MountManager* mount_manager_;
  TempFileManager temp_file_manager_;
  FakeKerberosArtifactClient* kerberos_client_;
  KerberosArtifactSynchronizer* kerberos_synchronizer_;
  // |metadata_cache| is used to test the GetEntries method
  std::unique_ptr<MetadataCache> metadata_cache_;
  bool enable_ntlm_ = false;
};

TEST_F(SmbProviderTest, GetSharesFailsOnEmptyProto) {
  ProtoBlob empty_blob;
  int32_t error;
  ProtoBlob result;

  smbprovider_->GetShares(empty_blob, &error, &result);
  EXPECT_EQ(ERROR_DBUS_PARSE_FAILED, CastError(error));
}

TEST_F(SmbProviderTest, GetSharesFailsOnNonExistentServer) {
  ProtoBlob blob = CreateGetSharesOptionsBlob("smb://0.0.0.1");
  int32_t error;
  ProtoBlob result;

  smbprovider_->GetShares(blob, &error, &result);
  EXPECT_EQ(ERROR_NOT_FOUND, CastError(error));
}

TEST_F(SmbProviderTest, GetSharesSucceedsOnEmptyServer) {
  const std::string server_url = "smb://192.168.0.1";
  fake_samba_->AddServer(server_url);

  ProtoBlob blob = CreateGetSharesOptionsBlob(server_url);
  int32_t error;
  ProtoBlob result;

  smbprovider_->GetShares(blob, &error, &result);
  EXPECT_EQ(ERROR_OK, CastError(error));
  EXPECT_TRUE(GetDirectoryEntryListProtoFromBlob(result).entries().empty());
}

TEST_F(SmbProviderTest, GetSharesSucceedsWithSingleShare) {
  const std::string server_url = "smb://192.168.0.1";
  const std::string share = "share1";

  fake_samba_->AddServer(server_url);
  fake_samba_->AddShare(server_url + "/" + share);

  ProtoBlob blob = CreateGetSharesOptionsBlob(server_url);
  int32_t error;
  ProtoBlob result;

  smbprovider_->GetShares(blob, &error, &result);
  EXPECT_EQ(ERROR_OK, CastError(error));

  DirectoryEntryListProto dir_entry_list =
      GetDirectoryEntryListProtoFromBlob(result);
  EXPECT_EQ(dir_entry_list.entries().size(), 1);

  const DirectoryEntryProto& entry = dir_entry_list.entries(0);
  EXPECT_EQ(entry.name(), share);
  EXPECT_TRUE(entry.is_directory());
}

TEST_F(SmbProviderTest, GetSharesSucceedsWithMultipleShares) {
  const std::string server_url = "smb://192.168.0.1";
  const std::string share1 = "share1";
  const std::string share2 = "share2";

  fake_samba_->AddServer(server_url);
  fake_samba_->AddShare(server_url + "/" + share1);
  fake_samba_->AddShare(server_url + "/" + share2);

  ProtoBlob blob = CreateGetSharesOptionsBlob(server_url);
  int32_t error;
  ProtoBlob result;

  smbprovider_->GetShares(blob, &error, &result);
  EXPECT_EQ(ERROR_OK, CastError(error));

  DirectoryEntryListProto dir_entry_list =
      GetDirectoryEntryListProtoFromBlob(result);
  EXPECT_EQ(dir_entry_list.entries().size(), 2);

  const DirectoryEntryProto& entry1 = dir_entry_list.entries(0);
  EXPECT_EQ(entry1.name(), share1);
  EXPECT_TRUE(entry1.is_directory());

  const DirectoryEntryProto& entry2 = dir_entry_list.entries(1);
  EXPECT_EQ(entry2.name(), share2);
  EXPECT_TRUE(entry2.is_directory());
}

TEST_F(SmbProviderTest, GetSharesDoesntReturnSelfAndParentEntries) {
  const std::string server_url = "smb://192.168.0.1";
  const std::string share1 = "share1";

  fake_samba_->AddServer(server_url);
  fake_samba_->AddShare(server_url + "/" + share1);

  // These shouldn't be returned by GetShares.
  fake_samba_->AddShare(server_url + "/.");
  fake_samba_->AddShare(server_url + "/..");

  ProtoBlob blob = CreateGetSharesOptionsBlob(server_url);
  int32_t error;
  ProtoBlob result;

  smbprovider_->GetShares(blob, &error, &result);
  EXPECT_EQ(ERROR_OK, CastError(error));

  DirectoryEntryListProto dir_entry_list =
      GetDirectoryEntryListProtoFromBlob(result);
  EXPECT_EQ(dir_entry_list.entries().size(), 1);

  const DirectoryEntryProto& entry1 = dir_entry_list.entries(0);
  EXPECT_EQ(entry1.name(), share1);
  EXPECT_TRUE(entry1.is_directory());
}

TEST_F(SmbProviderTest, GetSharesDoesntReturnNonShareEntries) {
  const std::string server_url = "smb://192.168.0.1";
  const std::string share1 = "share1";

  fake_samba_->AddServer(server_url);
  fake_samba_->AddShare(server_url + "/" + share1);

  // These shouldn't be returned by GetShares since they aren't shares.
  fake_samba_->AddDirectory(server_url + "/dir");
  fake_samba_->AddFile(server_url + "/file");

  ProtoBlob blob = CreateGetSharesOptionsBlob(server_url);
  int32_t error;
  ProtoBlob result;

  smbprovider_->GetShares(blob, &error, &result);
  EXPECT_EQ(ERROR_OK, CastError(error));

  DirectoryEntryListProto dir_entry_list =
      GetDirectoryEntryListProtoFromBlob(result);
  EXPECT_EQ(dir_entry_list.entries().size(), 1);

  const DirectoryEntryProto& entry1 = dir_entry_list.entries(0);
  EXPECT_EQ(entry1.name(), share1);
  EXPECT_TRUE(entry1.is_directory());
}

TEST_F(SmbProviderTest, GetSharesReturnsShareContainingDirectory) {
  const std::string server_url = "smb://192.168.0.1";
  const std::string share1 = "share1";

  fake_samba_->AddServer(server_url);
  fake_samba_->AddShare(server_url + "/" + share1);

  // Add a directory in the share.
  fake_samba_->AddDirectory(server_url + "/" + share1 + "/dir");

  ProtoBlob blob = CreateGetSharesOptionsBlob(server_url);
  int32_t error;
  ProtoBlob result;

  smbprovider_->GetShares(blob, &error, &result);
  EXPECT_EQ(ERROR_OK, CastError(error));

  DirectoryEntryListProto dir_entry_list =
      GetDirectoryEntryListProtoFromBlob(result);
  EXPECT_EQ(dir_entry_list.entries().size(), 1);

  const DirectoryEntryProto& entry1 = dir_entry_list.entries(0);
  EXPECT_EQ(entry1.name(), share1);
  EXPECT_TRUE(entry1.is_directory());
}

TEST_F(SmbProviderTest, SetupKerberosWritesKerberosFilesSuccessfully) {
  const std::string user = "test user";
  const std::string krb5cc = "test creds";
  const std::string krb5conf = "test conf";

  kerberos::KerberosFiles kerberos_files =
      CreateKerberosFilesProto(krb5cc, krb5conf);
  kerberos_client_->AddKerberosFiles(user, kerberos_files);

  dbus::MethodCall method_call(kSmbProviderInterface, "SetupKerberos");
  method_call.SetSerial(kDBusSerial);

  SmbProvider::SetupKerberosCallback callback =
      std::make_unique<brillo::dbus_utils::DBusMethodResponse<bool>>(
          &method_call,
          base::BindOnce(&ExpectKerberosCallback, true /* expected_result*/));

  smbprovider_->SetupKerberos(std::move(callback), user);

  ExpectFileEqual(krb5_conf_path_, krb5conf);
  ExpectFileEqual(krb5_ccache_path_, krb5cc);
}

TEST_F(SmbProviderTest, SetupKerberosFailsWhenKerberosFilesDoNotExist) {
  const std::string user = "test user";

  dbus::MethodCall method_call(kSmbProviderInterface, "SetupKerberos");
  method_call.SetSerial(kDBusSerial);

  SmbProvider::SetupKerberosCallback callback =
      std::make_unique<brillo::dbus_utils::DBusMethodResponse<bool>>(
          &method_call,
          base::BindOnce(&ExpectKerberosCallback, false /* expected_result*/));

  smbprovider_->SetupKerberos(std::move(callback), user);
}

TEST_F(SmbProviderTest, ParseNetBiosPacketSucceedsOnValidPacket) {
  const std::string name_string("testname");
  const std::vector<uint8_t> name(name_string.begin(), name_string.end());
  const uint8_t name_length(name.size());
  const uint16_t transaction_id(123);
  const std::string hostname_1 = "hostname1";
  const std::string hostname_2 = "hostname2";
  const std::vector<std::vector<uint8_t>> hostnames = {
      CreateValidNetBiosHostname(hostname_1, netbios::kFileServerNodeType),
      CreateValidNetBiosHostname(hostname_2, netbios::kFileServerNodeType)};

  const std::vector<uint8_t> valid_packet = CreateNetBiosResponsePacket(
      hostnames, name_length, name, transaction_id, 0x20 /* response_type */);

  ProtoBlob blob =
      smbprovider_->ParseNetBiosPacket(valid_packet, transaction_id);

  const HostnamesProto hostnames_proto = GetHostnamesProtoFromBlob(blob);
  EXPECT_EQ(2, hostnames_proto.hostnames().size());
  EXPECT_EQ(hostname_1, hostnames_proto.hostnames(0));
  EXPECT_EQ(hostname_2, hostnames_proto.hostnames(1));
}

TEST_F(SmbProviderTest, ParseNetBiosPacketFailsOnInvalidPacket) {
  const std::vector<uint8_t> invalid_packet;

  ProtoBlob blob =
      smbprovider_->ParseNetBiosPacket(invalid_packet, 0 /* transaction_id */);

  const HostnamesProto hostnames_proto = GetHostnamesProtoFromBlob(blob);
  EXPECT_EQ(0, hostnames_proto.hostnames().size());
}

}  // namespace smbprovider
