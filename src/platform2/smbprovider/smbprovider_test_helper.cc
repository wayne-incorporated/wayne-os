// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbprovider/smbprovider_test_helper.h"

#include <algorithm>
#include <utility>

#include <gtest/gtest.h>

#include "smbprovider/mount_config.h"
#include "smbprovider/netbios_packet_parser.h"
#include "smbprovider/proto_bindings/directory_entry.pb.h"
#include "smbprovider/temp_file_manager.h"

#include <base/check.h>
#include <base/check_op.h>

namespace smbprovider {
namespace {

ProtoBlob SerializeProtoToBlobAndCheck(
    const google::protobuf::MessageLite& proto) {
  ProtoBlob proto_blob;
  EXPECT_EQ(ERROR_OK, SerializeProtoToBlob(proto, &proto_blob));
  return proto_blob;
}

}  // namespace

GetSharesOptionsProto CreateGetSharesOptionsProto(
    const std::string& server_url) {
  GetSharesOptionsProto options;
  options.set_server_url(server_url);
  return options;
}

kerberos::KerberosFiles CreateKerberosFilesProto(const std::string& krb5cc,
                                                 const std::string& krb5conf) {
  kerberos::KerberosFiles kerberos_files;
  kerberos_files.set_krb5cc(krb5cc);
  kerberos_files.set_krb5conf(krb5conf);
  return kerberos_files;
}

ProtoBlob CreateGetSharesOptionsBlob(const std::string& server_url) {
  return SerializeProtoToBlobAndCheck(CreateGetSharesOptionsProto(server_url));
}

base::ScopedFD WritePasswordToFile(TempFileManager* temp_manager,
                                   const std::string& password) {
  const size_t password_size = password.size();
  std::vector<uint8_t> password_data(sizeof(password_size) + password.size());

  // Write the password length in the first sizeof(size_t) bytes of the buffer.
  std::memcpy(password_data.data(), &password_size, sizeof(password_size));

  // Append |password| starting at the end of password_size.
  std::memcpy(password_data.data() + sizeof(password_size), password.c_str(),
              password.size());

  return temp_manager->CreateTempFile(password_data);
}

std::string CreateKrb5ConfPath(const base::FilePath& temp_dir) {
  return temp_dir.Append(kTestKrb5ConfName).value();
}

std::string CreateKrb5CCachePath(const base::FilePath& temp_dir) {
  return temp_dir.Append(kTestCCacheName).value();
}

void ExpectFileEqual(const std::string& path,
                     const std::string expected_contents) {
  const base::FilePath file_path(path);
  std::string actual_contents;
  EXPECT_TRUE(ReadFileToString(file_path, &actual_contents));

  EXPECT_EQ(expected_contents, actual_contents);
}

void ExpectFileNotEqual(const std::string& path,
                        const std::string expected_contents) {
  const base::FilePath file_path(path);
  std::string actual_contents;
  EXPECT_TRUE(ReadFileToString(file_path, &actual_contents));

  EXPECT_NE(expected_contents, actual_contents);
}

void ExpectCredentialsEqual(MountManager* mount_manager,
                            int32_t mount_id,
                            const std::string& root_path,
                            const std::string& workgroup,
                            const std::string& username,
                            const std::string& password) {
  DCHECK(mount_manager);

  constexpr size_t kComparisonBufferSize = 256;
  char workgroup_buffer[kComparisonBufferSize];
  char username_buffer[kComparisonBufferSize];
  char password_buffer[kComparisonBufferSize];

  SambaInterface* samba_interface;
  EXPECT_TRUE(mount_manager->GetSambaInterface(mount_id, &samba_interface));

  const SambaInterface::SambaInterfaceId samba_interface_id =
      samba_interface->GetSambaInterfaceId();

  EXPECT_TRUE(mount_manager->GetAuthentication(
      samba_interface_id, root_path, workgroup_buffer, kComparisonBufferSize,
      username_buffer, kComparisonBufferSize, password_buffer,
      kComparisonBufferSize));

  EXPECT_EQ(std::string(workgroup_buffer), workgroup);
  EXPECT_EQ(std::string(username_buffer), username);
  EXPECT_EQ(std::string(password_buffer), password);
}

std::vector<uint8_t> CreateNetBiosResponsePacket(
    const std::vector<std::vector<uint8_t>>& hostnames,
    uint8_t name_length,
    std::vector<uint8_t> name,
    uint16_t transaction_id,
    uint8_t response_type) {
  // Build the prefix of the packet.
  std::vector<uint8_t> packet = {0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

  // Set Transaction ID in Big Endian representation.
  packet[0] = transaction_id >> 8;
  packet[1] = transaction_id & 0xFF;

  // Add the name section.
  packet.push_back(name_length);
  packet.insert(packet.end(), name.begin(), name.end());

  // Add the next section
  std::vector<uint8_t> middle_section = {0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00};
  // Set the response_type.
  middle_section[2] = response_type;

  packet.insert(packet.end(), middle_section.begin(), middle_section.end());

  // Set number of address list entries.
  packet.push_back(hostnames.size());

  // Add the address list entries.
  for (const auto& hostname : hostnames) {
    packet.insert(packet.end(), hostname.begin(), hostname.end());
  }

  return packet;
}

std::vector<uint8_t> CreateNetBiosResponsePacket(
    const std::vector<std::vector<uint8_t>>& hostnames,
    std::vector<uint8_t> name,
    uint16_t transaction_id,
    uint8_t response_type) {
  return CreateNetBiosResponsePacket(hostnames, name.size(), name,
                                     transaction_id, response_type);
}

std::vector<uint8_t> CreateValidNetBiosHostname(const std::string& hostname,
                                                uint8_t type) {
  DCHECK_LE(hostname.size(), netbios::kServerNameLength);

  std::vector<uint8_t> hostname_bytes(netbios::kServerEntrySize);
  std::copy(hostname.begin(), hostname.end(), hostname_bytes.begin());

  // Fill the rest of the name with spaces.
  std::fill(hostname_bytes.begin() + hostname.size(),
            hostname_bytes.begin() + netbios::kServerNameLength, 0x20);

  // Set the type.
  hostname_bytes[15] = type;

  // Set two nulls for the flags.
  hostname_bytes[16] = 0x00;
  hostname_bytes[17] = 0x00;

  return hostname_bytes;
}

}  // namespace smbprovider
