// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBPROVIDER_SMBPROVIDER_TEST_HELPER_H_
#define SMBPROVIDER_SMBPROVIDER_TEST_HELPER_H_

#include <memory>
#include <string>
#include <vector>

#include <base/files/file_util.h>
#include <kerberos/proto_bindings/kerberos_service.pb.h>

#include "smbprovider/mount_manager.h"
#include "smbprovider/proto.h"
#include "smbprovider/proto_bindings/directory_entry.pb.h"

namespace smbprovider {

constexpr char kTestCCacheName[] = "ccache";
constexpr char kTestKrb5ConfName[] = "krb5.conf";

struct MountConfig;
class TempFileManager;

GetSharesOptionsProto CreateGetSharesOptionsProto(
    const std::string& server_url);

// Writes the Credential Cache file contents `krb5cc` and the krb5.conf file
// contents `krb5conf` into a kerberos::KerberosFiles proto.
kerberos::KerberosFiles CreateKerberosFilesProto(const std::string& krb5cc,
                                                 const std::string& krb5conf);

ProtoBlob CreateGetSharesOptionsBlob(const std::string& server_url);

// FakeSamba URL helper methods.
inline std::string GetDefaultServer() {
  return "smb://wdshare";
}

inline std::string GetDefaultMountRoot() {
  return "smb://wdshare/test";
}

inline std::string GetDefaultDirectoryPath() {
  return "/path";
}

inline std::string GetDefaultFilePath() {
  return "/path/dog.jpg";
}

inline std::string GetDefaultFullPath(const std::string& relative_path) {
  return GetDefaultMountRoot() + relative_path;
}

inline std::string GetAddedFullDirectoryPath() {
  return GetDefaultMountRoot() + GetDefaultDirectoryPath();
}

inline std::string GetAddedFullFilePath() {
  return GetDefaultMountRoot() + GetDefaultFilePath();
}

// Writes |password| into a file using |temp_manager| with the format of
// "{password_length}{password}".
base::ScopedFD WritePasswordToFile(TempFileManager* temp_manager,
                                   const std::string& password);

std::string CreateKrb5ConfPath(const base::FilePath& temp_dir);

std::string CreateKrb5CCachePath(const base::FilePath& temp_dir);

// Expects that the file at |path| contains |expected_contents|.
void ExpectFileEqual(const std::string& path,
                     const std::string expected_contents);

// Expects that the file at |path| does not contain |expected_contents|.
void ExpectFileNotEqual(const std::string& path,
                        const std::string expected_contents);

// Expects that the credentials of the mount with |mount_id| are equal to the
// inputted credentials.
void ExpectCredentialsEqual(MountManager* mount_manager,
                            int32_t mount_id,
                            const std::string& root_path,
                            const std::string& workgroup,
                            const std::string& username,
                            const std::string& password);

// Creates a NetBios Name Query response packet. |hostnames| may contain well
// formed (18 byte) or malformed hostnames. For a well-formed packet,
// |name_length| must be equal to the length of |name|.
std::vector<uint8_t> CreateNetBiosResponsePacket(
    const std::vector<std::vector<uint8_t>>& hostnames,
    uint8_t name_length,
    std::vector<uint8_t> name,
    uint16_t transaction_id,
    uint8_t response_type);
std::vector<uint8_t> CreateNetBiosResponsePacket(
    const std::vector<std::vector<uint8_t>>& hostnames,
    std::vector<uint8_t> name,
    uint16_t transaction_id,
    uint8_t response_type);

// Creates a valid NetBios Hostname as a vector of bytes. |hostname_in| must be
// less than or equal to 15 bytes.
std::vector<uint8_t> CreateValidNetBiosHostname(const std::string& hostname,
                                                uint8_t type);

}  // namespace smbprovider

#endif  // SMBPROVIDER_SMBPROVIDER_TEST_HELPER_H_
