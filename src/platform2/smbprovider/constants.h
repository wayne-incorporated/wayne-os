// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBPROVIDER_CONSTANTS_H_
#define SMBPROVIDER_CONSTANTS_H_

#include <fcntl.h>    /* for file flags */
#include <stddef.h>   /* for size_t */
#include <sys/stat.h> /* for mode_t */

#include <cstdint>

namespace smbprovider {

// Buffer size used for reading a directory.
constexpr size_t kDirEntBufferSize = 1024 * 32;

// Number of microseconds to keep metadata in the cache.
constexpr uint64_t kMetadataCacheLifetimeMicroseconds = 30 * 1000 * 1000;

// Default number of entries at a time to buffer in directory iterators.
constexpr size_t kDefaultMetadataBatchSize = 512;

// Default flags for created files.
constexpr int kCreateFileFlags = O_CREAT | O_WRONLY | O_TRUNC | O_EXCL;

// Default permissions for created entries.
constexpr mode_t kCreateEntryPermissions = 0755;

// Windows/DOS file attribute for a directory.
constexpr uint16_t kFileAttributeDirectory = 0x10;

// Windows/DOS file attribute for a symlink.
constexpr uint16_t kFileAttributeReparsePoint = 0x400;

// SMB Url scheme
constexpr char kSmbUrlScheme[] = "smb://";

// MountId used to differentiate between an error case and a method that
// operates without a mount.
constexpr int32_t kInternalMountId = -2;

// Initial number of entries to send during read directory. This number is
// smaller than kReadDirectoryMaxBatchSize since we want the initial page to
// load as quickly as possible.
constexpr uint32_t kReadDirectoryInitialBatchSize = 64;

// Maximum number of entries to send at a time for read directory.
constexpr uint32_t kReadDirectoryMaxBatchSize = 2048;

// Initial ID value for the IdMap of file descriptors.
constexpr uint32_t kInitialFileDescriptorId = 1;

// Initial ID value for the IdMap of mount IDs.
constexpr uint32_t kInitialMountId = 0;

// Entries returned by smbc_getdents() that we ignore.
extern const char kEntryParent[];
extern const char kEntrySelf[];

// $HOME environment variable.
extern const char kHomeEnvironmentVariable[];
// Set as $HOME in order for libsmbclient to read smb.conf file.
extern const char kSmbProviderHome[];

// Location and file name for smb configuration file.
extern const char kSmbConfLocation[];
extern const char kSmbConfFile[];

// Data for smb config file.
extern const char kSmbConfData[];

// Environment variables for Kerberos.
extern const char kKrb5ConfigEnvironmentVariable[];
extern const char kKrb5CCNameEnvironmentVariable[];
extern const char kKrb5TraceEnvironmentVariable[];

// Location and file name for krb5 configuration file.
extern const char kKrb5ConfLocation[];
extern const char kKrb5ConfFile[];

// Location and file name for credential cache file.
extern const char kCCacheLocation[];
extern const char kCCacheFile[];

// Location and file name for the Kerberos trace file.
extern const char kKrbTraceLocation[];
extern const char kKrbTraceFile[];

}  // namespace smbprovider

#endif  // SMBPROVIDER_CONSTANTS_H_
