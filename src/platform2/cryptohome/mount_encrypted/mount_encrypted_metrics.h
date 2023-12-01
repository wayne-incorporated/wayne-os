// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_MOUNT_ENCRYPTED_MOUNT_ENCRYPTED_METRICS_H_
#define CRYPTOHOME_MOUNT_ENCRYPTED_MOUNT_ENCRYPTED_METRICS_H_

#include <string>

#include <base/time/time.h>
#include <metrics/metrics_library.h>

#include "cryptohome/mount_encrypted/encryption_key.h"

namespace mount_encrypted {

// This class provides wrapping functions for callers to report UMAs of
// `mount_encrypted`.
class MountEncryptedMetrics {
 public:
  static void Initialize(const std::string& output_file);
  static MountEncryptedMetrics* Get();
  static void Reset();

  // Not copyable or movable.
  MountEncryptedMetrics(const MountEncryptedMetrics&) = delete;
  MountEncryptedMetrics& operator=(const MountEncryptedMetrics&) = delete;
  MountEncryptedMetrics(MountEncryptedMetrics&&) = delete;
  MountEncryptedMetrics& operator=(MountEncryptedMetrics&&) = delete;

  virtual ~MountEncryptedMetrics() = default;

  void ReportSystemKeyStatus(EncryptionKey::SystemKeyStatus status);

  void ReportEncryptionKeyStatus(EncryptionKey::EncryptionKeyStatus status);

  void ReportTimeToTakeTpmOwnership(base::TimeDelta elapsed_time);

 private:
  explicit MountEncryptedMetrics(const std::string& output_file);

  MetricsLibrary metrics_library_;
};

class ScopedMountEncryptedMetricsSingleton {
 public:
  explicit ScopedMountEncryptedMetricsSingleton(
      const std::string& output_file) {
    MountEncryptedMetrics::Initialize(output_file);
  }
  ~ScopedMountEncryptedMetricsSingleton() { MountEncryptedMetrics::Reset(); }
};

}  // namespace mount_encrypted

#endif  // CRYPTOHOME_MOUNT_ENCRYPTED_MOUNT_ENCRYPTED_METRICS_H_
