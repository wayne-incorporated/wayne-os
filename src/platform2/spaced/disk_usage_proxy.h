// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SPACED_DISK_USAGE_PROXY_H_
#define SPACED_DISK_USAGE_PROXY_H_

#include <memory>

#include <base/files/file_path.h>
#include <base/functional/callback.h>
#include <base/observer_list.h>
#include <brillo/brillo_export.h>
#include <spaced/proto_bindings/spaced.pb.h>

#include "spaced/dbus-proxies.h"
#include "spaced/disk_usage.h"

namespace spaced {

class BRILLO_EXPORT SpacedObserverInterface : public base::CheckedObserver {
 public:
  ~SpacedObserverInterface() override = default;

  virtual void OnStatefulDiskSpaceUpdate(
      const StatefulDiskSpaceUpdate& update) = 0;
};

// Spaced returns negative value on internal errors. This is a wrapper of
// org::chromium::SpacedProxy converting DBus errors into negative value
// response and provides an unified interface.
class BRILLO_EXPORT DiskUsageProxy : public DiskUsageUtil {
 public:
  explicit DiskUsageProxy(
      std::unique_ptr<org::chromium::SpacedProxyInterface> spaced_proxy);
  ~DiskUsageProxy() override = default;

  static std::unique_ptr<DiskUsageProxy> Generate();

  int64_t GetFreeDiskSpace(const base::FilePath& path) override;
  void GetFreeDiskSpaceAsync(const base::FilePath& path,
                             base::OnceCallback<void(int64_t)> callback);
  int64_t GetTotalDiskSpace(const base::FilePath& path) override;
  int64_t GetRootDeviceSize() override;

  void OnStatefulDiskSpaceUpdate(const spaced::StatefulDiskSpaceUpdate& space);

  void AddObserver(SpacedObserverInterface* observer);
  void RemoveObserver(SpacedObserverInterface* observer);

  void StartMonitoring();

 private:
  std::unique_ptr<org::chromium::SpacedProxyInterface> spaced_proxy_;
  base::ObserverList<SpacedObserverInterface> observer_list_;
};

}  // namespace spaced

#endif  // SPACED_DISK_USAGE_PROXY_H_
