// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_CORE_DLC_DLC_CLIENT_H_
#define ML_CORE_DLC_DLC_CLIENT_H_

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <base/functional/callback.h>

namespace cros {

class DlcClient {
 public:
  // Factory function for creating DlcClients.
  static std::unique_ptr<DlcClient> Create(
      base::OnceCallback<void(const base::FilePath&)> dlc_root_path_cb,
      base::OnceCallback<void(const std::string&)> error_cb);
  // For Unit Tests, allow using a fixed path instead of DLC, eg
  // /build/share/ml_core
  static void SetDlcPathForTest(const base::FilePath* path);
  virtual void InstallDlc() = 0;
  virtual ~DlcClient() = default;
};

}  // namespace cros

#endif  // ML_CORE_DLC_DLC_CLIENT_H_
