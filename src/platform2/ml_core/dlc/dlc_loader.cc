// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml_core/dlc/dlc_loader.h"

#include <sysexits.h>
#include <string>

#include <base/logging.h>

namespace cros {

int DlcLoader::OnEventLoopStarted() {
  dlc_client_ = cros::DlcClient::Create(
      base::BindOnce(
          [](DlcLoader* loader, const base::FilePath& dlc_path) {
            LOG(INFO) << "DLC Installed";
            loader->dlc_root_path_ = dlc_path;
            loader->Quit();
          },
          base::Unretained(this)),
      base::BindOnce(
          [](DlcLoader* loader, const std::string& error_msg) {
            LOG(ERROR) << error_msg;
            loader->Quit();
          },
          base::Unretained(this)));
  dlc_client_->InstallDlc();
  return EX_OK;
}

bool DlcLoader::DlcLoaded() {
  return !dlc_root_path_.empty();
}

const base::FilePath& DlcLoader::GetDlcRootPath() {
  return dlc_root_path_;
}

}  // namespace cros
