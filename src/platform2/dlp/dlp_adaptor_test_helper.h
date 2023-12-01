// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DLP_DLP_ADAPTOR_TEST_HELPER_H_
#define DLP_DLP_ADAPTOR_TEST_HELPER_H_

#include <memory>

#include <base/files/scoped_temp_dir.h>
#include <base/task/single_thread_task_executor.h>
#include <brillo/message_loops/base_message_loop.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_exported_object.h>
#include <dbus/mock_object_proxy.h>
#include <featured/fake_platform_features.h>

#include "dlp/dlp_adaptor.h"

namespace dlp {

class DlpAdaptorTestHelper {
 public:
  DlpAdaptorTestHelper();
  ~DlpAdaptorTestHelper();

  DlpAdaptorTestHelper(const DlpAdaptorTestHelper&) = delete;
  DlpAdaptorTestHelper& operator=(const DlpAdaptorTestHelper&) = delete;

  DlpAdaptor* adaptor() { return adaptor_.get(); }

  const base::FilePath& home_path() const { return home_dir_.GetPath(); }

  scoped_refptr<dbus::MockObjectProxy> mock_dlp_files_policy_service_proxy() {
    return mock_dlp_files_policy_service_proxy_;
  }

  scoped_refptr<dbus::MockObjectProxy> mock_session_manager_proxy() {
    return mock_session_manager_proxy_;
  }

  // Whether CrOSLateBootDlpDatabaseCleanupFeature is enabled.
  void SetDatabaseCleanupFeatureEnabled(bool enabled) {
    feature_lib_->SetEnabled("CrOSLateBootDlpDatabaseCleanupFeature", enabled);
  }

 private:
  scoped_refptr<dbus::MockBus> bus_;
  scoped_refptr<dbus::MockExportedObject> mock_exported_object_;
  scoped_refptr<dbus::MockObjectProxy> mock_dlp_files_policy_service_proxy_;
  scoped_refptr<dbus::MockObjectProxy> mock_session_manager_proxy_;

  std::unique_ptr<feature::FakePlatformFeatures> feature_lib_;

  base::ScopedTempDir home_dir_;
  std::unique_ptr<DlpAdaptor> adaptor_;

  base::SingleThreadTaskExecutor task_executor_{base::MessagePumpType::IO};
  brillo::BaseMessageLoop brillo_loop_{task_executor_.task_runner()};
};

}  // namespace dlp

#endif  // DLP_DLP_ADAPTOR_TEST_HELPER_H_
