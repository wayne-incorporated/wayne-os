// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DLCSERVICE_TEST_UTILS_H_
#define DLCSERVICE_TEST_UTILS_H_

#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/scoped_temp_dir.h>
#include <base/test/simple_test_clock.h>
#include <brillo/message_loops/fake_message_loop.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_object_proxy.h>
#include <dlcservice/proto_bindings/dlcservice.pb.h>
#include <imageloader/proto_bindings/imageloader.pb.h>
#include <imageloader/dbus-proxy-mocks.h>
#if USE_LVM_STATEFUL_PARTITION
#include <lvmd/proto_bindings/lvmd.pb.h>
// NOLINTNEXTLINE(build/include_alpha)
#include <lvmd/dbus-proxy-mocks.h>
#endif  // USE_LVM_STATEFUL_PARTITION
#include <update_engine/proto_bindings/update_engine.pb.h>
// NOLINTNEXTLINE(build/include_alpha)
#include <update_engine/dbus-proxy-mocks.h>

#include "dlcservice/boot/mock_boot_slot.h"
#include "dlcservice/dlc_base.h"
#include "dlcservice/dlc_service.h"
#include "dlcservice/mock_metrics.h"
#include "dlcservice/mock_state_change_reporter.h"
#include "dlcservice/mock_system_properties.h"
#if USE_LVM_STATEFUL_PARTITION
#include "dlcservice/lvm/mock_lvmd_proxy_wrapper.h"
#endif  // USE_LVM_STATEFUL_PARTITION

namespace dlcservice {

extern const char kFirstDlc[];
extern const char kSecondDlc[];
extern const char kThirdDlc[];
extern const char kFourthDlc[];
extern const char kScaledDlc[];
extern const char kPackage[];
extern const char kDefaultOmahaUrl[];

MATCHER_P3(CheckDlcStateProto, state, progress, root_path, "") {
  return arg.state() == state && arg.progress() == progress &&
         arg.root_path() == root_path;
};

MATCHER_P(CheckInstallRequest,
          install_request,
          "Matches the InstallRequest protobuf") {
  return arg.SerializeAsString() == install_request.SerializeAsString();
}

int64_t GetFileSize(const base::FilePath& path);

class BaseTest : public testing::Test {
 public:
  BaseTest();
  BaseTest(const BaseTest&) = delete;
  BaseTest& operator=(const BaseTest&) = delete;

  void SetUp() override;

  void SetUpFilesAndDirectories();

  // Will create |path|/|id|/|package|/dlc.img file. Will return the path to the
  // generated preloaded image.
  base::FilePath SetUpDlcPreloadedImage(const DlcId& id);

  // Will create |path|/|id|/|package|/dlc.img file. Will return the path to the
  // generated factory install image.
  base::FilePath SetUpDlcFactoryImage(const DlcId& id);

  // Will create |path/|id|/|package|/dlc_[a|b]/dlc.img files.
  void SetUpDlcWithSlots(const DlcId& id);

  // Mimics an installation form update_engine on the current boot slot.
  void InstallWithUpdateEngine(const std::vector<std::string>& ids);

  void SetMountPath(const std::string& mount_path_expected);

 protected:
  brillo::ErrorPtr err_;

  base::ScopedTempDir scoped_temp_dir_;

  base::FilePath testdata_path_;
  base::FilePath manifest_path_;
  base::FilePath preloaded_content_path_;
  base::FilePath factory_install_path_;
  base::FilePath content_path_;
  base::FilePath prefs_path_;
  base::FilePath users_path_;
  base::FilePath verification_file_path_;
  base::FilePath mount_path_;
  base::FilePath resume_in_progress_path_;

#if USE_LVM_STATEFUL_PARTITION
  std::unique_ptr<MockLvmdProxyWrapper> mock_lvmd_proxy_wrapper_;
  MockLvmdProxyWrapper* mock_lvmd_proxy_wrapper_ptr_;
#endif  // USE_LVM_STATEFUL_PARTITION

  using ImageLoaderProxyMock = org::chromium::ImageLoaderInterfaceProxyMock;
  std::unique_ptr<ImageLoaderProxyMock> mock_image_loader_proxy_;
  ImageLoaderProxyMock* mock_image_loader_proxy_ptr_;

  scoped_refptr<dbus::MockBus> mock_bus_;
  scoped_refptr<dbus::MockObjectProxy> mock_update_engine_object_proxy_;

  using UpdateEngineProxyMock = org::chromium::UpdateEngineInterfaceProxyMock;
  std::unique_ptr<UpdateEngineProxyMock> mock_update_engine_proxy_;
  UpdateEngineProxyMock* mock_update_engine_proxy_ptr_;

  std::unique_ptr<MockBootSlot> mock_boot_slot_;
  MockBootSlot* mock_boot_slot_ptr_;

  MockMetrics* mock_metrics_;
  MockSystemProperties* mock_system_properties_;
  MockStateChangeReporter mock_state_change_reporter_;

  base::SimpleTestClock clock_;
  brillo::FakeMessageLoop loop_{&clock_};

 private:
  base::FilePath SetUpImage(const base::FilePath& root, const DlcId& id);
};

}  // namespace dlcservice

#endif  // DLCSERVICE_TEST_UTILS_H_
