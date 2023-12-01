// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_SCREENS_SCREEN_DOWNLOAD_H_
#define MINIOS_SCREENS_SCREEN_DOWNLOAD_H_

#include <memory>
#include <string>

#include "minios/metrics_reporter.h"
#include "minios/recovery_installer.h"
#include "minios/screens/screen_base.h"
#include "minios/update_engine_proxy.h"

namespace minios {

class ScreenDownload : public UpdateEngineProxy::UpdaterDelegate,
                       public ScreenBase {
 public:
  ScreenDownload(std::unique_ptr<RecoveryInstallerInterface> recovery_installer,
                 std::shared_ptr<UpdateEngineProxy> update_engine_proxy,
                 std::shared_ptr<DrawInterface> draw_utils,
                 std::unique_ptr<MetricsReporterInterface> metrics_reporter,
                 ScreenControllerInterface* screen_controller);

  ~ScreenDownload() = default;

  ScreenDownload(const ScreenDownload&) = delete;
  ScreenDownload& operator=(const ScreenDownload&) = delete;

  void Show() override;
  void Reset() override;
  void OnKeyPress(int key_changed) override;
  ScreenType GetType() override;
  std::string GetName() override;

  void SetDisplayUpdateEngineStateForTest(bool display) {
    display_update_engine_state_ = display;
  }

 private:
  FRIEND_TEST(ScreenDownloadTest, UpdateEngineError);
  FRIEND_TEST(ScreenDownloadTest, UpdateEngineProgressComplete);
  FRIEND_TEST(ScreenDownloadTest, RepartitionDisk);
  FRIEND_TEST(ScreenDownloadTest, RepartitionDiskFailed);
  FRIEND_TEST(ScreenDownloadTest, StartUpdateFailed);
  FRIEND_TEST(ScreenDownloadTest, IdleError);
  FRIEND_TEST(ScreenDownloadTest, CheckingForUpdateToIdleError);
  FRIEND_TEST(ScreenDownloadTest, ShowUpdateProgress);

  // Updates buttons with current selection.
  void ShowButtons();

  // Calls reboot.
  void Completed();

  // Shown when in the process of verifying update.
  void Finalizing();

  // Begin repartitioning disk, wiping data, and calling update engine to start
  // installation.
  void StartRecovery();

  // Calls corresponding MiniOs screen based on update engine status. If UE is
  // `DOWNLOADING` then shows a progress bar with percentage.
  void OnProgressChanged(const update_engine::StatusResult& status) override;

  std::unique_ptr<RecoveryInstallerInterface> recovery_installer_;
  std::shared_ptr<UpdateEngineProxy> update_engine_proxy_;

  // Determines whether we want to display the update engine state changes to
  // the UI. Only necessary after user has entered their password and connected
  // to the network.
  bool display_update_engine_state_;

  // Used to keep track of the last seen Update Engine stage to prevent
  // unnecessary screen changes.
  update_engine::Operation previous_update_state_{
      update_engine::Operation::IDLE};

  // Used to report network-based recovery metrics.
  std::unique_ptr<MetricsReporterInterface> metrics_reporter_;
};

}  // namespace minios

#endif  // MINIOS_SCREENS_SCREEN_DOWNLOAD_H_
