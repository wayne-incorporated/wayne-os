// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_POWER_MANAGER_H_
#define SHILL_POWER_MANAGER_H_

// This class instantiates a PowerManagerProxy and distributes power events to
// registered users.  It also provides a means for calling methods on the
// PowerManagerProxy.

#include <memory>
#include <string>

#include <base/cancelable_callback.h>
#include <base/functional/callback.h>
#include <base/time/time.h>
#include <linux/nl80211.h>

#include "shill/power_manager_proxy_interface.h"

namespace shill {

class ControlInterface;

class PowerManager : public PowerManagerProxyDelegate {
 public:
  // This callback is called prior to a suspend attempt.  When it is OK for the
  // system to suspend, this callback should call ReportSuspendReadiness().
  using SuspendImminentCallback = base::RepeatingClosure;

  // This callback is called after the completion of a suspend attempt.  The
  // receiver should undo any pre-suspend work that was done by the
  // SuspendImminentCallback.
  // The receiver should be aware that it is possible to get a
  // SuspendDoneCallback while processing a DarkSuspendImminentCallback. So,
  // SuspendDoneCallback should be ready to run concurrently with (and in a
  // sense override) the actions taken by DarkSuspendImminentCallback.
  using SuspendDoneCallback = base::RepeatingClosure;

  // This callback is called at the beginning of a dark resume.
  // The receiver should arrange for ReportDarkSuspendImminentReadiness() to be
  // called when shill is ready to resuspend. In most cases,
  // ReportDarkSuspendImminentReadiness will be called asynchronously.
  using DarkSuspendImminentCallback = base::RepeatingClosure;

  // |control_itnerface| creates the PowerManagerProxy. Use a fake for testing.
  // Note: |Start| should be called to initialize this object before using it.
  explicit PowerManager(ControlInterface* control_interface);
  PowerManager(const PowerManager&) = delete;
  PowerManager& operator=(const PowerManager&) = delete;

  ~PowerManager() override;

  bool suspending() const { return suspending_; }
  bool in_dark_resume() const { return in_dark_resume_; }
  int64_t suspend_duration_us() const { return suspend_duration_us_; }

  // Starts the PowerManager: Registers a suspend delay with the power manager
  // for |suspend_delay|. See PowerManagerProxyInterface::RegisterSuspendDelay()
  // for information about |suspend_delay|.
  // - |imminent_callback| will be invoked when a suspend attempt is commenced
  // - |done_callback| will be invoked when the attempt is completed. Returns
  //   false on failure.
  // - This object guarantees that a call to |imminent_callback| is followed by
  //   a call to |done_callback| (before any more calls to |imminent_callback|).
  virtual void Start(
      base::TimeDelta suspend_delay,
      const SuspendImminentCallback& suspend_imminent_callback,
      const SuspendDoneCallback& suspend_done_callback,
      const DarkSuspendImminentCallback& dark_suspend_imminent_callback);
  virtual void Stop();

  // Report suspend readiness. If called when there is no suspend attempt
  // active, this function will fail. Returns true if sucessfully reported to
  // powerd.
  virtual bool ReportSuspendReadiness();

  // Report dark suspend readiness. See ReportSuspendReadiness for more details.
  virtual bool ReportDarkSuspendReadiness();

  // Record the wake reason for the current dark resume.
  bool RecordDarkResumeWakeReason(const std::string& wake_reason);

  virtual void ChangeRegDomain(nl80211_dfs_regions domain);

  // Methods inherited from PowerManagerProxyDelegate.
  void OnSuspendImminent(int suspend_id) override;
  void OnSuspendDone(int suspend_id, int64_t suspend_duration_us) override;
  void OnDarkSuspendImminent(int suspend_id) override;

 private:
  friend class ManagerTest;
  friend class PowerManagerTest;
  friend class ServiceTest;

  // Human-readable string describing the suspend delay that is registered
  // with the power manager.
  static const int kInvalidSuspendId;
  static const char kSuspendDelayDescription[];
  static const char kDarkSuspendDelayDescription[];
  static const int kSuspendTimeoutMilliseconds;

  // These functions track the power_manager daemon appearing/vanishing from the
  // DBus connection.
  void OnPowerManagerAppeared();
  void OnPowerManagerVanished();

  void NotifySuspendDone();

  ControlInterface* control_interface_;

  // The power manager proxy created by this class.  It dispatches the inherited
  // delegate methods of this object when changes in the power state occur.
  std::unique_ptr<PowerManagerProxyInterface> power_manager_proxy_;
  // The delay (in milliseconds) to request powerd to wait after a suspend
  // notification is received. powerd will actually suspend the system at least
  // |suspend_delay_| after the notification, if we do not
  // |ReportSuspendReadiness| earlier.
  base::TimeDelta suspend_delay_;
  // powerd tracks each (dark) suspend delay requested (by different clients)
  // using randomly generated unique |(dark)suspend_delay_id_|s.
  bool suspend_delay_registered_;
  int suspend_delay_id_;
  bool dark_suspend_delay_registered_;
  int dark_suspend_delay_id_;
  // Callbacks from shill called by this object when:
  // ... powerd notified us that a suspend is imminent.
  SuspendImminentCallback suspend_imminent_callback_;
  // ... powerd notified us that the suspend attempt has finished.
  SuspendDoneCallback suspend_done_callback_;
  // ... powerd notified us that a dark suspend is imminent. This means that we
  // just entered dark resume.
  DarkSuspendImminentCallback dark_suspend_imminent_callback_;

  // Set to true by OnSuspendImminent() and to false by OnSuspendDone().
  bool suspending_;
  // Set to true if readiness to suspend has been reported, i.e. any action to
  // perform before suspend has been completed.
  bool suspend_ready_;
  // Set to true if the suspend done callback should be deferred until after
  // any action to perform before suspend has been completed, i.e. when a
  // SuspendDone notification arrives before ReportSuspendReadiness() is
  // called.
  bool suspend_done_deferred_;
  // Set to true by OnDarkSuspendImminent() and to false by OnSuspendDone().
  bool in_dark_resume_;
  int current_suspend_id_;
  int current_dark_suspend_id_;

  // Set to time spent in suspended state during the last suspend in
  // OnSuspendDone() and reset to 0 by OnSuspendImminent()
  int64_t suspend_duration_us_;

  power_manager::WifiRegDomainDbus wifi_reg_domain_;
  bool wifi_reg_domain_is_set;
};

}  // namespace shill

#endif  // SHILL_POWER_MANAGER_H_
