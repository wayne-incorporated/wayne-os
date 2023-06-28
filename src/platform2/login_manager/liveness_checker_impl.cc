// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/liveness_checker_impl.h"

#include <signal.h>
#include <string>
#include <vector>

#include <base/bind.h>
#include <base/callback.h>
#include <base/cancelable_callback.h>
#include <base/compiler_specific.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/memory/weak_ptr.h>
#include <base/process/launch.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/time/time.h>
#include <brillo/message_loops/message_loop.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/message.h>
#include <dbus/object_proxy.h>

#include "login_manager/process_manager_service_interface.h"

namespace login_manager {

LivenessCheckerImpl::LivenessCheckerImpl(
    ProcessManagerServiceInterface* manager,
    dbus::ObjectProxy* dbus_proxy,
    bool enable_aborting,
    base::TimeDelta interval)
    : manager_(manager),
      dbus_proxy_(dbus_proxy),
      enable_aborting_(enable_aborting),
      interval_(interval) {}

LivenessCheckerImpl::~LivenessCheckerImpl() {
  Stop();
}

void LivenessCheckerImpl::Start() {
  Stop();  // To be certain.
  last_ping_acked_ = true;
  liveness_check_.Reset(
      base::Bind(&LivenessCheckerImpl::CheckAndSendLivenessPing,
                 weak_ptr_factory_.GetWeakPtr(), interval_));
  brillo::MessageLoop::current()->PostDelayedTask(
      FROM_HERE, liveness_check_.callback(), interval_);
}

void LivenessCheckerImpl::Stop() {
  weak_ptr_factory_.InvalidateWeakPtrs();
  liveness_check_.Cancel();
}

bool LivenessCheckerImpl::IsRunning() {
  return !liveness_check_.IsCancelled();
}

void LivenessCheckerImpl::DisableAborting() {
  enable_aborting_ = false;
}

void LivenessCheckerImpl::CheckAndSendLivenessPing(base::TimeDelta interval) {
  // If there's an un-acked ping, the browser needs to be taken down.
  if (!last_ping_acked_) {
    LOG(WARNING) << "Browser hang detected!";

    // TODO(https://crbug.com/883029): Remove.
    std::string top_output;
    base::GetAppOutput({"top", "-b", "-c", "-n1", "-w512"}, &top_output);

    std::vector<std::string> top_output_lines = base::SplitString(
        top_output, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
    if (top_output_lines.size() > 20)
      top_output_lines.resize(20);
    top_output = base::JoinString(top_output_lines, "\n");

    LOG(WARNING) << "Top output (trimmed):";
    LOG(WARNING) << top_output;

    if (enable_aborting_) {
      // Note: If this log message is changed, the desktopui_HangDetector
      // autotest must be updated.
      LOG(WARNING) << "Aborting browser process.";

      manager_->AbortBrowserForHang();
      // HandleChildExit() will reap the process and restart if needed.
      Stop();
      return;
    }
  }

  DVLOG(1) << "Sending a liveness ping to the browser.";
  last_ping_acked_ = false;
  dbus::MethodCall ping(chromeos::kLivenessServiceInterface,
                        chromeos::kLivenessServiceCheckLivenessMethod);
  dbus_proxy_->CallMethod(&ping, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT,
                          base::Bind(&LivenessCheckerImpl::HandleAck,
                                     weak_ptr_factory_.GetWeakPtr()));

  DVLOG(1) << "Scheduling liveness check in " << interval.InSeconds() << "s.";
  liveness_check_.Reset(
      base::Bind(&LivenessCheckerImpl::CheckAndSendLivenessPing,
                 weak_ptr_factory_.GetWeakPtr(), interval));
  brillo::MessageLoop::current()->PostDelayedTask(
      FROM_HERE, liveness_check_.callback(), interval);
}

void LivenessCheckerImpl::HandleAck(dbus::Response* response) {
  last_ping_acked_ = (response != nullptr);
}

}  // namespace login_manager
