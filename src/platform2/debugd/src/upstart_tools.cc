// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/upstart_tools.h"

#include <utility>

#include <base/functional/callback_helpers.h>
#include <brillo/dbus/dbus_method_invoker.h>
#include <debugd/src/error_utils.h>
#include <dbus/message.h>
#include <dbus/object_proxy.h>

namespace debugd {

namespace {

constexpr char kUpstartToolsErrorString[] =
    "org.chromium.debugd.error.UpstartTools";

constexpr char kUpstartServiceName[] = "com.ubuntu.Upstart";
constexpr char kUpstartServicePath[] = "/com/ubuntu/Upstart";
constexpr char kUpstartJobInterface[] = "com.ubuntu.Upstart0_6.Job";
constexpr char kGetInstanceMethod[] = "GetInstance";
constexpr char kRestartMethod[] = "Restart";
constexpr char kStartMethod[] = "Start";
constexpr char kStopMethod[] = "Stop";
constexpr char kUpstartJobPath[] = "/com/ubuntu/Upstart/jobs/";

}  // namespace

UpstartToolsImpl::UpstartToolsImpl(const scoped_refptr<dbus::Bus>& bus)
    : bus_(bus) {
  upstart_proxy_ = bus_->GetObjectProxy(kUpstartServiceName,
                                        dbus::ObjectPath(kUpstartServicePath));
}

bool UpstartToolsImpl::IsJobRunning(const std::string& job_name,
                                    brillo::ErrorPtr* error) {
  return CallJobMethod(job_name, kGetInstanceMethod, {}, error);
}

bool UpstartToolsImpl::RestartJob(const std::string& job_name,
                                  brillo::ErrorPtr* error) {
  return CallJobMethod(job_name, kRestartMethod, {}, error);
}

bool UpstartToolsImpl::StartJob(const std::string& job_name,
                                brillo::ErrorPtr* error) {
  if (IsJobRunning(job_name, error)) {
    return true;
  }
  return CallJobMethod(job_name, kStartMethod, {}, error);
}

bool UpstartToolsImpl::StopJob(const std::string& job_name,
                               brillo::ErrorPtr* error) {
  if (!IsJobRunning(job_name, error)) {
    return true;
  }
  return CallJobMethod(job_name, kStopMethod, {}, error);
}

bool UpstartToolsImpl::CallJobMethod(
    const std::string& job_name,
    const std::string& method,
    const std::vector<std::string>& environment,
    brillo::ErrorPtr* error) {
  dbus::ObjectProxy* job_proxy = bus_->GetObjectProxy(
      kUpstartServiceName, dbus::ObjectPath(kUpstartJobPath + job_name));
  if (job_proxy == nullptr) {
    DEBUGD_ADD_ERROR_FMT(error, kUpstartToolsErrorString,
                         "Failed to get job proxy for %s", job_name.c_str());
    return false;
  }
  dbus::MethodCall method_call(kUpstartJobInterface, method);
  dbus::MessageWriter writer(&method_call);
  writer.AppendArrayOfStrings(environment);
  writer.AppendBool(true /* wait for response */);
  std::unique_ptr<dbus::Response> method_response =
      job_proxy->CallMethodAndBlock(&method_call,
                                    dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!method_response) {
    DEBUGD_ADD_ERROR_FMT(error, kUpstartToolsErrorString,
                         "%s job (%s) request had no response.", method.c_str(),
                         job_name.c_str());
    return false;
  }
  dbus::MessageReader reader(method_response.get());
  dbus::ObjectPath job_path;
  if (!reader.PopObjectPath(&job_path)) {
    DEBUGD_ADD_ERROR_FMT(error, kUpstartToolsErrorString,
                         "Failed to parse %s job (%s) response", method.c_str(),
                         job_name.c_str());
    return false;
  }
  return true;
}

}  // namespace debugd
