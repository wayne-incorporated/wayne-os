// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "printscanmgr/executor/upstart_tools.h"

#include <memory>
#include <string>

#include <base/check.h>
#include <base/strings/stringprintf.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/object_path.h>
#include <dbus/object_proxy.h>

#include "printscanmgr/mojom/executor.mojom.h"

namespace printscanmgr {

namespace {

constexpr char kUpstartServiceName[] = "com.ubuntu.Upstart";
constexpr char kUpstartServicePath[] = "/com/ubuntu/Upstart";
constexpr char kUpstartJobInterface[] = "com.ubuntu.Upstart0_6.Job";
constexpr char kGetInstanceMethod[] = "GetInstance";
constexpr char kRestartMethod[] = "Restart";
constexpr char kStopMethod[] = "Stop";
constexpr char kUpstartJobPath[] = "/com/ubuntu/Upstart/jobs/";

std::string UpstartJobToString(mojom::UpstartJob job) {
  switch (job) {
    case mojom::UpstartJob::kCupsd:
      return "cupsd";
    case mojom::UpstartJob::kLorgnette:
      return "lorgnette";
  }
}

// Production implementation of UpstartTools.
class UpstartToolsImpl : public UpstartTools {
 public:
  explicit UpstartToolsImpl(const scoped_refptr<dbus::Bus>& bus) : bus_(bus) {
    upstart_proxy_ = bus_->GetObjectProxy(
        kUpstartServiceName, dbus::ObjectPath(kUpstartServicePath));
  }

  ~UpstartToolsImpl() override = default;

  bool IsJobRunning(mojom::UpstartJob job, std::string* error) override {
    return CallJobMethod(job, kGetInstanceMethod, error);
  }

  bool RestartJob(mojom::UpstartJob job, std::string* error) override {
    return CallJobMethod(job, kRestartMethod, error);
  }

  bool StopJob(mojom::UpstartJob job, std::string* error) override {
    if (!IsJobRunning(job, error)) {
      return true;
    }
    return CallJobMethod(job, kStopMethod, error);
  }

 private:
  bool CallJobMethod(mojom::UpstartJob job,
                     const std::string& method,
                     std::string* error) {
    DCHECK(error);

    std::string job_name = UpstartJobToString(job);
    dbus::ObjectProxy* job_proxy = bus_->GetObjectProxy(
        kUpstartServiceName, dbus::ObjectPath(kUpstartJobPath + job_name));
    if (job_proxy == nullptr) {
      *error = base::StringPrintf("Failed to get job proxy for %s.",
                                  job_name.c_str());
      return false;
    }
    dbus::MethodCall method_call(kUpstartJobInterface, method);
    dbus::MessageWriter writer(&method_call);
    writer.AppendBool(true /* wait for response */);
    std::unique_ptr<dbus::Response> method_response =
        job_proxy->CallMethodAndBlock(&method_call,
                                      dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
    if (!method_response) {
      *error = base::StringPrintf("%s job (%s) request had no response.",
                                  method.c_str(), job_name.c_str());
      return false;
    }
    dbus::MessageReader reader(method_response.get());
    dbus::ObjectPath job_path;
    if (!reader.PopObjectPath(&job_path)) {
      *error = base::StringPrintf("Failed to parse %s job (%s) response.",
                                  method.c_str(), job_name.c_str());
      return false;
    }
    return true;
  }

  scoped_refptr<dbus::Bus> bus_;
  dbus::ObjectProxy* upstart_proxy_;
};

}  // namespace

// static
std::unique_ptr<UpstartTools> UpstartTools::Create(
    const scoped_refptr<dbus::Bus>& bus) {
  return std::make_unique<UpstartToolsImpl>(bus);
}

}  // namespace printscanmgr
