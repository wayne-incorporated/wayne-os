// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "modemfwd/logging.h"
#include "modemfwd/upstart_job_controller.h"

namespace modemfwd {

UpstartJobController::UpstartJobController(std::string upstart_service_name,
                                           std::string job_name,
                                           scoped_refptr<dbus::Bus> bus)
    : job_name_(job_name),
      upstart_proxy_(std::make_unique<com::ubuntu::Upstart0_6Proxy>(
          bus, upstart_service_name, dbus::ObjectPath("/com/ubuntu/Upstart"))),
      job_proxy_(std::make_unique<com::ubuntu::Upstart0_6::JobProxy>(
          bus, upstart_service_name, job_name_)),
      job_stopped_(false) {}

bool UpstartJobController::IsRunning() {
  if (!IsInstalled()) {
    return false;
  }
  std::vector<std::string> in_env;
  dbus::ObjectPath path;
  brillo::ErrorPtr error;
  if (!job_proxy_->GetInstance(in_env, &path, &error)) {
    if (error) {
      ELOG(INFO) << "Could not get job instance for "
                 << job_proxy_->GetObjectPath().value() << ": "
                 << error->GetMessage();
      return false;
    }
  }
  if (!path.IsValid())
    return false;
  ELOG(INFO) << "Found upstart job: " << path.value();
  return true;
}

bool UpstartJobController::IsInstalled() {
  std::vector<dbus::ObjectPath> jobs;
  brillo::ErrorPtr err;
  if (!upstart_proxy_->GetAllJobs(&jobs, &err)) {
    ELOG(INFO) << "Could not get list of jobs from upstart: "
               << err->GetMessage();
    return false;
  }
  for (auto job : jobs) {
    if (job == job_name_) {
      return true;
    }
  }
  return false;
}

bool UpstartJobController::Stop() {
  std::vector<std::string> in_env;
  brillo::ErrorPtr error;
  if (!IsRunning()) {
    return false;
  }
  ELOG(INFO) << "Stopping " << job_proxy_->GetObjectPath().value();
  job_proxy_->Stop(in_env, true /* in_wait */, &error);
  if (error) {
    ELOG(INFO) << "Could not stop" << job_proxy_->GetObjectPath().value()
               << ": " << error->GetMessage();
    return false;
  }
  job_stopped_ = true;
  return true;
}

bool UpstartJobController::Start() {
  return Start(std::vector<std::string>());
}

bool UpstartJobController::Start(std::vector<std::string> in_env) {
  brillo::ErrorPtr error;
  dbus::ObjectPath path;
  ELOG(INFO) << "Starting " << job_proxy_->GetObjectPath().value();
  job_proxy_->Start(in_env, true /* in_wait */, &path, &error);
  if (error) {
    ELOG(INFO) << "Could not start " << job_proxy_->GetObjectPath().value()
               << ": " << error->GetMessage();
    return false;
  }
  job_stopped_ = false;
  return true;
}

UpstartJobController::~UpstartJobController() {
  if (job_stopped_) {
    ELOG(INFO) << __func__ << ": " << job_proxy_->GetObjectPath().value()
               << " was stopped previously. Restarting";
    Start();
  }
}

}  // namespace modemfwd
