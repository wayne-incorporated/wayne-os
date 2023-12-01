// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/trunks_dbus_proxy.h"

#include <memory>
#include <utility>

#include <absl/strings/str_format.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <libhwsec-foundation/tpm_error/tpm_error_data.h>
#include <libhwsec-foundation/tpm_error/tpm_error_uma_reporter_impl.h>

#include "trunks/command_codes.h"
#include "trunks/dbus_interface.h"
#include "trunks/error_codes.h"
#include "trunks/trunks_interface.pb.h"

namespace {

// Use a five minute timeout because some commands on some TPM hardware can take
// a very long time. If a few lengthy operations are already in the queue, a
// subsequent command needs to wait for all of them. Timeouts are always
// possible but under normal conditions 5 minutes seems to be plenty.
const int kDBusMaxTimeout = 5 * 60 * 1000;

}  // namespace

namespace trunks {

TrunksDBusProxy::TrunksDBusProxy()
    : TrunksDBusProxy(kTrunksServiceName,
                      kTrunksServicePath,
                      kTrunksInterface,
                      /*bus=*/nullptr) {}

TrunksDBusProxy::TrunksDBusProxy(scoped_refptr<dbus::Bus> bus)
    : TrunksDBusProxy(
          kTrunksServiceName, kTrunksServicePath, kTrunksInterface, bus) {}

TrunksDBusProxy::TrunksDBusProxy(const std::string& name,
                                 const std::string& path,
                                 const std::string& interface)
    : TrunksDBusProxy(name, path, interface, /*bus=*/nullptr) {}

TrunksDBusProxy::TrunksDBusProxy(const std::string& name,
                                 const std::string& path,
                                 const std::string& interface,
                                 scoped_refptr<dbus::Bus> bus)
    : dbus_name_(name),
      dbus_path_(path),
      dbus_interface_(interface),
      bus_(bus),
      uma_reporter_(
          std::make_unique<hwsec_foundation::TpmErrorUmaReporterImpl>()) {}

TrunksDBusProxy::~TrunksDBusProxy() {
  if (bus_) {
    bus_->ShutdownAndBlock();
  }
}

bool TrunksDBusProxy::Init() {
  origin_thread_id_ = base::PlatformThread::CurrentId();
  if (!bus_) {
    dbus::Bus::Options options;
    options.bus_type = dbus::Bus::SYSTEM;
    bus_ = new dbus::Bus(options);
  }
  if (!bus_->Connect()) {
    return false;
  }
  if (!object_proxy_) {
    object_proxy_ =
        bus_->GetObjectProxy(dbus_name_, dbus::ObjectPath(dbus_path_));
    if (!object_proxy_) {
      return false;
    }
  }
  base::TimeTicks deadline = base::TimeTicks::Now() + init_timeout_;
  while (!IsServiceReady(false /* force_check */) &&
         base::TimeTicks::Now() < deadline) {
    base::PlatformThread::Sleep(init_attempt_delay_);
  }
  return IsServiceReady(false /* force_check */);
}

bool TrunksDBusProxy::IsServiceReady(bool force_check) {
  if (!service_ready_ || force_check) {
    service_ready_ = CheckIfServiceReady();
  }
  return service_ready_;
}

bool TrunksDBusProxy::CheckIfServiceReady() {
  if (!bus_ || !object_proxy_) {
    return false;
  }
  std::string owner = bus_->GetServiceOwnerAndBlock(trunks::kTrunksServiceName,
                                                    dbus::Bus::SUPPRESS_ERRORS);
  return !owner.empty();
}

void TrunksDBusProxy::SendCommand(const std::string& command,
                                  ResponseCallback callback) {
  ResponseCallback metrics_callback =
      base::BindOnce(&TrunksDBusProxy::ReportMetricsCallback, GetWeakPtr(),
                     std::move(callback), command);
  SendCommandInternal(command, std::move(metrics_callback));
}

void TrunksDBusProxy::SendCommandInternal(const std::string& command,
                                          ResponseCallback callback) {
  if (origin_thread_id_ != base::PlatformThread::CurrentId()) {
    LOG(ERROR) << "Error TrunksDBusProxy cannot be shared by multiple threads.";
    std::move(callback).Run(CreateErrorResponse(TRUNKS_RC_IPC_ERROR));
    return;
  }
  if (!IsServiceReady(false /* force_check */)) {
    LOG(ERROR) << "Error TrunksDBusProxy cannot connect to trunksd.";
    std::move(callback).Run(CreateErrorResponse(SAPI_RC_NO_CONNECTION));
    return;
  }
  std::pair<ResponseCallback, ResponseCallback> split =
      base::SplitOnceCallback(std::move(callback));
  SendCommandRequest tpm_command_proto;
  tpm_command_proto.set_command(command);
  auto on_success = base::BindOnce(
      [](ResponseCallback callback, const SendCommandResponse& response) {
        std::move(callback).Run(response.response());
      },
      std::move(split.first));
  brillo::dbus_utils::CallMethodWithTimeout(
      kDBusMaxTimeout, object_proxy_, dbus_interface_, trunks::kSendCommand,
      std::move(on_success),
      base::BindOnce(&TrunksDBusProxy::OnError, GetWeakPtr(),
                     std::move(split.second)),
      tpm_command_proto);
}

void TrunksDBusProxy::OnError(ResponseCallback callback, brillo::Error* error) {
  TPM_RC error_code = IsServiceReady(true /* force_check */)
                          ? SAPI_RC_NO_RESPONSE_RECEIVED
                          : SAPI_RC_NO_CONNECTION;
  std::move(callback).Run(CreateErrorResponse(error_code));
}

std::string TrunksDBusProxy::SendCommandAndWait(const std::string& command) {
  std::string response = SendCommandAndWaitInternal(command);
  ReportMetrics(command, response);
  return response;
}

std::string TrunksDBusProxy::SendCommandAndWaitInternal(
    const std::string& command) {
  if (origin_thread_id_ != base::PlatformThread::CurrentId()) {
    LOG(ERROR) << "Error TrunksDBusProxy cannot be shared by multiple threads.";
    return CreateErrorResponse(TRUNKS_RC_IPC_ERROR);
  }
  if (!IsServiceReady(false /* force_check */)) {
    LOG(ERROR) << "Error TrunksDBusProxy cannot connect to trunksd.";
    return CreateErrorResponse(SAPI_RC_NO_CONNECTION);
  }
  SendCommandRequest tpm_command_proto;
  tpm_command_proto.set_command(command);
  brillo::ErrorPtr error;
  std::unique_ptr<dbus::Response> dbus_response =
      brillo::dbus_utils::CallMethodAndBlockWithTimeout(
          kDBusMaxTimeout, object_proxy_, dbus_interface_, trunks::kSendCommand,
          &error, tpm_command_proto);
  SendCommandResponse tpm_response_proto;
  if (dbus_response.get() &&
      brillo::dbus_utils::ExtractMethodCallResults(dbus_response.get(), &error,
                                                   &tpm_response_proto)) {
    return tpm_response_proto.response();
  } else {
    LOG(ERROR) << "TrunksProxy could not parse response: "
               << error->GetMessage();
    TPM_RC error_code;
    if (!IsServiceReady(true /* force_check */)) {
      error_code = SAPI_RC_NO_CONNECTION;
    } else if (dbus_response == nullptr) {
      error_code = SAPI_RC_NO_RESPONSE_RECEIVED;
    } else {
      error_code = SAPI_RC_MALFORMED_RESPONSE;
    }
    return CreateErrorResponse(error_code);
  }
}

void TrunksDBusProxy::ReportMetrics(const std::string& command,
                                    const std::string& response) {
  TPM_CC cc;
  TPM_RC parse_rc = GetCommandCode(command, cc);
  if (parse_rc != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": failed to parse command code: "
               << GetErrorString(parse_rc);
    return;
  }
  if (!IsGenericTpmCommand(cc)) {
    return;
  }
  TPM_RC rc;
  parse_rc = GetResponseCode(response, rc);
  if (parse_rc != TPM_RC_SUCCESS) {
    LOG(WARNING) << __func__ << ": failed to parse response code: "
                 << GetErrorString(parse_rc);
    rc = TRUNKS_RC_PARSE_ERROR;
  }
  std::string message =
      absl::StrFormat("command = 0x%04x (%s), response = 0x%04x (%s)", cc,
                      GetCommandString(cc), rc, GetErrorString(rc));
  VLOG(1) << __func__ << ": " << message;
  TpmErrorData error_data{cc, GetFormatOneError(rc)};
  if (!uma_reporter_->ReportTpm2CommandAndResponse(error_data)) {
    LOG(WARNING) << __func__
                 << ": failed to report tpm2 command and response: " << message;
  }
}

void TrunksDBusProxy::ReportMetricsCallback(ResponseCallback callback,
                                            const std::string& command,
                                            const std::string& response) {
  ReportMetrics(command, response);
  std::move(callback).Run(response);
}

}  // namespace trunks
