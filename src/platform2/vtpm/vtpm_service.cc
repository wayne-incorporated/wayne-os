// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/vtpm_service.h"

#include <memory>
#include <string>
#include <utility>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <brillo/dbus/dbus_method_response.h>

#include "vtpm/vtpm_interface.pb.h"

namespace vtpm {

namespace {

// Makes a `SendCommandResponse` with `response` as the TPM response.
SendCommandResponse MakeResponseProto(const std::string& response) {
  SendCommandResponse response_proto;
  response_proto.set_response(response);
  return response_proto;
}

}  // namespace

VtpmService::VtpmService(Command* command) : command_(command) {
  CHECK(command_);
}

void VtpmService::SendCommand(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<SendCommandResponse>>
        response,
    const SendCommandRequest& request) {
  VLOG(1) << __func__;
  // Delegates the command execution to `command_`.
  command_->Run(request.command(),
                MakeCallingThreadCallback(std::move(response)));
}

void VtpmService::RunResponseCallback(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<SendCommandResponse>>
        response,
    const std::string& send_command_response) {
  response->Return(MakeResponseProto(send_command_response));
}

void VtpmService::PostResponseCallback(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<SendCommandResponse>>
        response,
    const std::string& send_command_response) {
  origin_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&VtpmService::RunResponseCallback, base::Unretained(this),
                     std::move(response), send_command_response));
}

CommandResponseCallback VtpmService::MakeCallingThreadCallback(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<SendCommandResponse>>
        response) {
  return base::BindOnce(&VtpmService::PostResponseCallback,
                        base::Unretained(this), std::move(response));
}

}  // namespace vtpm
