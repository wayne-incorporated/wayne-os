// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include <stdlib.h>

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>

#include <algorithm>
#include <utility>
#include <vector>

#include "shill/logging.h"
#include "shill/net/io_handler_factory.h"
#include "shill/net/process_manager.h"
#include "shill/throttler.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kTC;
}  // namespace Logging

const char Throttler::kTCPath[] = "/sbin/tc";

const char* const Throttler::kTCCleanUpCmds[] = {
    "qdisc del dev ${INTERFACE} root\n",
    "qdisc del dev ${INTERFACE} ingress\n"};

// For fq_codel quantum 300 gives a boost to interactive flows
// Only works for bandwidths < 50 Mbps.
const char* const Throttler::kTCThrottleUplinkCmds[] = {
    "qdisc add dev ${INTERFACE} root handle 1: htb default 11\n",
    "class add dev ${INTERFACE} parent 1: classid 1:1 htb rate ${ULRATE}\n",
    ("class add dev ${INTERFACE} parent 1:1 classid 1:11 htb rate ${ULRATE} "
     "prio 0 quantum 300\n")};

const char* const Throttler::kTCThrottleDownlinkCmds[] = {
    "qdisc add dev ${INTERFACE} handle ffff: ingress\n",
    "filter add dev ${INTERFACE} parent ffff: protocol all "
    " prio 50 u32 match ip"
    " src 0.0.0.0/0 police rate ${DLRATE} burst ${BURST}k mtu 66000"
    " drop flowid :1\n"};

const char kTemplateInterface[] = "${INTERFACE}";
const char kTemplateULRate[] = "${ULRATE}";
const char kTemplateDLRate[] = "${DLRATE}";
const char kTemplateBurst[] = "${BURST}";

const char Throttler::kTCUser[] = "nobody";
const char Throttler::kTCGroup[] = "nobody";

Throttler::Throttler(EventDispatcher* dispatcher, Manager* manager)
    : file_io_(FileIO::GetInstance()),
      tc_stdin_(-1),
      tc_pid_(0),
      manager_(manager),
      io_handler_factory_(IOHandlerFactory::GetInstance()),
      process_manager_(ProcessManager::GetInstance()) {
  SLOG(2) << __func__;
}

Throttler::~Throttler() {
  SLOG(2) << __func__;
}

void Throttler::ClearTCState() {
  tc_pid_ = 0;
  tc_commands_.clear();
  tc_current_interface_.clear();
  tc_interfaces_to_throttle_.clear();
  callback_.Reset();
}

bool Throttler::DisableThrottlingOnAllInterfaces(ResultCallback callback) {
  bool result = false;

  std::vector<std::string> interfaces = manager_->GetDeviceInterfaceNames();
  std::vector<std::string> commands;

  for (const auto& interface_name : interfaces) {
    for (std::string command : kTCCleanUpCmds) {
      base::ReplaceSubstringsAfterOffset(&command, 0, kTemplateInterface,
                                         interface_name);
      commands.push_back(command);
    }
  }

  if (commands.empty()) {
    Done(std::move(callback), Error::kSuccess, "");
    ClearThrottleStatus();
    return true;
  }

  callback_ = std::move(callback);
  result = StartTCForCommands(commands);
  if (result) {
    ClearThrottleStatus();
  }
  return result;
}

void Throttler::Done(ResultCallback callback,
                     Error::Type error_type,
                     const std::string& message) {
  Error error(error_type, message, FROM_HERE);
  if (error_type != Error::kSuccess) {
    error.Log();
  }
  if (!callback.is_null()) {
    std::move(callback).Run(error);
    SLOG(4) << "ran callback";
  } else {
    SLOG(4) << "null callback";
  }
  ClearTCState();
  return;
}

bool Throttler::ThrottleInterfaces(ResultCallback callback,
                                   uint32_t upload_rate_kbits,
                                   uint32_t download_rate_kbits) {
  // At least one of upload/download should be throttled.
  // 0 value indicates no throttling.
  if ((upload_rate_kbits == 0) && (download_rate_kbits == 0)) {
    Done(std::move(callback), Error::kInvalidArguments,
         "One of download/upload rates should be set");
    return false;
  }

  tc_interfaces_to_throttle_ = manager_->GetDeviceInterfaceNames();

  std::string interface_name = GetNextInterface();

  if (interface_name.empty()) {
    Done(std::move(callback), Error::kOperationFailed,
         "No interfaces available for throttling");
    return false;
  }

  // Set state here, OnProcessExited will clear in case of failure
  desired_throttling_enabled_ = true;
  desired_upload_rate_kbits_ = upload_rate_kbits;
  desired_download_rate_kbits_ = download_rate_kbits;

  return Throttle(std::move(callback), interface_name, upload_rate_kbits,
                  download_rate_kbits);
}

bool Throttler::Throttle(ResultCallback callback,
                         const std::string& interface_name,
                         uint32_t upload_rate_kbits,
                         uint32_t download_rate_kbits) {
  SLOG(4) << __func__ << " : " << interface_name << "(" << upload_rate_kbits
          << ", " << download_rate_kbits << ")";

  if (tc_pid_ || !tc_commands_.empty() || !tc_current_interface_.empty()) {
    Done(std::move(callback), Error::kWrongState,
         "Cannot run concurrent TC operations");
    return false;
  }

  std::string throttle_file;
  std::vector<std::string> commands;

  // Easier to clean up first and start afresh than issue tc changes.
  for (std::string command : kTCCleanUpCmds) {
    base::ReplaceSubstringsAfterOffset(&command, 0, kTemplateInterface,
                                       interface_name);
    commands.push_back(command);
  }

  // Add commands for upload(egress) queueing disciplines
  // and filters
  if (upload_rate_kbits) {
    for (std::string command : kTCThrottleUplinkCmds) {
      std::string ulrate(base::NumberToString(upload_rate_kbits) + "kbit");
      base::ReplaceSubstringsAfterOffset(&command, 0, kTemplateInterface,
                                         interface_name);
      base::ReplaceSubstringsAfterOffset(&command, 0, kTemplateULRate, ulrate);
      commands.push_back(command);
    }
  }

  // Add commands for download(ingress) queueing disciplines
  // and filters
  if (download_rate_kbits) {
    for (std::string command : kTCThrottleDownlinkCmds) {
      std::string dlrate(base::NumberToString(download_rate_kbits) + "kbit");
      std::string to_burst(base::NumberToString(download_rate_kbits * 2));
      base::ReplaceSubstringsAfterOffset(&command, 0, kTemplateInterface,
                                         interface_name);
      base::ReplaceSubstringsAfterOffset(&command, 0, kTemplateDLRate, dlrate);
      base::ReplaceSubstringsAfterOffset(&command, 0, kTemplateBurst, to_burst);
      commands.push_back(command);
    }
  }
  callback_ = std::move(callback);
  tc_current_interface_ = interface_name;
  return StartTCForCommands(commands);
}

bool Throttler::ApplyThrottleToNewInterface(const std::string& interface_name) {
  if (!desired_throttling_enabled_) {
    // Nothing to do if no throttling is desired
    return false;
  }
  // An operation is currently in progress, append to list of interfaces
  if (tc_pid_ != 0) {
    tc_interfaces_to_throttle_.push_back(interface_name);
    return true;
  }
  // No operation currently in progress, start a new tc process
  return Throttle(base::DoNothing(), interface_name, desired_upload_rate_kbits_,
                  desired_download_rate_kbits_);
}

bool Throttler::StartTCForCommands(const std::vector<std::string>& commands) {
  CHECK_EQ(tc_pid_, 0);
  CHECK(!commands.empty());
  std::vector<std::string> args = {
      "-f",  // Continue if there is a failure or no-op
      "-b",  // Batch mode
      "-"    // Use stdin for input
  };

  ProcessManager::MinijailOptions minijail_options;
  minijail_options.user = kTCUser;
  minijail_options.group = kTCGroup;
  minijail_options.capmask = CAP_TO_MASK(CAP_NET_ADMIN);
  minijail_options.inherit_supplementary_groups = false;

  tc_commands_ = commands;
  // shill's stderr is wired to syslog, so nullptr for stderr
  // here implies throttling errors show up in /var/log/net.log.
  struct std_file_descriptors std_fds {
    &tc_stdin_, nullptr, nullptr
  };
  tc_pid_ = process_manager_->StartProcessInMinijailWithPipes(
      FROM_HERE, base::FilePath(kTCPath), args, {}, minijail_options,
      base::BindOnce(&Throttler::OnProcessExited, weak_factory_.GetWeakPtr()),
      std_fds);

  SLOG(1) << "Spawned tc with pid: " << tc_pid_;

  if (file_io_->SetFdNonBlocking(tc_stdin_)) {
    Done(std::move(callback_), Error::kOperationFailed,
         "Unable to set TC pipes to be non-blocking");
    return false;
  }
  tc_stdin_handler_.reset(io_handler_factory_->CreateIOReadyHandler(
      tc_stdin_, IOHandler::kModeOutput,
      base::BindRepeating(&Throttler::WriteTCCommands,
                          weak_factory_.GetWeakPtr())));
  return true;
}

void Throttler::WriteTCCommands(int fd) {
  CHECK_EQ(fd, tc_stdin_);
  CHECK(tc_pid_);

  for (const auto& command : tc_commands_) {
    SLOG(2) << "Issuing tc command: " << command;

    ssize_t bytes_written =
        file_io_->Write(tc_stdin_, command.data(), command.size());
    if (bytes_written != static_cast<ssize_t>(command.size())) {
      LOG(ERROR) << "Bytes written: " << bytes_written
                 << "v/s Command size: " << command.size();
    }
  }

  tc_stdin_handler_.reset();
  file_io_->Close(tc_stdin_);
  tc_stdin_ = -1;
  return;
}

void Throttler::ClearThrottleStatus() {
  desired_throttling_enabled_ = false;
  desired_upload_rate_kbits_ = 0;
  desired_download_rate_kbits_ = 0;
}

std::string Throttler::GetNextInterface() {
  std::string interface_name;
  if (!tc_interfaces_to_throttle_.empty()) {
    interface_name = tc_interfaces_to_throttle_.back();
    tc_interfaces_to_throttle_.pop_back();
  }
  return interface_name;
}

void Throttler::OnProcessExited(int exit_status) {
  CHECK(tc_pid_);
  CHECK(!tc_commands_.empty());
  // Should keep track of interface names if throttling, but not if disabling
  CHECK(!desired_throttling_enabled_ || !tc_current_interface_.empty());

  if (exit_status != EXIT_SUCCESS) {
    if (!desired_throttling_enabled_) {
      LOG(WARNING) << "Attempted to disable throttling when no throttles "
                   << "were applied";
    } else {
      LOG(ERROR) << "Throttler failed with status: " << exit_status;
    }
  }

  std::string next_interface = GetNextInterface();

  if (next_interface.empty()) {
    Done(std::move(callback_), Error::kSuccess, "");
  } else {
    SLOG(2) << "Done with " << tc_current_interface_ << " now calling "
            << next_interface;
    tc_pid_ = 0;
    tc_commands_.clear();
    tc_current_interface_.clear();
    Throttle(std::move(callback_), next_interface, desired_upload_rate_kbits_,
             desired_download_rate_kbits_);
  }
}

}  // namespace shill
