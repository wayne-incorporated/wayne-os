// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROSLOG_CONSTANTS_H_
#define CROSLOG_CONSTANTS_H_

#include <array>
#include <string_view>

namespace croslog {

static constexpr std::array kLogSources{
    // Log files from rsyslog:
    // clang-format off
    std::string_view("/var/log/arc.log"),
    std::string_view("/var/log/boot.log"),
    std::string_view("/var/log/hammerd.log"),
    std::string_view("/var/log/messages"),
    std::string_view("/var/log/net.log"),
    std::string_view("/var/log/secure"),
    std::string_view("/var/log/upstart.log"),
    // clang-format on
};

static constexpr std::array kAuditLogSources{
    // Log files from auditd:
    // clang-format off
    std::string_view("/var/log/audit/audit.log"),
    // clang-format on
};
static constexpr std::array kLogsToRotate{
    // clang-format off
    std::string_view("/var/log/messages"),
    std::string_view("/var/log/secure"),
    std::string_view("/var/log/net.log"),
    std::string_view("/var/log/faillog"),
    std::string_view("/var/log/fwupd.log"),
    std::string_view("/var/log/session_manager"),
    std::string_view("/var/log/atrus.log"),
    std::string_view("/var/log/tlsdate.log"),
    std::string_view("/var/log/authpolicy.log"),
    std::string_view("/var/log/tpm-firmware-updater.log"),
    std::string_view("/var/log/arc.log"),
    std::string_view("/var/log/recover_duts/recover_duts.log"),
    std::string_view("/var/log/hammerd.log"),
    std::string_view("/var/log/upstart.log"),
    std::string_view("/var/log/typecd.log"),
    std::string_view("/var/log/bluetooth.log"),
    std::string_view("/var/log/hypervisor.log"),
    std::string_view("/var/log/secagentd.log"),
    // Log file for testing. On production, this file should not exist and
    // should just be ignored.
    std::string_view("/var/log/temporary_log_file_for_testing.log"),
    // clang-format on
};

}  // namespace croslog

#endif  // CROSLOG_CONSTANTS_H_
