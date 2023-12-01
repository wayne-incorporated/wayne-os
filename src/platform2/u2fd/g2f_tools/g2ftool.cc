// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sysexits.h>

#include <algorithm>
#include <iostream>
#include <memory>
#include <optional>
#include <string>

#include <base/command_line.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

#include "u2fd/g2f_tools/g2f_client.h"

int main(int argc, char* argv[]) {
  DEFINE_bool(syslog, false, "also log to syslog");
  DEFINE_string(dev, "", "path to G2F device");
  DEFINE_bool(ping, false, "{action} ping device");
  DEFINE_bool(raw, false, "{action} send raw HID command");
  DEFINE_bool(msg, false, "{action} send U2F message");
  DEFINE_bool(wink, false, "{action} wink");
  DEFINE_bool(reg, false, "{action} send U2F_REGISTER message");
  DEFINE_bool(auth, false, "{action} send U2F_AUTHENTICATE message");
  DEFINE_bool(lock, false, "lock channel before action");
  DEFINE_int32(ping_size, 10, "size of ping data");
  DEFINE_int32(lock_timeout, 10, "lock_timeout in seconds [0..10]");
  DEFINE_string(payload, "", "request payload bytes (hex) for --raw or --msg");
  DEFINE_int32(cc, -1, "command code to send for --raw");
  DEFINE_int32(p1, -1, "P1 value to send for --reg or --auth, -1 for default");
  DEFINE_string(challenge, "", "challenge parameter for --reg or --auth");
  DEFINE_string(application, "", "application parameter for --reg or --auth");
  DEFINE_string(key_handle, "", "key handle parameter for --auth");
  DEFINE_bool(g2f, false, "use fixed G2F attestation key for --reg");
  DEFINE_int32(v, 0, "verbosity level (up to 3)");

  brillo::FlagHelper::Init(argc, argv, "g2ftool - G2F testing tool");

  int log_flags = brillo::kLogToStderrIfTty;
  if (FLAGS_syslog) {
    log_flags |= brillo::kLogToSyslog;
  }
  brillo::InitLog(log_flags);

  if (FLAGS_dev.empty()) {
    LOG(ERROR) << "Must provide a non-empty device";
    return EX_USAGE;
  }

  g2f_client::HidDevice hid_device(FLAGS_dev);
  g2f_client::U2FHid u2f_hid(&hid_device);
  g2f_client::U2F u2f(&u2f_hid);

  const std::vector<bool> actions = {FLAGS_ping, FLAGS_wink, FLAGS_raw,
                                     FLAGS_msg,  FLAGS_reg,  FLAGS_auth};
  if (std::count(actions.cbegin(), actions.cend(), true) != 1) {
    LOG(ERROR) << "Must specify exactly one action";
    return EX_USAGE;
  }

  if (FLAGS_lock) {
    if (FLAGS_lock_timeout < 0 || FLAGS_lock_timeout > 10) {
      LOG(ERROR) << "Lock timeout must be in [0..10]";
      return EX_USAGE;
    }
    if (!u2f_hid.Lock(static_cast<uint8_t>(FLAGS_lock_timeout))) {
      return EX_SOFTWARE;
    }
    std::cout << "Locked for " << FLAGS_lock_timeout << " seconds."
              << std::endl;
  }

  if (FLAGS_ping) {
    if (!u2f_hid.Ping(FLAGS_ping_size)) {
      return EX_SOFTWARE;
    }
    std::cout << "Ping success." << std::endl;
  } else if (FLAGS_wink) {
    if (!u2f_hid.Wink()) {
      return EX_SOFTWARE;
    }
    std::cout << "Wink success." << std::endl;
  } else if (FLAGS_raw) {
    if (!u2f_hid.Init(false /* force_realloc */)) {
      return EX_SOFTWARE;
    }
    g2f_client::U2FHid::Command request;
    if (!FLAGS_payload.empty() &&
        !base::HexStringToBytes(FLAGS_payload, &request.payload)) {
      LOG(ERROR) << "Failed to convert --payload to bytes";
      return EX_USAGE;
    }
    if (FLAGS_cc < 0 || FLAGS_cc > 0xFF) {
      LOG(ERROR) << "Must provide --cc in [0..255]";
      return EX_USAGE;
    }
    request.cmd = static_cast<uint8_t>(FLAGS_cc);
    g2f_client::U2FHid::Command response;
    if (!u2f_hid.RawCommand(request, &response)) {
      return EX_SOFTWARE;
    }
    std::cout << response.FullDump() << std::endl;
  } else if (FLAGS_msg) {
    brillo::Blob request;
    if (!FLAGS_payload.empty() &&
        !base::HexStringToBytes(FLAGS_payload, &request)) {
      LOG(ERROR) << "Failed to convert --payload to bytes";
      return EX_USAGE;
    }
    brillo::Blob response;
    if (!u2f_hid.Msg(request, &response)) {
      return EX_SOFTWARE;
    }
    std::cout << base::HexEncode(response.data(), response.size()) << std::endl;
  } else if (FLAGS_reg) {
    if (FLAGS_p1 < -1 || FLAGS_p1 > 255) {
      LOG(ERROR) << "P1 value should be 0-255, or -1 for default" << std::endl;
      return EX_USAGE;
    }
    std::optional<uint8_t> p1;
    if (FLAGS_p1 > -1) {
      p1 = FLAGS_p1;
    }
    brillo::Blob challenge;
    if (!FLAGS_challenge.empty() &&
        !base::HexStringToBytes(FLAGS_challenge, &challenge)) {
      LOG(ERROR) << "Failed to convert --reg_challenge to bytes" << std::endl;
      return EX_USAGE;
    }
    brillo::Blob application;
    if (!FLAGS_application.empty() &&
        !base::HexStringToBytes(FLAGS_application, &application)) {
      std::cout << "Failed to convert --reg_application to bytes" << std::endl;
      return EX_USAGE;
    }
    brillo::Blob public_key;
    brillo::Blob key_handle;
    brillo::Blob certificate_and_signature;
    if (!u2f.Register(p1, challenge, application, FLAGS_g2f, &public_key,
                      &key_handle, &certificate_and_signature)) {
      return EX_SOFTWARE;
    }
    std::cout << "public_key="
              << base::HexEncode(public_key.data(), public_key.size())
              << std::endl
              << "key_handle="
              << base::HexEncode(key_handle.data(), key_handle.size())
              << std::endl
              << "certificate_and_signature="
              << base::HexEncode(certificate_and_signature.data(),
                                 certificate_and_signature.size())
              << std::endl;
  } else if (FLAGS_auth) {
    if (FLAGS_p1 < -1 || FLAGS_p1 > 255) {
      LOG(ERROR) << "P1 value should be 0-255, or -1 for default" << std::endl;
      return EX_USAGE;
    }
    std::optional<uint8_t> p1;
    if (FLAGS_p1 > -1) {
      p1 = FLAGS_p1;
    }
    brillo::Blob challenge;
    if (!FLAGS_challenge.empty() &&
        !base::HexStringToBytes(FLAGS_challenge, &challenge)) {
      std::cout << "Failed to convert --challenge to bytes" << std::endl;
      return EX_USAGE;
    }
    brillo::Blob application;
    if (!FLAGS_application.empty() &&
        !base::HexStringToBytes(FLAGS_application, &application)) {
      std::cout << "Failed to convert --application to bytes" << std::endl;
      return EX_USAGE;
    }
    brillo::Blob key_handle;
    if (!FLAGS_key_handle.empty() &&
        !base::HexStringToBytes(FLAGS_key_handle, &key_handle)) {
      std::cout << "Failed to convert --key_handle to bytes" << std::endl;
      return EX_USAGE;
    }
    bool presence_verified;
    brillo::Blob counter;
    brillo::Blob signature;
    if (!u2f.Authenticate(p1, challenge, application, key_handle,
                          &presence_verified, &counter, &signature)) {
      return EX_SOFTWARE;
    }
    std::cout << "presence_verified=" << presence_verified << std::endl
              << "counter=" << base::HexEncode(counter.data(), counter.size())
              << std::endl
              << "signature="
              << base::HexEncode(signature.data(), signature.size())
              << std::endl;
  }

  return EX_OK;
}
