// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Bluetooth helper to detect USB disconnect events on bluetooth controller.
// Such an event indicates a low-level transport error or a controller failure
// that caused it to remove itself from the bus.

#include <iostream>
#include <unistd.h>
#include <vector>

#include <base/files/file_util.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <re2/re2.h>

namespace {

constexpr char kBtIdentifierRegex[] = "usb(.*)bluetooth";
constexpr char kLogCommand[] = "croslog";

std::vector<std::string> GetBtUsbIdentifiers() {
  const base::FilePath symbolic_hci_path("/sys/class/bluetooth/hci0");
  base::FilePath resolved_path;
  std::string matched_value;
  std::vector<std::string> entries;

  if (!base::PathExists(symbolic_hci_path) || !base::IsLink(symbolic_hci_path))
    return entries;

  if (!base::ReadSymbolicLink(symbolic_hci_path, &resolved_path))
    return entries;

  if (!RE2::PartialMatch(resolved_path.MaybeAsASCII(), kBtIdentifierRegex,
                         &matched_value))
    return entries;

  entries = base::SplitString(matched_value, "/", base::KEEP_WHITESPACE,
                              base::SPLIT_WANT_NONEMPTY);

  return entries;
}

int LocateUsbDisconnects() {
  std::vector<std::string> identifiers = GetBtUsbIdentifiers();

  if (identifiers.empty())
    return 0;

  // A USB disconnect event will show up in the logs with the format:
  // "usb 1-3: USB disconnect", but there are more than one identifier that may
  // match to the bluetooth device. Here, we construct a grep string to pass to
  // croslog to locate any relevant USB disconnect events.
  std::string grep_string =
      "--grep=usb (" + base::JoinString(identifiers, "|") + "): USB disconnect";

  return execlp(kLogCommand, kLogCommand, "--show-cursor=false", "--boot",
                grep_string.c_str(), nullptr);
}

}  // namespace

int main() {
  return LocateUsbDisconnects();
}
