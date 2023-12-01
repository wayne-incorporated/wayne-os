// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_IPTABLES_H_
#define PATCHPANEL_IPTABLES_H_

#include <optional>
#include <ostream>
#include <string>

namespace patchpanel {

// Helper class for running iptables and ip6tables commands with
// MinijailedProcessRunner.
class Iptables {
 public:
  // Represents one of the predefined netfilter tables. The "raw" and "security"
  // tables are not used in patchpanel.
  enum class Table {
    kFilter,
    kMangle,
    kNat,
  };

  // Command that represents the specific action to perform in iptables.
  enum class Command {
    // Append
    kA,
    // Delete
    kD,
    // Flush
    kF,
    // Insert
    kI,
    // List
    kL,
    // New chain
    kN,
    // List rules
    kS,
    // Delete chain
    kX,
  };

  static std::string TableName(Table table);
  static std::string CommandName(Command command);
  static std::optional<Table> TableFromName(const std::string& table);
  static std::optional<Command> CommandFromName(const std::string& command);
};

std::ostream& operator<<(std::ostream& stream, Iptables::Table table);

std::ostream& operator<<(std::ostream& stream, Iptables::Command command);

}  // namespace patchpanel

#endif  // PATCHPANEL_IPTABLES_H_
