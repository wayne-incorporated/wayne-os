// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/iptables.h"

namespace patchpanel {
namespace {
constexpr char kFilterTable[] = "filter";
constexpr char kMangleTable[] = "mangle";
constexpr char kNatTable[] = "nat";
}  // namespace

// static
std::string Iptables::TableName(Iptables::Table table) {
  switch (table) {
    case Table::kFilter:
      return kFilterTable;
    case Table::kMangle:
      return kMangleTable;
    case Table::kNat:
      return kNatTable;
  }
}

// static
std::string Iptables::CommandName(Iptables::Command command) {
  switch (command) {
    case Command::kA:
      return "-A";
    case Command::kD:
      return "-D";
    case Command::kF:
      return "-F";
    case Command::kI:
      return "-I";
    case Command::kL:
      return "-L";
    case Command::kN:
      return "-N";
    case Command::kS:
      return "-S";
    case Command::kX:
      return "-X";
  }
}

// static
std::optional<Iptables::Table> Iptables::TableFromName(
    const std::string& table) {
  if (table == "nat") {
    return Table::kNat;
  }
  if (table == "filter") {
    return Table::kFilter;
  }
  if (table == "mangle") {
    return Table::kMangle;
  }
  // The "raw" and "security" tables are not used in patchpanel.
  return std::nullopt;
}

// static
std::optional<Iptables::Command> Iptables::CommandFromName(
    const std::string& command) {
  if (command == "-A") {
    return Command::kA;
  } else if (command == "-D") {
    return Command::kD;
  } else if (command == "-F") {
    return Command::kF;
  } else if (command == "-I") {
    return Command::kI;
  } else if (command == "-L") {
    return Command::kL;
  } else if (command == "-N") {
    return Command::kN;
  } else if (command == "-S") {
    return Command::kS;
  } else if (command == "-X") {
    return Command::kX;
  }
  return std::nullopt;
}

std::ostream& operator<<(std::ostream& stream, Iptables::Table table) {
  return stream << Iptables::TableName(table);
}

std::ostream& operator<<(std::ostream& stream, Iptables::Command command) {
  return stream << Iptables::CommandName(command);
}

}  // namespace patchpanel
