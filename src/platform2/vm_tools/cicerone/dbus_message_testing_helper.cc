// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/cicerone/dbus_message_testing_helper.h"

namespace vm_tools {
namespace cicerone {

using ::testing::MakePolymorphicMatcher;
using ::testing::PolymorphicMatcher;

HasMethodNameMatcher::HasMethodNameMatcher(
    const std::string& expected_method_name)
    : expected_method_name_(expected_method_name) {}

HasMethodNameMatcher::HasMethodNameMatcher(const HasMethodNameMatcher& rhs) =
    default;
HasMethodNameMatcher::~HasMethodNameMatcher() = default;

bool HasMethodNameMatcher::MatchAndExplain(
    dbus::Message* message, testing::MatchResultListener* listener) const {
  *listener << "method name is " << message->GetMember();
  return message->GetMember() == expected_method_name_;
}

void HasMethodNameMatcher::DescribeTo(std::ostream* os) const {
  *os << "has method name " << expected_method_name_;
}

void HasMethodNameMatcher::DescribeNegationTo(std::ostream* os) const {
  *os << "does not have method name " << expected_method_name_;
}

PolymorphicMatcher<HasMethodNameMatcher> HasMethodName(
    const std::string& expected_method_name) {
  return MakePolymorphicMatcher(HasMethodNameMatcher(expected_method_name));
}

HasInterfaceNameMatcher::HasInterfaceNameMatcher(
    const std::string& expected_interface_name)
    : expected_interface_name_(expected_interface_name) {}

HasInterfaceNameMatcher::HasInterfaceNameMatcher(
    const HasInterfaceNameMatcher& rhs) = default;
HasInterfaceNameMatcher::~HasInterfaceNameMatcher() = default;

bool HasInterfaceNameMatcher::MatchAndExplain(
    dbus::Message* message, testing::MatchResultListener* listener) const {
  *listener << "interface name is " << message->GetInterface();
  return message->GetInterface() == expected_interface_name_;
}

void HasInterfaceNameMatcher::DescribeTo(std::ostream* os) const {
  *os << "has interface name " << expected_interface_name_;
}

void HasInterfaceNameMatcher::DescribeNegationTo(std::ostream* os) const {
  *os << "does not have interface name " << expected_interface_name_;
}

PolymorphicMatcher<HasInterfaceNameMatcher> HasInterfaceName(
    const std::string& expected_interface_name) {
  return MakePolymorphicMatcher(
      HasInterfaceNameMatcher(expected_interface_name));
}

}  // namespace cicerone
}  // namespace vm_tools
