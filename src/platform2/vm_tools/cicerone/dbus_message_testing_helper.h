// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CICERONE_DBUS_MESSAGE_TESTING_HELPER_H_
#define VM_TOOLS_CICERONE_DBUS_MESSAGE_TESTING_HELPER_H_

#include <ostream>
#include <string>

#include <dbus/message.h>
#include <gmock/gmock.h>

namespace vm_tools {
namespace cicerone {

class HasMethodNameMatcher {
 public:
  explicit HasMethodNameMatcher(const std::string& expected_method_name);
  HasMethodNameMatcher(const HasMethodNameMatcher& rhs);
  ~HasMethodNameMatcher();
  bool MatchAndExplain(dbus::Message* message,
                       testing::MatchResultListener* listener) const;
  void DescribeTo(std::ostream* os) const;
  void DescribeNegationTo(std::ostream* os) const;

 private:
  std::string expected_method_name_;
};

// GMock matcher which matches dbus::Messages (or derived classes) with the
// given method name (a.k.a. member name).
testing::PolymorphicMatcher<HasMethodNameMatcher> HasMethodName(
    const std::string& expected_method_name);

class HasInterfaceNameMatcher {
 public:
  explicit HasInterfaceNameMatcher(const std::string& expected_interface_name);
  HasInterfaceNameMatcher(const HasInterfaceNameMatcher& rhs);
  ~HasInterfaceNameMatcher();
  bool MatchAndExplain(dbus::Message* message,
                       testing::MatchResultListener* listener) const;
  void DescribeTo(std::ostream* os) const;
  void DescribeNegationTo(std::ostream* os) const;

 private:
  std::string expected_interface_name_;
};

// GMock matcher which matches dbus::Messages (or derived classes) with the
// given interface name.
testing::PolymorphicMatcher<HasInterfaceNameMatcher> HasInterfaceName(
    const std::string& expected_interface_name);

}  // namespace cicerone
}  // namespace vm_tools

#endif  // VM_TOOLS_CICERONE_DBUS_MESSAGE_TESTING_HELPER_H_
