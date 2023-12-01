// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "init/usermode-helper.h"

#include <gtest/gtest.h>

#include <initializer_list>
#include <vector>

namespace {
// Convenience function.
bool ValidateProgramArgs(std::initializer_list<const char*> argv) {
  std::vector<const char*> vargv(argv);
  return usermode_helper::ValidateProgramArgs(argv.size(), vargv.data());
}
}  // namespace

TEST(ValidateProgramArgs, UnknownPrograms) {
  EXPECT_FALSE(ValidateProgramArgs({"/sbin/crash_reporter "}));
  EXPECT_FALSE(ValidateProgramArgs({"crash_reporter"}));
  EXPECT_FALSE(ValidateProgramArgs({"/bin/crash_reporter"}));
}

TEST(ValidateProgramArgs, GoodCrashReporter) {
  EXPECT_TRUE(ValidateProgramArgs({"/sbin/crash_reporter", "--user=foo"}));
  EXPECT_TRUE(ValidateProgramArgs(
      {"/sbin/crash_reporter", "--early", "--log_to_stderr", "--user=foo"}));
  EXPECT_TRUE(ValidateProgramArgs(
      {"/sbin/crash_reporter", "--user=foo", "--core2md_failure"}));
  EXPECT_TRUE(ValidateProgramArgs(
      {"/sbin/crash_reporter", "--user=foo", "--directory_failure"}));
  EXPECT_TRUE(ValidateProgramArgs(
      {"/sbin/crash_reporter", "--user=foo", "--crash_test"}));
}

TEST(ValidateProgramArgs, BadCrashReporter) {
  EXPECT_FALSE(ValidateProgramArgs({"/sbin/crash_reporter"}));
  EXPECT_FALSE(ValidateProgramArgs({"/sbin/crash_reporter", "--init"}));
  EXPECT_FALSE(ValidateProgramArgs(
      {"/sbin/crash_reporter", "--user=foo", "--filter_in=blah"}));
  EXPECT_FALSE(ValidateProgramArgs({"/sbin/crash_reporter", "--user=foo",
                                    "--filter_in=blah", "--core2md_failure"}));
}

TEST(ValidateProgramArgs, GoodModprobe) {
  EXPECT_TRUE(ValidateProgramArgs({"/sbin/modprobe", "-q", "--", "mod"}));
}

TEST(ValidateProgramArgs, BadModprobe) {
  EXPECT_FALSE(ValidateProgramArgs({"/sbin/modprobe"}));
  EXPECT_FALSE(ValidateProgramArgs({"/sbin/modprobe", "mod"}));
  EXPECT_FALSE(ValidateProgramArgs({"/sbin/modprobe", "-q"}));
  EXPECT_FALSE(ValidateProgramArgs({"/sbin/modprobe", "-q", "mod"}));
  EXPECT_FALSE(ValidateProgramArgs({"/sbin/modprobe", "-q", "--"}));
  EXPECT_FALSE(ValidateProgramArgs({"/sbin/modprobe", "--"}));
  EXPECT_FALSE(ValidateProgramArgs({"/sbin/modprobe", "--", "mod"}));
  EXPECT_FALSE(ValidateProgramArgs({"/sbin/modprobe", "-a", "mod1", "mod2"}));
  EXPECT_FALSE(ValidateProgramArgs({"/sbin/modprobe", "-r", "mod"}));
}

TEST(ValidateProgramArgs, GoodPoweroff) {
  EXPECT_TRUE(ValidateProgramArgs({"/sbin/poweroff"}));
}

TEST(ValidateProgramArgs, BadPoweroff) {
  EXPECT_FALSE(ValidateProgramArgs({"/sbin/poweroff", "-f"}));
}

TEST(ValidateProgramArgs, GoodReboot) {
  EXPECT_TRUE(ValidateProgramArgs({"/sbin/reboot"}));
}

TEST(ValidateProgramArgs, BadReboot) {
  EXPECT_FALSE(ValidateProgramArgs({"/sbin/reboot", "-f"}));
}

TEST(ValidateProgramArgs, GoodRequestKey) {
  EXPECT_TRUE(
      ValidateProgramArgs({"/sbin/request-key", "<op>", "<key>", "<uid>",
                           "<gid>", "<keyring>", "<keyring>", "<keyring>"}));
}

TEST(ValidateProgramArgs, RequestKey) {
  EXPECT_FALSE(
      ValidateProgramArgs({"/sbin/request-key", "<op>", "<key>", "<uid>",
                           "<gid>", "<keyring>", "<keyring>", "--option"}));
  EXPECT_FALSE(
      ValidateProgramArgs({"/sbin/request-key", "<op>", "<key>", "<uid>",
                           "<gid>", "<keyring>", "<keyring>"}));
  EXPECT_FALSE(ValidateProgramArgs({"/sbin/request-key", "<op>", "<key>",
                                    "<uid>", "<gid>", "<keyring>", "<keyring>",
                                    "<keyring>", "toomany"}));
}

TEST(ValidateProgramArgs, BridgeStp) {
  EXPECT_TRUE(ValidateProgramArgs({"/sbin/bridge-stp", "br-lan", "start"}));
  EXPECT_TRUE(ValidateProgramArgs({"/sbin/bridge-stp", "br-lan", "stop"}));
  EXPECT_FALSE(ValidateProgramArgs({"/sbin/bridge-stp", "br-lan"}));
  EXPECT_FALSE(
      ValidateProgramArgs({"/sbin/bridge-stp", "br-lan", "start", "toomany"}));
  EXPECT_FALSE(ValidateProgramArgs({"/sbin/bridge-stp", "start", "br-lan"}));
}
