// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "permission_broker/rule_engine.h"

#include <libudev.h>
#include <poll.h>
#include <sys/inotify.h>

#include "permission_broker/rule.h"

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>

namespace permission_broker {

RuleEngine::RuleEngine() : udev_(udev_new()) {}

RuleEngine::RuleEngine(const std::string& udev_run_path,
                       const base::TimeDelta& poll_interval)
    : udev_(udev_new()),
      poll_interval_(poll_interval),
      udev_run_path_(udev_run_path) {
  CHECK(udev_) << "Could not create udev context, is sysfs mounted?";
}

RuleEngine::~RuleEngine() {}

void RuleEngine::AddRule(Rule* rule) {
  CHECK(rule) << "Cannot add NULL as a rule.";
  rules_.push_back(std::unique_ptr<Rule>(rule));
}

Rule::Result RuleEngine::ProcessPath(const std::string& path) {
  WaitForEmptyUdevQueue();

  LOG(INFO) << "ProcessPath(" << path << ")";
  Rule::Result result = Rule::IGNORE;

  ScopedUdevDevicePtr device(FindUdevDevice(path));
  if (device.get()) {
    for (const std::unique_ptr<Rule>& rule : rules_) {
      Rule::Result rule_result = rule->ProcessDevice(device.get());
      LOG(INFO) << "  " << rule->name() << ": "
                << Rule::ResultToString(rule_result);
      if (rule_result == Rule::DENY) {
        result = Rule::DENY;
        break;
      } else if (rule_result == Rule::ALLOW_WITH_DETACH) {
        result = Rule::ALLOW_WITH_DETACH;
      } else if (rule_result == Rule::ALLOW_WITH_LOCKDOWN) {
        result = Rule::ALLOW_WITH_LOCKDOWN;
      } else if (rule_result == Rule::ALLOW &&
                 result != Rule::ALLOW_WITH_DETACH &&
                 result != Rule::ALLOW_WITH_LOCKDOWN) {
        result = Rule::ALLOW;
      }
    }
  } else {
    LOG(INFO) << "No udev entry found for " << path << ", denying access.";
    result = Rule::DENY;
  }

  LOG(INFO) << "Verdict for " << path << ": " << Rule::ResultToString(result);
  return result;
}

void RuleEngine::WaitForEmptyUdevQueue() {
  struct udev_queue* queue = udev_queue_new(udev_.get());
  if (udev_queue_get_queue_is_empty(queue)) {
    udev_queue_unref(queue);
    return;
  }

  struct pollfd udev_poll;
  memset(&udev_poll, 0, sizeof(udev_poll));
  udev_poll.fd = inotify_init();
  udev_poll.events = POLLIN;

  int watch =
      inotify_add_watch(udev_poll.fd, udev_run_path_.c_str(), IN_MOVED_TO);
  CHECK_NE(watch, -1) << "Could not add watch for udev run directory.";

  while (!udev_queue_get_queue_is_empty(queue)) {
    if (poll(&udev_poll, 1, poll_interval_.InMilliseconds()) > 0) {
      char buffer[sizeof(struct inotify_event)];
      const ssize_t result = read(udev_poll.fd, buffer, sizeof(buffer));
      if (result < 0)
        LOG(WARNING) << "Did not read complete udev event.";
    }
  }
  udev_queue_unref(queue);
  close(udev_poll.fd);
}

ScopedUdevDevicePtr RuleEngine::FindUdevDevice(const std::string& path) {
  ScopedUdevEnumeratePtr enumerate(udev_enumerate_new(udev_.get()));
  udev_enumerate_scan_devices(enumerate.get());

  struct udev_list_entry* entry = nullptr;
  udev_list_entry_foreach(entry,
                          udev_enumerate_get_list_entry(enumerate.get())) {
    const char* syspath = udev_list_entry_get_name(entry);
    ScopedUdevDevicePtr device(
        udev_device_new_from_syspath(udev_.get(), syspath));

    const char* devnode = udev_device_get_devnode(device.get());
    if (devnode && !strcmp(devnode, path.c_str()))
      return device;
  }

  return nullptr;
}

}  // namespace permission_broker
