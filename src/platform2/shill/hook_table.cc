// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/hook_table.h"

#include <list>
#include <string>
#include <utility>

#include <base/cancelable_callback.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/logging.h>
#include <base/time/time.h>

#include "shill/error.h"
#include "shill/event_dispatcher.h"
#include "shill/logging.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kManager;
}  // namespace Logging

HookTable::HookTable(EventDispatcher* event_dispatcher)
    : event_dispatcher_(event_dispatcher) {}

void HookTable::Add(const std::string& name, base::OnceClosure start_callback) {
  SLOG(2) << __func__ << ": " << name;
  Remove(name);
  hook_table_.emplace(name, HookAction(std::move(start_callback)));
}

HookTable::~HookTable() {
  timeout_callback_.Cancel();
}

void HookTable::Remove(const std::string& name) {
  SLOG(2) << __func__ << ": " << name;
  hook_table_.erase(name);
}

void HookTable::ActionComplete(const std::string& name) {
  SLOG(2) << __func__ << ": " << name;
  auto it = hook_table_.find(name);
  if (it != hook_table_.end()) {
    HookAction* action = &it->second;
    if (action->started && !action->completed) {
      action->completed = true;
    }
  }
  if (AllActionsComplete() && !done_callback_.is_null()) {
    timeout_callback_.Cancel();
    std::move(done_callback_).Run(Error(Error::kSuccess));
  }
}

void HookTable::Run(base::TimeDelta timeout, ResultCallback done) {
  SLOG(2) << __func__;
  if (hook_table_.empty()) {
    std::move(done).Run(Error(Error::kSuccess));
    return;
  }
  done_callback_ = std::move(done);
  timeout_callback_.Reset(
      base::BindOnce(&HookTable::ActionsTimedOut, base::Unretained(this)));
  event_dispatcher_->PostDelayedTask(FROM_HERE, timeout_callback_.callback(),
                                     timeout);

  // Mark all actions as having started before we execute any actions.
  // Otherwise, if the first action completes inline, its call to
  // ActionComplete() will cause the |done| callback to be invoked before the
  // rest of the actions get started.
  //
  // An action that completes inline could call HookTable::Remove(), which
  // modifies |hook_table_|. It is thus not safe to iterate through
  // |hook_table_| to execute the actions. Instead, we keep a list of start
  // callback of each action and iterate through that to invoke the callback.
  std::list<base::OnceClosure> action_start_callbacks;
  for (auto& hook_entry : hook_table_) {
    HookAction* action = &hook_entry.second;
    action_start_callbacks.push_back(std::move(action->start_callback));
    action->started = true;
    action->completed = false;
  }
  // Now start the actions.
  for (auto& callback : action_start_callbacks) {
    std::move(callback).Run();
  }
}

bool HookTable::AllActionsComplete() const {
  SLOG(2) << __func__;
  for (const auto& hook_entry : hook_table_) {
    const HookAction& action = hook_entry.second;
    if (action.started && !action.completed) {
      return false;
    }
  }
  return true;
}

void HookTable::ActionsTimedOut() {
  if (done_callback_) {
    std::move(done_callback_).Run(Error(Error::kOperationTimeout));
  }
}

}  // namespace shill
