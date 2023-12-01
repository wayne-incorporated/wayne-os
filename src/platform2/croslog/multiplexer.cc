// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "croslog/multiplexer.h"

#include <optional>
#include <utility>

#include "base/strings/string_util.h"

#include "croslog/log_parser_syslog.h"

#include <base/check.h>

namespace croslog {

Multiplexer::LogSource::LogSource(base::FilePath log_file,
                                  std::unique_ptr<LogParser> parser_in,
                                  bool install_change_watcher)
    : reader(log_file, std::move(parser_in), install_change_watcher) {}

Multiplexer::Multiplexer() = default;

void Multiplexer::AddSource(base::FilePath log_file,
                            std::unique_ptr<LogParser> parser,
                            bool install_change_watcher) {
  auto source = std::make_unique<LogSource>(
      std::move(log_file), std::move(parser), install_change_watcher);
  source->reader.AddObserver(this);
  sources_.emplace_back(std::move(source));
}

void Multiplexer::OnFileChanged(LogLineReader* reader) {
  for (auto&& source : sources_) {
    if (source->reader.file_path() != reader->file_path())
      continue;

    // Invalidate caches, since the backed buffer may be invalid.
    if (source->cache_next_backward.has_value()) {
      CHECK(!source->cache_next_forward.has_value());
      source->cache_next_backward.reset();
      source->reader.GetNextEntry();
    } else if (source->cache_next_forward.has_value()) {
      source->cache_next_forward.reset();
      source->reader.GetPreviousEntry();
    }
  }

  for (Observer& obs : observers_)
    obs.OnLogFileChanged();
}

MaybeLogEntry Multiplexer::Forward() {
  for (auto&& source : sources_) {
    if (source->cache_next_backward.has_value()) {
      CHECK(!source->cache_next_forward.has_value());
      source->cache_next_backward.reset();
      source->reader.GetNextEntry();
    }

    if (!source->cache_next_forward.has_value()) {
      MaybeLogEntry entry = source->reader.GetNextEntry();
      if (!entry.has_value()) {
        // No more entry from this source.
        continue;
      }
      // Reading an entry succeeds. Use this.
      source->cache_next_forward.emplace(std::move(*entry));
    }
  }

  Multiplexer::LogSource* next_source = nullptr;
  for (auto&& source : sources_) {
    if (!source->cache_next_forward.has_value()) {
      // This source doesn't have a next entry.
      continue;
    }

    if (next_source == nullptr || next_source->cache_next_forward->time() >
                                      source->cache_next_forward->time()) {
      next_source = source.get();
    }
  }

  if (next_source == nullptr) {
    return std::nullopt;
  }

  MaybeLogEntry entry = std::move(next_source->cache_next_forward);
  next_source->cache_next_forward.reset();
  return entry;
}

MaybeLogEntry Multiplexer::Backward() {
  for (auto&& source : sources_) {
    if (source->cache_next_forward.has_value()) {
      CHECK(!source->cache_next_backward.has_value());
      source->cache_next_forward.reset();
      source->reader.GetPreviousEntry();
    }

    if (!source->cache_next_backward.has_value()) {
      MaybeLogEntry entry = source->reader.GetPreviousEntry();
      if (!entry.has_value()) {
        // No more entry from this source.
        continue;
      }
      // Reading an entry succeeds. Use this.
      source->cache_next_backward.emplace(std::move(*entry));
    }
  }

  Multiplexer::LogSource* next_source = nullptr;
  for (auto&& source : sources_) {
    if (!source->cache_next_backward.has_value()) {
      // This source doesn't have a next entry.
      continue;
    }

    if (next_source == nullptr || next_source->cache_next_backward->time() <=
                                      source->cache_next_backward->time()) {
      next_source = source.get();
    }
  }

  if (next_source == nullptr) {
    return std::nullopt;
  }

  MaybeLogEntry entry = std::move(next_source->cache_next_backward);
  next_source->cache_next_backward.reset();
  return entry;
}

void Multiplexer::AddObserver(Observer* obs) {
  observers_.AddObserver(obs);
}

void Multiplexer::RemoveObserver(Observer* obs) {
  observers_.RemoveObserver(obs);
}

void Multiplexer::SetLinesFromLast(uint32_t pos) {
  for (auto& source : sources_) {
    source->cache_next_backward.reset();
    source->cache_next_forward.reset();
    source->reader.SetPositionLast();
  }

  for (int i = 0; i < pos; i++) {
    MaybeLogEntry s = Backward();
    if (!s.has_value())
      return;
  }
}

}  // namespace croslog
