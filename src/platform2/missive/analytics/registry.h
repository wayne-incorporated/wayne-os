// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MISSIVE_ANALYTICS_REGISTRY_H_
#define MISSIVE_ANALYTICS_REGISTRY_H_

#include <memory>
#include <string>
#include <unordered_map>

#include <base/strings/string_piece.h>
#include <base/time/time.h>
#include <base/timer/timer.h>

#include "missive/analytics/resource_collector.h"

namespace reporting::analytics {

// A registry. All resource collectors in the registry are run once for a
// certain time interval.
class Registry {
 public:
  // TODO(b/211017145): Add a constructor and Add() method that takes an
  // initializer_list argument.
  Registry() = default;
  Registry(const Registry&) = delete;
  Registry& operator=(const Registry&) = delete;
  Registry(Registry&&) = default;
  Registry& operator=(Registry&&) = default;

  // Registers a resource collector. The |Registry| instance will take over
  // ownership of the |ResourceCollector| instance. If another collector with
  // the same name has already been registered, it is replaced with the
  // collector argument.
  void Add(base::StringPiece name,
           std::unique_ptr<ResourceCollector> collector);
  // Removes a resource collector. Returns true if a collector is removed.
  // Returns false if there is no collector with the given name.
  bool Remove(base::StringPiece name);

 private:
  std::unordered_map<std::string, std::unique_ptr<ResourceCollector>>
      resource_collectors_;
};

}  // namespace reporting::analytics

#endif  // MISSIVE_ANALYTICS_REGISTRY_H_
