// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_MGLRU_UTIL_H_
#define VM_TOOLS_CONCIERGE_MGLRU_UTIL_H_

#include <optional>
#include <string>
#include <vector>

namespace vm_tools::concierge::mglru {

// MGLRU caching at a high level is organized as follows:
// Memory Control Groups (memcg)
//    Nodes
//      Generations
// The following structs are organized in the same way
// to store the sizes of MGLRU generations

// A single MGLRU generation
struct MglruGeneration {
  // The sequence number
  uint32_t sequence_num;

  // The age of this generation in ms
  uint32_t timestamp_msec;

  // The number of pages of anonymous memory in this generation
  uint32_t anon;

  // The number of pages of file cache in this generation
  uint32_t file;
};

// A single MGLRU node
struct MglruNode {
  // The id of this node
  uint32_t id;

  // The generations in this node
  std::vector<MglruGeneration> generations;
};

// A single memory control group
struct MglruMemcg {
  // The id of this memory control group
  uint32_t id;

  // The nodes in this memory control group
  std::vector<MglruNode> nodes;
};

// Contains the stats of MGLRU at a point in time
struct MglruStats {
  // The current memory control groups
  std::vector<MglruMemcg> cgs;
};

// Parses MglruStats from the contents of the MGLRU sysfs admin file
// Usually: /sys/kernel/mm/lru_gen/admin
std::optional<MglruStats> ParseStatsFromString(const std::string admin_file);

// Formats the given stats into a human readable string
std::string StatsToString(const MglruStats& stats);

}  // namespace vm_tools::concierge::mglru

#endif  // VM_TOOLS_CONCIERGE_MGLRU_UTIL_H_
