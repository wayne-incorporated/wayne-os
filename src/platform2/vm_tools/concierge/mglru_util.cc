// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/mglru_util.h"

#include <sstream>
#include <utility>

namespace vm_tools::concierge::mglru {
namespace {

// Parses a single generation from the input stream and adds it to the supplied
// node. The input stream is expected to be at the starting position for the
// generation, otherwise this function will fail. On failure the stream is reset
// to a good state and set to its original position.
bool ParseGeneration(std::stringstream& mglru_stream, MglruNode& node) {
  std::streampos starting_position = mglru_stream.tellg();

  MglruGeneration gen;
  mglru_stream >> gen.sequence_num >> gen.timestamp_msec >> gen.anon >>
      gen.file;

  if (mglru_stream.fail()) {
    mglru_stream.clear();
    mglru_stream.seekg(starting_position);
    return false;
  }

  node.generations.emplace_back(std::move(gen));
  return true;
}

// Parses a single node from the input stream and adds it to the supplied memcg.
// The input stream is expected to be at the starting position for the node,
// otherwise this function will fail. On failure the stream is reset to a good
// state and set to its original position.
bool ParseNode(std::stringstream& mglru_stream, MglruMemcg& memcg) {
  std::streampos starting_position = mglru_stream.tellg();

  std::string token;
  mglru_stream >> token;

  // A node always starts with the node identifier token.
  if (token != "node") {
    mglru_stream.clear();
    mglru_stream.seekg(starting_position);
    return false;
  }

  MglruNode new_node;

  // After the node identifier is the node ID.
  mglru_stream >> new_node.id;
  if (mglru_stream.fail()) {
    mglru_stream.clear();
    mglru_stream.seekg(starting_position);
    return false;
  }

  // Next is one or more generations. Parse generations until we encounter a
  // failure. The first failure indicates the end of the list of generations.
  while (ParseGeneration(mglru_stream, new_node)) {
  }

  // If no generations were parsed, there is an error.
  if (new_node.generations.size() == 0) {
    mglru_stream.clear();
    mglru_stream.seekg(starting_position);
    return false;
  }

  // Add new Node to last CG
  memcg.nodes.emplace_back(std::move(new_node));

  return true;
}

// Parses a single memcg from the input stream and adds it to the supplied
// stats. The input stream is expected to be at the starting position for the
// memcg, otherwise this function will fail. On failure the stream is reset to a
// good state and set to its original position.
bool ParseMemcg(std::stringstream& mglru_stream, MglruStats& parsed_stats) {
  std::streampos starting_position = mglru_stream.tellg();

  std::string token;
  mglru_stream >> token;

  // The first token of a memcg is always the memcg identifier.
  if (token != "memcg") {
    mglru_stream.clear();
    mglru_stream.seekg(starting_position);
    return false;
  }

  MglruMemcg new_memcg;

  // After the memcg identifier is the id
  mglru_stream >> new_memcg.id;
  if (mglru_stream.fail()) {
    mglru_stream.clear();
    mglru_stream.seekg(starting_position);
    return false;
  }

  // Newer kernel versions have a '/' after memcg
  std::streampos before_slash = mglru_stream.tellg();
  mglru_stream >> token;
  if (token != "/") {
    mglru_stream.clear();
    mglru_stream.seekg(before_slash);
  }

  // After the id is a list of one or more nodes. Parse nodes until failure. The
  // first failure indicates the end of the list of nodes.
  while (ParseNode(mglru_stream, new_memcg)) {
  }

  // If no nodes were parsed, then there was an error.
  if (new_memcg.nodes.size() == 0) {
    mglru_stream.clear();
    mglru_stream.seekg(starting_position);
    return false;
  }

  // Add the newly parsed memcg to the stats
  parsed_stats.cgs.emplace_back(std::move(new_memcg));

  return true;
}

}  // namespace

std::optional<MglruStats> ParseStatsFromString(const std::string admin_file) {
  std::stringstream contents_stream(admin_file);

  MglruStats parsed_stats{};

  // The MGLRU stats file is a list of one or more memcgs. Parse until failure.
  // The first failure indicates the end of the list of memcgs.
  while (ParseMemcg(contents_stream, parsed_stats)) {
  }

  std::string token;

  contents_stream >> token;

  // If the parsing did not consume the entire input file, or if no memcgs were
  // parsed, then something went wrong.
  if (token != "" || !contents_stream.eof() || parsed_stats.cgs.size() == 0) {
    return std::nullopt;
  }

  return parsed_stats;
}

std::string StatsToString(const MglruStats& stats) {
  std::stringstream output;

  for (const MglruMemcg& cg : stats.cgs) {
    output << "memcg  " << cg.id << '\n';
    for (const MglruNode& node : cg.nodes) {
      output << "  node  " << node.id << '\n';
      for (const MglruGeneration& gen : node.generations) {
        output << "    " << gen.sequence_num << "  " << gen.timestamp_msec
               << "  " << gen.anon << "  " << gen.file << '\n';
      }
    }
  }

  return output.str();
}

}  // namespace vm_tools::concierge::mglru
