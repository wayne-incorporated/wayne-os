// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_RAR_MOUNTER_H_
#define CROS_DISKS_RAR_MOUNTER_H_

#include <memory>
#include <string>
#include <vector>

#include <base/strings/string_piece.h>
#include <gtest/gtest_prod.h>

#include "cros-disks/archive_mounter.h"
#include "cros-disks/fuse_mounter.h"

namespace cros_disks {

// An ArchiveMounter with handling of RAR multipart archives.
class RarMounter : public ArchiveMounter {
 public:
  RarMounter(const Platform* platform,
             brillo::ProcessReaper* process_reaper,
             Metrics* metrics,
             std::unique_ptr<SandboxedProcessFactory> sandbox_factory);
  RarMounter(const RarMounter&) = delete;
  RarMounter& operator=(const RarMounter&) = delete;

  ~RarMounter() override;

 private:
  // Increments a sequence of digits or letters [begin, end). Returns true if
  // success, and false in case of overflow.
  static bool Increment(std::string::iterator begin, std::string::iterator end);

  // A semi-open index range [begin, end).
  struct IndexRange {
    size_t begin, end;

    bool empty() const { return begin == end; }
    size_t size() const { return end - begin; }

    // Friend operators for testing, logging and debugging.
    friend std::ostream& operator<<(std::ostream& out, const IndexRange& r) {
      return out << "{ begin: " << r.begin << ", end: " << r.end << " }";
    }

    friend bool operator==(const IndexRange& a, const IndexRange& b) {
      return a.begin == b.begin && a.end == b.end;
    }
  };

  // Checks if the given path ends with ".partNNNN.rar", which is the new
  // naming pattern for multipart archives. Returns the range of characters
  // forming the numeric part NNNN if path matches the pattern, or an empty
  // range otherwise.
  static IndexRange ParseDigits(base::StringPiece path);

  // Adds bind paths using old naming scheme.
  void AddPathsWithOldNamingScheme(std::vector<std::string>* bind_paths,
                                   base::StringPiece original_path) const;

  // Adds bind paths using new naming scheme.
  void AddPathsWithNewNamingScheme(std::vector<std::string>* bind_paths,
                                   base::StringPiece original_path,
                                   const IndexRange& digits) const;

  // Prepares the bind paths for the given RAR file path.
  //
  // If the given path is considered to be part of a multipart archive, this
  // function tries to find all the related files.
  //
  // Two different naming schemes are supported.
  //
  // The old naming scheme is:
  //
  // basename.rar
  // basename.r00
  // basename.r01
  // ...
  // basename.r99
  // basename.s00
  // basename.s01
  // ...
  //
  //
  // The new naming scheme is:
  //
  // basename1.rar
  // basename2.rar
  // ...
  // basename9.rar
  //
  // or
  //
  // basename01.rar
  // basename02.rar
  // ...
  // basename99.rar
  //
  // or
  //
  // basename001.rar
  // basename002.rar
  // ...
  // basename999.rar
  // etc.
  std::vector<std::string> GetBindPaths(
      base::StringPiece original_path) const override;

  FRIEND_TEST(RarMounterTest, Increment);
  FRIEND_TEST(RarMounterTest, ParseDigits);
  FRIEND_TEST(RarMounterTest, GetBindPathsWithOldNamingScheme);
  FRIEND_TEST(RarMounterTest, GetBindPathsWithNewNamingScheme);
  FRIEND_TEST(RarMounterTest, GetBindPathsStopsOnOverflow);
};

}  // namespace cros_disks

#endif  // CROS_DISKS_RAR_MOUNTER_H_
