// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHARGESPLASH_FRECON_H_
#define CHARGESPLASH_FRECON_H_

#include <fstream>
#include <string>
#include <vector>

namespace chargesplash {

class Frecon {
 public:
  Frecon() = default;
  Frecon(const Frecon&) = delete;
  Frecon& operator=(const Frecon&) = delete;
  ~Frecon();

  // Start a new frecon process and attach it to the output.  If a
  // frecon process already exists, it will be terminated.
  //
  // Returns true upon success, or false if an error occurred starting
  // frecon.
  bool InitFrecon();

  // Attach the output to another file.
  void AttachOutput(std::ostream* output);

  // Write a string to all outputs.
  void Write(const std::string& msg);

 private:
  int frecon_pid_ = -1;
  std::ofstream frecon_vt_;
  std::vector<std::ostream*> outputs_;
};

}  // namespace chargesplash

#endif  // CHARGESPLASH_FRECON_H_
