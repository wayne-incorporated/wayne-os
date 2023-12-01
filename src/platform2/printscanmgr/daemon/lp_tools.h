// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PRINTSCANMGR_DAEMON_LP_TOOLS_H_
#define PRINTSCANMGR_DAEMON_LP_TOOLS_H_

#include <string>
#include <vector>

#include <base/files/file_path.h>

namespace printscanmgr {

class LpTools {
 public:
  // Return code for a process which did not start successfully.
  static constexpr int kRunError = -1;

  virtual ~LpTools() = default;

  // Runs lpadmin with the provided |arg_list| and |std_input|.
  virtual int Lpadmin(const std::vector<std::string>& arg_list,
                      const std::vector<uint8_t>* std_input = nullptr) = 0;

  // Runs lpstat with the provided |arg_list| and |std_input|.
  virtual int Lpstat(const std::vector<std::string>& arg_list,
                     std::string* output) = 0;

  // Runs cupstestppd with |ppd_content| and returns the exit code.
  virtual int CupsTestPpd(const std::vector<uint8_t>& ppd_content) const = 0;

  // Returns true iff `uri` looks reasonable.
  virtual bool CupsUriHelper(const std::string& uri) const = 0;

  virtual const base::FilePath& GetCupsPpdDir() const = 0;

  // Returns the exit code for the executed process.
  virtual int RunCommand(const std::string& command,
                         const std::vector<std::string>& arg_list,
                         const std::vector<uint8_t>* std_input = nullptr,
                         std::string* out = nullptr) const = 0;
};

// Production implementation of the LpTools interface.
class LpToolsImpl : public LpTools {
 public:
  ~LpToolsImpl() override = default;

  // LpTools overrides:
  int Lpadmin(const std::vector<std::string>& arg_list,
              const std::vector<uint8_t>* std_input = nullptr) override;
  int Lpstat(const std::vector<std::string>& arg_list,
             std::string* output) override;
  int CupsTestPpd(const std::vector<uint8_t>& ppd_content) const override;
  bool CupsUriHelper(const std::string& uri) const override;
  const base::FilePath& GetCupsPpdDir() const override;
  int RunCommand(const std::string& command,
                 const std::vector<std::string>& arg_list,
                 const std::vector<uint8_t>* std_input = nullptr,
                 std::string* out = nullptr) const override;
};

}  // namespace printscanmgr

#endif  // PRINTSCANMGR_DAEMON_LP_TOOLS_H_
