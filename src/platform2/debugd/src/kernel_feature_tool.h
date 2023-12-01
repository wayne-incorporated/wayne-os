// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_KERNEL_FEATURE_TOOL_H_
#define DEBUGD_SRC_KERNEL_FEATURE_TOOL_H_

#include <memory>
#include <string>
#include <unordered_map>

#include <base/values.h>
#include <brillo/errors/error.h>
#include <vector>

namespace debugd {
class FeatureCommand {
 public:
  explicit FeatureCommand(const std::string& name) : name_(name) {}
  FeatureCommand(FeatureCommand&& other) = default;
  // virtual destructor is required because we create a unique pointer
  // of an abstract class. See KernelFeature class definition.
  virtual ~FeatureCommand() = default;

  std::string name() { return name_; }
  virtual bool Execute() = 0;

 private:
  std::string name_;
};

class WriteFileCommand : public FeatureCommand {
 public:
  WriteFileCommand(const std::string& file_name, const std::string& value);
  WriteFileCommand(WriteFileCommand&& other) = default;
  bool Execute() override;

 private:
  std::string file_name_;
  std::string value_;
};

class FileExistsCommand : public FeatureCommand {
 public:
  explicit FileExistsCommand(const std::string& file_name);
  FileExistsCommand(FileExistsCommand&& other) = default;
  bool Execute() override;

 private:
  std::string file_name_;
};

class AlwaysSupportedCommand : public FeatureCommand {
 public:
  AlwaysSupportedCommand() : FeatureCommand("AlwaysSupported") {}
  AlwaysSupportedCommand(AlwaysSupportedCommand&& other) = default;
  bool Execute() override { return true; }
};

class KernelFeature {
 public:
  KernelFeature() = default;
  KernelFeature(KernelFeature&& other) = default;
  KernelFeature(const KernelFeature& other) = delete;
  KernelFeature& operator=(const KernelFeature& other) = delete;

  std::string name() { return name_; }
  void SetName(std::string name) { name_ = name; }

  // Check if feature is supported on the device
  bool IsSupported() const;

  // Execute a sequence of commands to enable a feature
  bool Execute() const;

  // Used by the parser to add commands to a feature
  void AddCmd(std::unique_ptr<FeatureCommand> cmd);
  void AddQueryCmd(std::unique_ptr<FeatureCommand> cmd);

 private:
  std::vector<std::unique_ptr<FeatureCommand>> exec_cmds_;
  std::vector<std::unique_ptr<FeatureCommand>> support_check_cmds_;
  std::string name_;
};

class FeatureParserBase {
  using FeatureMap = std::unordered_map<std::string, KernelFeature>;

 public:
  virtual bool ParseFile(const base::FilePath& path, std::string* err_str) = 0;
  virtual ~FeatureParserBase() = default;
  const FeatureMap* GetFeatureMap() { return &feature_map_; }

 protected:
  std::unordered_map<std::string, KernelFeature> feature_map_;
  // Parse features only once per object
  bool features_parsed_ = false;
};

class JsonFeatureParser : public FeatureParserBase {
 public:
  bool ParseFile(const base::FilePath& path, std::string* err_str) override;

 private:
  bool MakeFeatureObject(base::Value::Dict& feature_obj,
                         std::string* err_str,
                         KernelFeature& kf);
};

class KernelFeatureTool {
 public:
  KernelFeatureTool();
  ~KernelFeatureTool();

  // Enables a kernel feature
  bool KernelFeatureEnable(brillo::ErrorPtr* error,
                           const std::string& name,
                           bool* result,
                           std::string* err_str);

  // Provide a kernel feature list
  bool KernelFeatureList(brillo::ErrorPtr* error,
                         bool* result,
                         std::string* out_str);

 private:
  bool ParseFeatureList(std::string* err_str);
  bool GetFeatureList(std::string* csv_list, std::string* err_str);
  std::unique_ptr<FeatureParserBase> parser_;
};
}  // namespace debugd

#endif  // DEBUGD_SRC_KERNEL_FEATURE_TOOL_H_
