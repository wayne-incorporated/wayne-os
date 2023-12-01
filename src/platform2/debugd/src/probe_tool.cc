// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/probe_tool.h"

#include <fcntl.h>

#include <iterator>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/files/scoped_temp_dir.h>
#include <base/json/json_string_value_serializer.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/values.h>
#include <brillo/errors/error_codes.h>
#include <re2/re2.h>

#include "debugd/src/error_utils.h"
#include "debugd/src/sandboxed_process.h"

namespace debugd {

namespace {
constexpr char kErrorPath[] = "org.chromium.debugd.RunProbeFunctionError";
constexpr char kSandboxInfoDir[] = "/etc/runtime_probe/sandbox";
constexpr char kSandboxArgs[] = "/etc/runtime_probe/sandbox/args.json";
constexpr char kRuntimeProbeBinary[] = "/usr/bin/runtime_probe";
constexpr char kDefaultRunAs[] = "runtime_probe";
constexpr char kMinijailBindFlag[] = "-b";
constexpr char kMinijailBindKey[] = "binds";
constexpr char kMinijailUserKey[] = "user";
constexpr char kMinijailGroupKey[] = "group";
constexpr char kMinijailOtherArgsKey[] = "other_args";

bool CreateNonblockingPipe(base::ScopedFD* read_fd, base::ScopedFD* write_fd) {
  int pipe_fd[2];
  int ret = pipe2(pipe_fd, O_CLOEXEC | O_NONBLOCK);
  if (ret != 0) {
    PLOG(ERROR) << "Cannot create a pipe";
    return false;
  }
  read_fd->reset(pipe_fd[0]);
  write_fd->reset(pipe_fd[1]);
  return true;
}

bool PathOrSymlinkExists(const base::FilePath& path) {
  auto abs_path = base::MakeAbsoluteFilePath(path);
  return base::PathExists(abs_path);
}

std::optional<base::Value::Dict> ParseProbeStatement(
    brillo::ErrorPtr* error, const std::string& probe_statement_str) {
  JSONStringValueDeserializer deserializer(probe_statement_str);
  auto value = deserializer.Deserialize(nullptr, nullptr);
  if (!value || !value->is_dict()) {
    DEBUGD_ADD_ERROR_FMT(
        error, kErrorPath,
        "Failed to parse probe statement. Expected json but got: %s",
        probe_statement_str.c_str());
    return std::nullopt;
  }
  base::Value::Dict probe_statement = std::move(*value).TakeDict();

  if (probe_statement.size() != 1) {
    DEBUGD_ADD_ERROR_FMT(
        error, kErrorPath,
        "Expected only one probe function in probe statement but got: %zu",
        probe_statement.size());
    return std::nullopt;
  }
  return probe_statement;
}

}  // namespace

bool ProbeTool::EvaluateProbeFunction(brillo::ErrorPtr* error,
                                      const std::string& probe_statement,
                                      int log_level,
                                      base::ScopedFD* outfd,
                                      base::ScopedFD* errfd) {
  // Details of sandboxing for probing should be centralized in a single
  // directory. Sandboxing is mandatory when we don't allow debug features.
  auto process = CreateSandboxedProcess(error, probe_statement);
  if (process == nullptr)
    return false;  // DEBUGD_ADD_ERROR is already called.

  base::ScopedFD out_r_fd, out_w_fd;
  base::ScopedFD err_r_fd, err_w_fd;
  if (!CreateNonblockingPipe(&out_r_fd, &out_w_fd) ||
      !CreateNonblockingPipe(&err_r_fd, &err_w_fd)) {
    DEBUGD_ADD_ERROR(error, kErrorPath, "Cannot create a pipe");
    return false;
  }

  process->AddArg(kRuntimeProbeBinary);
  process->AddArg("--helper");
  process->AddArg(base::StringPrintf("--log_level=%d", log_level));
  process->AddArg("--");
  process->AddArg(probe_statement);
  process->BindFd(out_w_fd.get(), STDOUT_FILENO);
  process->BindFd(err_w_fd.get(), STDERR_FILENO);
  process->Start();
  process->Release();
  *outfd = std::move(out_r_fd);
  *errfd = std::move(err_r_fd);
  return true;
}

std::optional<base::Value::Dict> ProbeTool::LoadMinijailArguments(
    brillo::ErrorPtr* error) {
  std::string minijail_args_str;
  if (!base::ReadFileToString(base::FilePath(kSandboxArgs),
                              &minijail_args_str)) {
    DEBUGD_ADD_ERROR_FMT(error, kErrorPath,
                         "Failed to read Minijail arguments from: %s",
                         kSandboxArgs);
    return std::nullopt;
  }
  JSONStringValueDeserializer deserializer(minijail_args_str);
  auto dict = deserializer.Deserialize(nullptr, nullptr);
  if (!dict || !dict->is_dict()) {
    DEBUGD_ADD_ERROR_FMT(
        error, kErrorPath,
        "Minijail arguments are not stored in dict. Expected dict but got: %s",
        minijail_args_str.c_str());
    return std::nullopt;
  }
  return std::move(*dict).TakeDict();
}

bool ProbeTool::GetValidMinijailArguments(
    brillo::ErrorPtr* error,
    const std::string& probe_statement_str,
    std::string* function_name_out,
    std::string* user_out,
    std::string* group_out,
    std::vector<std::string>* args_out) {
  function_name_out->clear();
  user_out->clear();
  group_out->clear();
  args_out->clear();

  if (!minijail_args_dict_) {
    minijail_args_dict_ = LoadMinijailArguments(error);
    if (!minijail_args_dict_) {
      return false;  // DEBUGD_ADD_ERROR is already called.
    }
  }

  auto probe_statement = ParseProbeStatement(error, probe_statement_str);
  if (!probe_statement) {
    return false;  // DEBUGD_ADD_ERROR is already called.
  }

  const auto& function_name = probe_statement->begin()->first;
  const auto* minijail_args = minijail_args_dict_->FindDict(function_name);
  if (!minijail_args) {
    DEBUGD_ADD_ERROR_FMT(
        error, kErrorPath,
        "Arguments of \"%s\" is not found in Minijail arguments file: %s",
        function_name.c_str(), kSandboxArgs);
    return false;
  }
  DVLOG(2) << "Minijail arguments: " << (*minijail_args);

  // Parse user argument.
  const auto* user_arg = minijail_args->FindString(kMinijailUserKey);
  // If the user is not specified, use the default user.
  std::string user = user_arg ? *user_arg : kDefaultRunAs;

  // Parse group argument.
  const auto* group_arg = minijail_args->FindString(kMinijailGroupKey);
  // If the group is not specified, use the default group.
  std::string group = group_arg ? *group_arg : kDefaultRunAs;

  std::vector<std::string> args{};

  // Parse other arguments.
  // Do this before parsing bind-mount arguments because we need some -k
  // arguments to appear before some -b arguments.
  const auto* other_args = minijail_args->FindList(kMinijailOtherArgsKey);
  if (other_args) {
    for (const auto& arg : *other_args) {
      if (!arg.is_string()) {
        DEBUGD_ADD_ERROR_FMT(
            error, kErrorPath,
            "Failed to parse Minijail arguments. Expected string but got: %s",
            arg.DebugString().c_str());
        return false;
      }
      const auto& curr_arg = arg.GetString();
      args.push_back(curr_arg);
    }
  }

  // Parse bind-mount arguments.
  const auto* bind_args = minijail_args->FindList(kMinijailBindKey);
  if (bind_args) {
    std::vector<std::string> real_bind_args{};
    for (const auto& arg : *bind_args) {
      if (arg.is_string()) {
        const auto& curr_arg = arg.GetString();
        // Check existence of bind paths.
        auto bind_paths = base::SplitString(
            curr_arg, ",", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
        if (bind_paths.size() < 1) {
          DEBUGD_ADD_ERROR_FMT(
              error, kErrorPath,
              "Failed to parse Minijail bind arguments. Got: %s",
              curr_arg.c_str());
          return false;
        }
        if (PathOrSymlinkExists(base::FilePath(bind_paths[0]))) {
          real_bind_args.push_back(curr_arg);
        }
      } else if (arg.is_dict()) {
        const auto& arg_dict = arg.GetDict();
        const auto* dirname = arg_dict.FindString("dirname");
        const auto* basename = arg_dict.FindString("basename");
        if (!dirname) {
          DEBUGD_ADD_ERROR_FMT(
              error, kErrorPath,
              "Failed to parse Minijail arguments. Missing key \"dirname\"");
          return false;
        }
        if (!basename) {
          DEBUGD_ADD_ERROR_FMT(
              error, kErrorPath,
              "Failed to parse Minijail arguments. Missing key \"basename\"");
          return false;
        }
        const auto* args_ptr = arg_dict.FindString("args");
        std::string extra_bind_args = args_ptr ? *args_ptr : "";
        for (const auto& filepath : FilesUnderPath(*dirname)) {
          if (RE2::FullMatch(filepath.BaseName().value(), basename->c_str())) {
            real_bind_args.push_back(filepath.value() + extra_bind_args);
          }
        }
      } else {
        DEBUGD_ADD_ERROR_FMT(error, kErrorPath,
                             "Failed to parse Minijail arguments. Got: %s",
                             arg.DebugString().c_str());
        return false;
      }
    }
    for (const auto& real_bind_arg : real_bind_args) {
      args.push_back(kMinijailBindFlag);
      args.push_back(real_bind_arg);
    }
  }

  *function_name_out = std::move(function_name);
  *user_out = std::move(user);
  *group_out = std::move(group);
  *args_out = std::move(args);

  return true;
}

std::vector<base::FilePath> ProbeTool::FilesUnderPath(
    const std::string& root) const {
  std::vector<base::FilePath> rv;
  base::FileEnumerator it(base::FilePath{root}, false,
                          base::FileEnumerator::SHOW_SYM_LINKS |
                              base::FileEnumerator::FILES |
                              base::FileEnumerator::DIRECTORIES);
  for (auto path = it.Next(); !path.empty(); path = it.Next()) {
    rv.emplace_back(std::move(path));
  }
  return rv;
}

std::unique_ptr<brillo::Process> ProbeTool::CreateSandboxedProcess(
    brillo::ErrorPtr* error, const std::string& probe_statement) {
  auto sandboxed_process = std::make_unique<SandboxedProcess>();
  // The following is the general Minijail set up for runtime_probe in debugd
  // /dev/log needs to be bind mounted before any possible tmpfs mount on run
  // See:
  //   minijail0 manpage (`man 1 minijail0` in cros\_sdk)
  //   https://chromium.googlesource.com/chromiumos/docs/+/HEAD/sandboxing.md
  std::vector<std::string> parsed_args{
      "-G",                // Inherit all the supplementary groups
      "-P", "/mnt/empty",  // Set /mnt/empty as the root fs using pivot_root
      "-b", "/",           // Bind mount rootfs
      "-b", "/proc",       // Bind mount /proc
      "-b", "/dev/log",    // Enable logging
      "-t",                // Mount a tmpfs on /tmp
      "-r",                // Remount /proc readonly
      "-d"                 // Mount /dev with a minimal set of nodes.
  };
  std::string function_name;
  std::vector<std::string> config_args;
  std::string sandbox_user, sandbox_group;
  if (!GetValidMinijailArguments(error, probe_statement, &function_name,
                                 &sandbox_user, &sandbox_group, &config_args))
    return nullptr;  // DEBUGD_ADD_ERROR is already called.

  parsed_args.insert(std::end(parsed_args),
                     std::make_move_iterator(std::begin(config_args)),
                     std::make_move_iterator(std::end(config_args)));

  sandboxed_process->SandboxAs(sandbox_user, sandbox_group);
  const auto seccomp_path = base::FilePath{kSandboxInfoDir}.Append(
      base::StringPrintf("%s-seccomp.policy", function_name.c_str()));
  if (!base::PathExists(seccomp_path)) {
    DEBUGD_ADD_ERROR_FMT(error, kErrorPath,
                         "Seccomp policy file of \"%s\" is not found at: %s",
                         function_name.c_str(), seccomp_path.value().c_str());
    return nullptr;
  }
  sandboxed_process->SetSeccompFilterPolicyFile(seccomp_path.MaybeAsASCII());
  DVLOG(1) << "Sandbox for " << function_name << " is ready";
  if (!sandboxed_process->Init(parsed_args)) {
    DEBUGD_ADD_ERROR(error, kErrorPath,
                     "Sandboxed process initialization failure");
    return nullptr;
  }
  return sandboxed_process;
}

}  // namespace debugd
