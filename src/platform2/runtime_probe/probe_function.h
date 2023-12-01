// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_PROBE_FUNCTION_H_
#define RUNTIME_PROBE_PROBE_FUNCTION_H_

#include <array>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <variant>
#include <vector>

#include <base/json/json_writer.h>
#include <base/values.h>
#include <base/strings/string_util.h>

namespace runtime_probe {

// Creates a probe function. This is a syntax suger for |FromKwargsValue|.
template <typename T>
std::unique_ptr<T> CreateProbeFunction(
    const base::Value::Dict& dict_value = {}) {
  return T::template FromKwargsValue<T>(dict_value);
}

class ProbeFunction {
  // ProbeFunction is the base class for all probe functions.  A derived
  // class should implement required virtual functions and contain some static
  // members: |function_name|, FromKwargsValue().
  //
  // FromKwargsValue is the main point to create a probe function instance.  It
  // takes a dictionary value in type base::Value as arguments and returns a
  // pointer to the instance of the probe function.
  //
  // Formally, a probe function will be represented as following structure::
  //   {
  //     <function_name:string>: <args:ArgsType>
  //   }
  //
  // where the top layer dictionary should have one and only one key.  For
  // example::
  //   {
  //     "sysfs": {
  //       "dir_path": "/sys/class/cool/device/dev*",
  //       "keys": ["key_1", "key_2"],
  //       "optional_keys": ["opt_key_1"]
  //     }
  //   }

 public:
  using DataType = base::Value::List;

  // Interface to parse a function argument. See RegisterArgumentParser().
  class ArgumentParser {
   public:
    ArgumentParser() = default;
    virtual ~ArgumentParser() = default;

    // Implement this to parse the argument from a value. |value| set to
    // |std::nullopt| means that the field is not found in the argument list.
    // Returns true if parse succeeds. Set |err| to some error messages which
    // will be logged with the function name and the field name (|err| will be
    // ignored if returning true).
    virtual bool Parse(const std::optional<base::Value>& value,
                       std::string& err) = 0;
  };

  // Returns the name of the probe function.  The returned value should always
  // identical to the static member |function_name| of the derived class.
  //
  // A common implementation can be declared by macro NAME_PROBE_FUNCTION(name)
  // below.
  virtual const std::string& GetFunctionName() const = 0;

  // Converts |dv| with function name as key to ProbeFunction.  Returns nullptr
  // on failure.
  static std::unique_ptr<ProbeFunction> FromValue(const base::Value& dv);

  // Creates a probe function of type |T| with arguments. Returns nullptr if
  // arguments cannot be parsed.
  template <typename T>
  static std::unique_ptr<T> FromKwargsValue(
      const base::Value::Dict& dict_value) {
    std::unique_ptr<T> fun{new T()};
    if (fun->ParseArguments(dict_value)) {
      return fun;
    }
    return nullptr;
  }

  ProbeFunction(const ProbeFunction&) = delete;
  ProbeFunction& operator=(const ProbeFunction&) = delete;
  virtual ~ProbeFunction();

  // Evaluates this probe function. Returns a list of base::Value. For the probe
  // function that requests sandboxing, see |PrivilegedProbeFunction|.
  virtual DataType Eval() const { return EvalImpl(); }

  // This is for helper to evaluate the probe function. Helper is designed for
  // portion that need extended sandbox. See |PrivilegedProbeFunction| for more
  // detials.
  //
  // Output will be an integer and the interpretation of the integer on
  // purposely leaves to the caller because it might execute other binary
  // in sandbox environment and we might want to preserve the exit code.
  virtual int EvalInHelper(std::string* output) const;

  // Registers an ArgumentParser. The callers need to guarantee the lifecycle of
  // ArgumentParser object. It should be alive when calling
  // |ParseArguments()|.
  void RegisterArgumentParser(const std::string field_name,
                              ArgumentParser* parser);

  using FactoryFunctionType =
      std::function<std::unique_ptr<ProbeFunction>(const base::Value::Dict&)>;

  using RegisteredFunctionTableType =
      std::map<std::string_view, FactoryFunctionType>;

  // Mapping from |function_name| to FromKwargsValue() of each derived classes.
  static RegisteredFunctionTableType registered_functions_;

 protected:
  ProbeFunction();

  // Implement this method to provide the probing. The output should be a list
  // of base::Value.
  virtual DataType EvalImpl() const = 0;

  // Implement this to verify the parsed arguments or do other set up which
  // based on arguments (e.g. create other probe functions with the arguments).
  // It is called after all ArgumentParser are executed. Returning false makes
  // the |ParseArguments()| fail.
  virtual bool PostParseArguments() { return true; }

  // Gets the arguments. It is the raw arguments passed to this function.
  const base::Value::Dict& arguments() const { return arguments_; }

 private:
  // Parses the probe function arguments. Returns false when error.
  bool ParseArguments(const base::Value::Dict& arguments);

  // A map of argument field names to argument parsers.
  std::map<std::string, ArgumentParser*> argument_parsers_;
  // The raw arguments.
  base::Value::Dict arguments_;
};

class PrivilegedProbeFunction : public ProbeFunction {
  // |PrivilegedProbeFunction| run in the sandbox with pre-defined permissions.
  // This is for all the operations which request special permission like sysfs
  // access. |PrivilegedProbeFunction| will be initialized with same json
  // statement in the helper process, which invokes |EvalImpl()|. Since
  // execution of |PrivilegedProbeFunction::EvalImpl()| implies a different
  // sandbox, it is encouraged to keep work that doesn't need a privilege in
  // |PostHelperEvalImpl()|.
  //
  // For each |PrivilegedProbeFunction|, please modify `sandbox/args.json` and
  // `sandbox/${ARCH}/${function_name}-seccomp.policy`.
  using ProbeFunction::ProbeFunction;

 public:
  // ProbeFunction overrides.
  DataType Eval() const final;
  int EvalInHelper(std::string* output) const final;

 protected:
  // Serializes this probe function and passes it to helper. The output of the
  // helper will store in |result|. Returns true if success on executing helper.
  bool InvokeHelper(std::string* result) const;

  // Serializes this probe function and passes it to helper.  Helper function
  // for InvokeHelper() where the output is known in advanced in JSON format.
  // The transform of JSON will be automatically applied.  Returns std::nullopt
  // on failure.
  std::optional<base::Value> InvokeHelperToJSON() const;

 private:
  // This method is called after |EvalImpl()| finished. The |result| is the
  // value returned by |EvalImpl()|. Because |EvalImpl()| is executed in helper,
  // this method is for those operations that cannot or don't want to be
  // performed in helper, for example dbus call. This method can do some extra
  // logic out of helper and modify the |result|. See b/185292404 for the
  // discussion about this two steps EvalImpl.
  virtual void PostHelperEvalImpl(DataType* result) const {}
};

// Tells if T is a subclass of ProbeFunction.
template <typename T>
inline constexpr auto is_probe_function_v = std::is_base_of_v<ProbeFunction, T>;

// Represents a list of ProbeFunction.
template <typename... Ts>
class ProbeFunctions {
  static_assert((is_probe_function_v<Ts> && ...),
                "Ts must be a subclass of ProbeFunction");

 public:
  // Gets an array of all function names.
  static constexpr std::array<const char*, sizeof...(Ts)> GetFunctionNames() {
    return {Ts::function_name...};
  }

  // Constructs a table mapping function name to its factory method.
  static ProbeFunction::RegisteredFunctionTableType
  ConstructRegisteredFunctionTable() {
    return {{Ts::function_name, CreateProbeFunction<Ts>}...};
  }
};

#define NAME_PROBE_FUNCTION(name)                       \
  const std::string& GetFunctionName() const override { \
    static const std::string instance(function_name);   \
    return instance;                                    \
  }                                                     \
  static constexpr auto function_name = name

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_PROBE_FUNCTION_H_
