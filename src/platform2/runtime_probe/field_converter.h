// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_FIELD_CONVERTER_H_
#define RUNTIME_PROBE_FIELD_CONVERTER_H_

#include <cstdint>
#include <memory>
#include <string>

#include <pcrecpp.h>

#include <base/strings/string_piece.h>
#include <base/values.h>
#include <gtest/gtest.h>

#include "runtime_probe/utils/type_utils.h"

namespace runtime_probe {

enum class ValidatorOperator : uint8_t {
  NOP = 0,
  RE,  // Regular Expression match
  EQ,  // EQual to
  NE,  // Not Equal to
  GT,  // Greater Than
  GE,  // Greater than or Euqal to
  LT,  // Less Than
  LE,  // Less than or Equal to

  NUM_OP,
};

// Base class of field converter.
//
// Each derived class should implement one and only one constructor
// FieldConverter(const std::string& validate_rule).
class FieldConverter {
 public:
  enum class ReturnCode {
    OK = 0,
    FIELD_NOT_FOUND = 1,
    // Failed to convert the field
    INCOMPATIBLE_VALUE = 2,
    // The operator is not supported by this converter
    UNSUPPORTED_OPERATOR = 3,
    // Field value is invalid
    INVALID_VALUE = 4,
  };

  // Try to find |field_name| in |dict_value|, and convert it to expected type.
  //
  // @return |ReturnCode| to indicate success or reason of failure.
  virtual ReturnCode Convert(const std::string& field_name,
                             base::Value* dict_value) const = 0;

  // Check if value of |field_name| in dict_value is valid.
  //
  // @return |ReturnCode| to indicate success or reason of failure.
  virtual ReturnCode Validate(const std::string& field_name,
                              base::Value* dict_value) const = 0;

  virtual std::string ToString() const = 0;

  virtual ~FieldConverter() = default;
};

// Convert a field to string.
//
// Supported validators:
//   - "!re <Perl-compatible regular expression>"
//   - "!eq <expected string>"
//   - "!ne <unexpected string>"
class StringFieldConverter : public FieldConverter {
 public:
  ReturnCode Convert(const std::string& field_name,
                     base::Value* dict_value) const override;

  ReturnCode Validate(const std::string& field_name,
                      base::Value* dict_value) const override;

  std::string ToString() const override;

  static std::unique_ptr<StringFieldConverter> Build(
      const base::StringPiece& validate_rule);

  StringFieldConverter(ValidatorOperator op, const base::StringPiece& operand)
      : operator_(op), operand_(operand) {
    if (op == ValidatorOperator::RE) {
      // pcrecpp::RE constructor will always succeed, but might set "error()" if
      // the pattern is invalid.  This will be checked in |Build()|.
      regex_ = std::make_unique<pcrecpp::RE>(std::string(operand));
    }
  }

 private:
  ValidatorOperator operator_;
  std::string operand_;
  std::unique_ptr<pcrecpp::RE> regex_;

  FRIEND_TEST(StringFieldConverterTest, TestValidateRule);
};

// Numeric Field Converters convert a field into a numeric type.
// The logic of these fields are very similar.  To allow implementing common
// logic with template, helper function |StringToOperand| and type alias
// |OperandType| is defined.  |OperandType| is the type of |operand_| member
// variable.  And |StringToOperand| converts a string to |OperandType| value
// and return true on success.

// Convert a field to integer.
//
// However, heximal value is not allowed, please use |HexFieldConverter|
// instead.
//
// Supported validators:
//   - "!eq <integer>"
//   - "!ne <integer>"
//   - "!gt <integer>"
//   - "!ge <integer>"
//   - "!lt <integer>"
//   - "!le <integer>"
class IntegerFieldConverter : public FieldConverter {
 public:
  using FieldConverter::FieldConverter;
  using OperandType = int;

  ReturnCode Convert(const std::string& field_name,
                     base::Value* dict_value) const override;

  ReturnCode Validate(const std::string& field_name,
                      base::Value* dict_value) const override;

  std::string ToString() const override;

  static std::unique_ptr<IntegerFieldConverter> Build(
      const base::StringPiece& validate_rule);

  IntegerFieldConverter(ValidatorOperator op, OperandType operand)
      : operator_(op), operand_(operand) {}

  static bool StringToOperand(base::StringPiece s, OperandType* output) {
    return runtime_probe::StringToInt(s, output);
  }

 private:
  ValidatorOperator operator_;
  OperandType operand_;

  FRIEND_TEST(IntegerFieldConverterTest, TestValidateRule);
};

// Convert a hex string field to integer.
//
// If the original field is string, this class assumes it is base 16.
// Otherwise, if the field is already a number (int or double), the behavior wil
// be identical to |IntegerFieldConverter|.
//
// Supported validators: same as |IntegerFieldConverter|
class HexFieldConverter : public FieldConverter {
 public:
  using FieldConverter::FieldConverter;
  using OperandType = int64_t;

  ReturnCode Convert(const std::string& field_name,
                     base::Value* dict_value) const override;

  ReturnCode Validate(const std::string& field_name,
                      base::Value* dict_value) const override;

  std::string ToString() const override;

  static std::unique_ptr<HexFieldConverter> Build(
      const base::StringPiece& validate_rule);

  HexFieldConverter(ValidatorOperator op, OperandType operand)
      : operator_(op), operand_(operand) {}

  static bool StringToOperand(base::StringPiece s, OperandType* output) {
    return runtime_probe::HexStringToInt64(s, output);
  }

 private:
  ValidatorOperator operator_;
  OperandType operand_;

  FRIEND_TEST(HexFieldConverterTest, TestValidateRule);
};

// Convert a field to double.
//
// Supported validators: same as |IntegerFieldConverter|, except the operand
// could be double.
class DoubleFieldConverter : public FieldConverter {
 public:
  using FieldConverter::FieldConverter;
  using OperandType = double;

  ReturnCode Convert(const std::string& field_name,
                     base::Value* dict_value) const override;

  ReturnCode Validate(const std::string& field_name,
                      base::Value* dict_value) const override;

  std::string ToString() const override;

  static std::unique_ptr<DoubleFieldConverter> Build(
      const base::StringPiece& validate_rule);

  DoubleFieldConverter(ValidatorOperator op, OperandType operand)
      : operator_(op), operand_(operand) {}

  static bool StringToOperand(base::StringPiece s, OperandType* output) {
    return runtime_probe::StringToDouble(s, output);
  }

 private:
  ValidatorOperator operator_;
  OperandType operand_;

  FRIEND_TEST(DoubleFieldConverterTest, TestValidateRule);
};

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_FIELD_CONVERTER_H_
