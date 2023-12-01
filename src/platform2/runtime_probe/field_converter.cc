// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime_probe/field_converter.h"

#include <inttypes.h>

#include <memory>

#include <base/check.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_number_conversions.h>
#include <base/values.h>

namespace runtime_probe {

namespace {
using ReturnCode = FieldConverter::ReturnCode;

constexpr const char* GetPrefix(ValidatorOperator op) {
  switch (op) {
    case ValidatorOperator::NOP:
      return "!nop ";
    case ValidatorOperator::RE:
      return "!re ";
    case ValidatorOperator::EQ:
      return "!eq ";
    case ValidatorOperator::NE:
      return "!ne ";
    case ValidatorOperator::GT:
      return "!gt ";
    case ValidatorOperator::GE:
      return "!ge ";
    case ValidatorOperator::LT:
      return "!lt ";
    case ValidatorOperator::LE:
      return "!le ";
    default:
      DCHECK(false) << "should never reach here";
  }
  return nullptr;
}

constexpr const char* ToString(ValidatorOperator op) {
  switch (op) {
    case ValidatorOperator::NOP:
      return "NOP";
    case ValidatorOperator::RE:
      return "RE";
    case ValidatorOperator::EQ:
      return "EQ";
    case ValidatorOperator::NE:
      return "NE";
    case ValidatorOperator::GT:
      return "GT";
    case ValidatorOperator::GE:
      return "GE";
    case ValidatorOperator::LT:
      return "LT";
    case ValidatorOperator::LE:
      return "LE";
    default:
      DCHECK(false) << "should never reach here";
  }
  return nullptr;
}

bool SplitValidateRuleString(const base::StringPiece& validate_rule,
                             ValidatorOperator* operator_,
                             base::StringPiece* operand) {
  if (validate_rule.empty()) {
    *operator_ = ValidatorOperator::NOP;
    *operand = "";
    return true;
  }

  auto first_space_idx = validate_rule.find_first_of(' ');
  auto prefix = validate_rule.substr(0, first_space_idx + 1);
  auto rest = validate_rule.substr(first_space_idx + 1);

  for (int i = 0; i < static_cast<int>(ValidatorOperator::NUM_OP); i++) {
    auto op = static_cast<ValidatorOperator>(i);
    if (prefix == GetPrefix(op)) {
      *operator_ = op;
      if (op != ValidatorOperator::NOP)  // NOP shouldn't have operand.
        *operand = rest;
      return true;
    }
  }
  return false;
}

template <typename ConverterType>
std::unique_ptr<ConverterType> BuildNumericConverter(
    const base::StringPiece& validate_rule) {
  ValidatorOperator op;
  base::StringPiece rest;

  if (SplitValidateRuleString(validate_rule, &op, &rest)) {
    if (op == ValidatorOperator::NOP)
      return std::make_unique<ConverterType>(op, 0);

    if (op == ValidatorOperator::EQ || op == ValidatorOperator::NE ||
        op == ValidatorOperator::GT || op == ValidatorOperator::GE ||
        op == ValidatorOperator::LT || op == ValidatorOperator::LE) {
      typename ConverterType::OperandType operand;
      if (ConverterType::StringToOperand(rest, &operand)) {
        return std::make_unique<ConverterType>(op, operand);
      } else {
        LOG(ERROR) << "Can't convert to operand: " << rest;
      }
    }
  }
  LOG(ERROR) << "Invalid validate rule: " << validate_rule;
  return nullptr;
}

template <typename ValueType>
ReturnCode CheckNumber(ValidatorOperator op,
                       const ValueType lhs,
                       const ValueType rhs) {
  bool is_valid = true;
  switch (op) {
    case ValidatorOperator::NOP:
      break;
    case ValidatorOperator::EQ:
      is_valid = lhs == rhs;
      break;
    case ValidatorOperator::GE:
      is_valid = lhs >= rhs;
      break;
    case ValidatorOperator::GT:
      is_valid = lhs > rhs;
      break;
    case ValidatorOperator::LE:
      is_valid = lhs <= rhs;
      break;
    case ValidatorOperator::LT:
      is_valid = lhs < rhs;
      break;
    case ValidatorOperator::NE:
      is_valid = lhs != rhs;
      break;
    default:
      return ReturnCode::UNSUPPORTED_OPERATOR;
  }
  return is_valid ? ReturnCode::OK : ReturnCode::INVALID_VALUE;
}

}  // namespace

std::string StringFieldConverter::ToString() const {
  return base::StringPrintf("StringFieldConverter(%s, %s)",
                            ::runtime_probe::ToString(operator_),
                            operand_.c_str());
}

std::string IntegerFieldConverter::ToString() const {
  return base::StringPrintf("IntegerFieldConverter(%s, %d)",
                            ::runtime_probe::ToString(operator_), operand_);
}

std::string HexFieldConverter::ToString() const {
  return base::StringPrintf("HexFieldConverter(%s, 0x%" PRIx64 ")",
                            ::runtime_probe::ToString(operator_), operand_);
}

std::string DoubleFieldConverter::ToString() const {
  return base::StringPrintf("DoubleFieldConverter(%s, %f)",
                            ::runtime_probe::ToString(operator_), operand_);
}

std::unique_ptr<StringFieldConverter> StringFieldConverter::Build(
    const base::StringPiece& validate_rule) {
  ValidatorOperator op;
  base::StringPiece pattern;

  if (SplitValidateRuleString(validate_rule, &op, &pattern)) {
    if (op == ValidatorOperator::NOP)
      return std::make_unique<StringFieldConverter>(op, "");

    if (op == ValidatorOperator::EQ || op == ValidatorOperator::NE) {
      return std::make_unique<StringFieldConverter>(op, pattern);
    }

    if (op == ValidatorOperator::RE) {
      auto instance = std::make_unique<StringFieldConverter>(op, pattern);
      if (instance->regex_->error().empty()) {
        // No error, the pattern is valid.
        return instance;
      }
      // Error string is set to non-empty if there are errors.
      LOG(ERROR) << "Invalid pattern: " << pattern;
      LOG(ERROR) << instance->regex_->error();
    }
  }

  LOG(ERROR) << "Invalid validate rule: " << validate_rule;
  return nullptr;
}

std::unique_ptr<IntegerFieldConverter> IntegerFieldConverter::Build(
    const base::StringPiece& validate_rule) {
  return BuildNumericConverter<IntegerFieldConverter>(validate_rule);
}

std::unique_ptr<HexFieldConverter> HexFieldConverter::Build(
    const base::StringPiece& validate_rule) {
  return BuildNumericConverter<HexFieldConverter>(validate_rule);
}

std::unique_ptr<DoubleFieldConverter> DoubleFieldConverter::Build(
    const base::StringPiece& validate_rule) {
  return BuildNumericConverter<DoubleFieldConverter>(validate_rule);
}

ReturnCode StringFieldConverter::Convert(const std::string& field_name,
                                         base::Value* dict_value) const {
  CHECK(dict_value);
  auto& dict = dict_value->GetDict();

  auto* value = dict.Find(field_name);
  if (!value)
    return ReturnCode::FIELD_NOT_FOUND;

  switch (value->type()) {
    case base::Value::Type::DOUBLE:
      dict.Set(field_name, std::to_string(value->GetDouble()));
      return ReturnCode::OK;
    case base::Value::Type::INTEGER:
      dict.Set(field_name, std::to_string(value->GetInt()));
      return ReturnCode::OK;
    case base::Value::Type::NONE:
      dict.Set(field_name, "null");
      return ReturnCode::OK;
    case base::Value::Type::STRING:
      return ReturnCode::OK;
    default:
      return ReturnCode::INCOMPATIBLE_VALUE;
  }
}

ReturnCode IntegerFieldConverter::Convert(const std::string& field_name,
                                          base::Value* dict_value) const {
  CHECK(dict_value);
  auto& dict = dict_value->GetDict();

  auto* value = dict.Find(field_name);
  if (!value)
    return ReturnCode::FIELD_NOT_FOUND;

  switch (value->type()) {
    case base::Value::Type::DOUBLE:
      dict.Set(field_name, static_cast<int>(value->GetDouble()));
      return ReturnCode::OK;
    case base::Value::Type::INTEGER:
      return ReturnCode::OK;
    case base::Value::Type::STRING: {
      const auto& string_value = value->GetString();
      OperandType int_value;
      if (StringToOperand(string_value, &int_value)) {
        dict.Set(field_name, int_value);
        return ReturnCode::OK;
      } else {
        LOG(ERROR) << "Failed to convert '" << string_value << "' to integer.";
        return ReturnCode::INCOMPATIBLE_VALUE;
      }
    }
    default:
      return ReturnCode::INCOMPATIBLE_VALUE;
  }
}

ReturnCode HexFieldConverter::Convert(const std::string& field_name,
                                      base::Value* dict_value) const {
  CHECK(dict_value);
  if (!dict_value->is_dict()) {
    return ReturnCode::FIELD_NOT_FOUND;
  }
  auto& dict = dict_value->GetDict();

  auto* value = dict.Find(field_name);
  if (!value)
    return ReturnCode::FIELD_NOT_FOUND;

  OperandType int_value;
  switch (value->type()) {
    case base::Value::Type::DOUBLE:
      dict.Set(field_name, static_cast<int>(value->GetDouble()));
      return ReturnCode::OK;
    case base::Value::Type::INTEGER: {
      int_value = value->GetInt();
      break;
    }
    case base::Value::Type::STRING: {
      const auto& string_value_ = value->GetString();
      if (!StringToOperand(string_value_, &int_value)) {
        LOG(ERROR) << "Failed to convert '" << string_value_ << "' to integer.";
        return ReturnCode::INCOMPATIBLE_VALUE;
      }
      break;
    }
    default:
      return ReturnCode::INCOMPATIBLE_VALUE;
  }
  // Since base::Value only supports 32-bit integer, we use string field to
  // store large integers.  We convert values to decimal strings to make
  // google::protobuf::util::JsonStringToMessage parse strings to integers
  // correctly.
  const auto string_value = base::NumberToString(int_value);
  dict.Set(field_name, string_value);
  return ReturnCode::OK;
}

ReturnCode DoubleFieldConverter::Convert(const std::string& field_name,
                                         base::Value* dict_value) const {
  CHECK(dict_value);
  if (!dict_value->is_dict()) {
    return ReturnCode::FIELD_NOT_FOUND;
  }
  auto& dict = dict_value->GetDict();

  auto* value = dict.Find(field_name);
  if (!value)
    return ReturnCode::FIELD_NOT_FOUND;

  switch (value->type()) {
    case base::Value::Type::DOUBLE:
      return ReturnCode::OK;
    case base::Value::Type::INTEGER:
      dict.Set(field_name, value->GetDouble());
      return ReturnCode::OK;
    case base::Value::Type::STRING: {
      const auto& string_value = value->GetString();
      double double_value;
      if (StringToDouble(string_value, &double_value)) {
        dict.Set(field_name, double_value);
        return ReturnCode::OK;
      } else {
        LOG(ERROR) << "Failed to convert '" << string_value << "' to double.";
        return ReturnCode::INCOMPATIBLE_VALUE;
      }
    }
    default:
      return ReturnCode::INCOMPATIBLE_VALUE;
  }
}

ReturnCode StringFieldConverter::Validate(const std::string& field_name,
                                          base::Value* dict_value) const {
  CHECK(dict_value);
  if (!dict_value->is_dict()) {
    return ReturnCode::FIELD_NOT_FOUND;
  }
  const auto& dict = dict_value->GetDict();

  auto* value_ = dict.Find(field_name);
  if (!value_)
    return ReturnCode::FIELD_NOT_FOUND;
  if (!value_->is_string())
    return ReturnCode::INCOMPATIBLE_VALUE;

  const auto& value = value_->GetString();
  bool is_valid = true;
  switch (operator_) {
    case ValidatorOperator::NOP:
      break;
    case ValidatorOperator::EQ:
      is_valid = value == operand_;
      break;
    case ValidatorOperator::RE:
      is_valid = regex_->FullMatch(value);
      break;
    case ValidatorOperator::NE:
      is_valid = value != operand_;
      break;
    default:
      return ReturnCode::UNSUPPORTED_OPERATOR;
  }
  return is_valid ? ReturnCode::OK : ReturnCode::INVALID_VALUE;
}

ReturnCode IntegerFieldConverter::Validate(const std::string& field_name,
                                           base::Value* dict_value) const {
  CHECK(dict_value);
  if (!dict_value->is_dict()) {
    return ReturnCode::FIELD_NOT_FOUND;
  }
  const auto& dict = dict_value->GetDict();

  auto* value_ = dict.Find(field_name);
  if (!value_)
    return ReturnCode::FIELD_NOT_FOUND;
  if (!value_->is_int())
    return ReturnCode::INCOMPATIBLE_VALUE;
  const auto value = value_->GetInt();

  return CheckNumber(operator_, value, operand_);
}

ReturnCode HexFieldConverter::Validate(const std::string& field_name,
                                       base::Value* dict_value) const {
  CHECK(dict_value);
  if (!dict_value->is_dict()) {
    return ReturnCode::FIELD_NOT_FOUND;
  }
  const auto& dict = dict_value->GetDict();

  auto* value_ = dict.Find(field_name);
  if (!value_)
    return ReturnCode::FIELD_NOT_FOUND;
  OperandType value;
  switch (value_->type()) {
    case base::Value::Type::INTEGER: {
      value = value_->GetInt();
      break;
    }
    case base::Value::Type::STRING: {
      const auto& string_value = value_->GetString();
      if (!StringToInt64(string_value, &value))
        return ReturnCode::INCOMPATIBLE_VALUE;
      break;
    }
    default:
      return ReturnCode::INCOMPATIBLE_VALUE;
  }
  return CheckNumber(operator_, value, operand_);
}

ReturnCode DoubleFieldConverter::Validate(const std::string& field_name,
                                          base::Value* dict_value) const {
  CHECK(dict_value);
  if (!dict_value->is_dict()) {
    return ReturnCode::FIELD_NOT_FOUND;
  }
  const auto& dict = dict_value->GetDict();

  auto* value_ = dict.Find(field_name);
  if (!value_)
    return ReturnCode::FIELD_NOT_FOUND;
  if (!value_->is_double() && !value_->is_int())
    return ReturnCode::INCOMPATIBLE_VALUE;
  const auto value = value_->GetDouble();

  return CheckNumber(operator_, value, operand_);
}

}  // namespace runtime_probe
