// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ipp_in_json.h"

#include <memory>
#include <utility>

#include <base/check.h>
#include <base/json/json_writer.h>
#include <base/values.h>
#include <chromeos/libipp/attribute.h>
#include <chromeos/libipp/frame.h>
#include <chromeos/libipp/ipp_enums.h>
#include <chromeos/libipp/parser.h>

namespace {

base::StringPiece ToStringPiece(std::string_view sv) {
  return base::StringPiece(sv.data(), sv.length());
}

base::Value SaveAsJson(const ipp::Collection& coll);

// Converts `value` from the attribute `attr` to base::Value.
template <typename ValueType>
base::Value SaveValueAsJson(const ipp::Attribute& attr,
                            const ValueType& value) {
  return base::Value(ipp::ToString(value));
}

template <>
base::Value SaveValueAsJson<int32_t>(const ipp::Attribute& attr,
                                     const int32_t& value) {
  if (attr.Tag() == ipp::ValueTag::boolean)
    return base::Value(static_cast<bool>(value));
  if (attr.Tag() == ipp::ValueTag::enum_) {
    ipp::AttrName attrName;
    if (ipp::FromString(std::string(attr.Name()), &attrName)) {
      return base::Value(ipp::ToString(attrName, value));
    }
  }
  return base::Value(value);
}

template <>
base::Value SaveValueAsJson<std::string>(const ipp::Attribute& attr,
                                         const std::string& value) {
  return base::Value(value);
}

template <>
base::Value SaveValueAsJson<ipp::StringWithLanguage>(
    const ipp::Attribute& attr, const ipp::StringWithLanguage& value) {
  base::Value::Dict obj;
  obj.Set("value", value.value);
  obj.Set("language", value.language);
  return base::Value(std::move(obj));
}

// Converts all values from `attr` to base::Value. The type of values must match
// `ValueType`.
template <typename ValueType>
base::Value SaveValuesAsJsonTyped(const ipp::Attribute& attr) {
  std::vector<ValueType> values;
  attr.GetValues(values);
  if (values.size() > 1) {
    base::Value::List arr;
    for (size_t i = 0; i < values.size(); ++i)
      arr.Append(SaveValueAsJson(attr, values[i]));
    return base::Value(std::move(arr));
  } else {
    return SaveValueAsJson(attr, values.at(0));
  }
}

template <>
base::Value SaveValuesAsJsonTyped<const ipp::Collection&>(
    const ipp::Attribute& attr) {
  ipp::ConstCollsView colls = attr.Colls();
  if (colls.size() > 1) {
    base::Value::List arr;
    for (const ipp::Collection& coll : colls)
      arr.Append(SaveAsJson(coll));
    return base::Value(std::move(arr));
  } else {
    return SaveAsJson(colls[0]);
  }
}

// It saves all attribute's values as JSON structure.
base::Value SaveValuesAsJson(const ipp::Attribute& attr) {
  switch (attr.Tag()) {
    case ipp::ValueTag::textWithLanguage:
    case ipp::ValueTag::nameWithLanguage:
      return SaveValuesAsJsonTyped<ipp::StringWithLanguage>(attr);
    case ipp::ValueTag::dateTime:
      return SaveValuesAsJsonTyped<ipp::DateTime>(attr);
    case ipp::ValueTag::resolution:
      return SaveValuesAsJsonTyped<ipp::Resolution>(attr);
    case ipp::ValueTag::rangeOfInteger:
      return SaveValuesAsJsonTyped<ipp::RangeOfInteger>(attr);
    case ipp::ValueTag::collection:
      return SaveValuesAsJsonTyped<const ipp::Collection&>(attr);
    default:
      if (ipp::IsInteger(attr.Tag()))
        return SaveValuesAsJsonTyped<int32_t>(attr);
      return SaveValuesAsJsonTyped<std::string>(attr);
  }
}

// It saves a given Collection as JSON object.
base::Value SaveAsJson(const ipp::Collection& coll) {
  base::Value::Dict obj;

  for (const ipp::Attribute& a : coll) {
    auto tag = a.Tag();
    if (!ipp::IsOutOfBand(tag)) {
      base::Value::Dict obj2;
      obj2.Set("type", ToStringPiece(ipp::ToStrView(tag)));
      obj2.Set("value", SaveValuesAsJson(a));
      obj.Set(ToStringPiece(a.Name()), std::move(obj2));
    } else {
      obj.Set(ToStringPiece(a.Name()), ToStringPiece(ipp::ToStrView(tag)));
    }
  }

  return base::Value(std::move(obj));
}

// It saves all groups from given Package as JSON object.
base::Value SaveAsJson(const ipp::Frame& pkg) {
  base::Value::Dict obj;
  for (ipp::GroupTag gt : ipp::kGroupTags) {
    auto groups = pkg.Groups(gt);
    if (groups.empty())
      continue;
    if (groups.size() > 1) {
      base::Value::List arr;
      for (const ipp::Collection& g : groups)
        arr.Append(SaveAsJson(g));
      obj.Set(ToString(gt), std::move(arr));
    } else {
      obj.Set(ToString(gt), SaveAsJson(groups[0]));
    }
  }
  return base::Value(std::move(obj));
}

// Saves given logs as JSON array.
base::Value SaveAsJson(const ipp::SimpleParserLog& log) {
  base::Value::List arr;
  for (const auto& l : log.Errors()) {
    arr.Append(base::Value(ipp::ToString(l)));
  }
  return base::Value(std::move(arr));
}

}  // namespace

bool ConvertToJson(const ipp::Frame& response,
                   const ipp::SimpleParserLog& log,
                   bool compressed_json,
                   std::string* json) {
  // Build structure.
  base::Value::Dict doc;
  doc.Set("status", ipp::ToString(response.StatusCode()));
  if (!log.Errors().empty()) {
    doc.Set("parsing_logs", SaveAsJson(log));
  }
  doc.Set("response", SaveAsJson(response));
  // Convert to JSON.
  bool result;
  if (compressed_json) {
    result = base::JSONWriter::Write(doc, json);
  } else {
    const int options = base::JSONWriter::OPTIONS_PRETTY_PRINT;
    result = base::JSONWriter::WriteWithOptions(doc, options, json);
  }
  return result;
}
