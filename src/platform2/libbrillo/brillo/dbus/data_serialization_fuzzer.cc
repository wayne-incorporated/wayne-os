// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include <base/logging.h>
#include <base/strings/string_util.h>
#include <brillo/dbus/data_serialization.h>
#include <dbus/string_util.h>
#include <fuzzer/FuzzedDataProvider.h>

namespace {
constexpr int kRandomMaxContainerSize = 8;
constexpr int kRandomMaxDataLength = 128;

typedef enum DataType {
  kUint8 = 0,
  kUint16,
  kUint32,
  kUint64,
  kInt16,
  kInt32,
  kInt64,
  kBool,
  kDouble,
  kString,
  kObjectPath,
  // A couple vector types.
  kVectorInt16,
  kVectorString,
  // A couple pair types.
  kPairBoolInt64,
  kPairUint32String,
  // A couple tuple types.
  kTupleUint16StringBool,
  kTupleDoubleInt32ObjectPath,
  // A couple map types.
  kMapInt32String,
  kMapDoubleBool,
  kMaxValue = kMapDoubleBool,
} DataType;

template <typename T>
void AppendValue(dbus::MessageWriter* writer, bool variant, const T& value) {
  if (variant)
    brillo::dbus_utils::AppendValueToWriterAsVariant(writer, value);
  else
    brillo::dbus_utils::AppendValueToWriter(writer, value);
}

template <typename T>
void GenerateIntAndAppendValue(FuzzedDataProvider* data_provider,
                               dbus::MessageWriter* writer,
                               bool variant) {
  AppendValue(writer, variant, data_provider->ConsumeIntegral<T>());
}

template <typename T>
void PopValue(dbus::MessageReader* reader, bool variant, T* value) {
  if (variant)
    brillo::dbus_utils::PopVariantValueFromReader(reader, value);
  else
    brillo::dbus_utils::PopValueFromReader(reader, value);
}

std::string GenerateValidUTF8(FuzzedDataProvider* data_provider) {
  // >= 0x80
  // Generates a random string and returns it if it is valid UTF8, if it is not
  // then it will strip it down to all the 7-bit ASCII chars and just return
  // that string.
  std::string str =
      data_provider->ConsumeRandomLengthString(kRandomMaxDataLength);
  if (base::IsStringUTF8(str))
    return str;
  for (auto it = str.begin(); it != str.end(); it++) {
    if (static_cast<uint8_t>(*it) >= 0x80) {
      // Might be invalid, remove it.
      it = str.erase(it);
      it--;
    }
  }
  return str;
}

std::unique_ptr<dbus::Response> DemarshalRandomDBusResponse(
    FuzzedDataProvider* data_provider) {
  std::string string_to_demarshal = data_provider->ConsumeRandomLengthString();
  DBusMessage* raw_message =
      dbus_message_demarshal(string_to_demarshal.data(),
                             string_to_demarshal.size(), /*error=*/nullptr);
  if (!raw_message)
    return nullptr;
  if (dbus_message_get_type(raw_message) != DBUS_MESSAGE_TYPE_METHOD_RETURN) {
    dbus_message_unref(raw_message);
    return nullptr;
  }
  return dbus::Response::FromRawMessage(raw_message);
}

std::unique_ptr<dbus::Response> WriteRandomDBusResponse(
    FuzzedDataProvider* data_provider) {
  // Consume a random fraction of our data writing random things to a D-Bus
  // message, and then consume the remaining data reading randomly from that
  // same D-Bus message.  Given the templated nature of these functions and that
  // they support essentially an infinite amount of types, we are constraining
  // this to a fixed set of types defined above.
  std::unique_ptr<dbus::Response> message = dbus::Response::CreateEmpty();

  dbus::MessageWriter writer(message.get());

  int bytes_left_for_read =
      static_cast<int>(data_provider->ConsumeProbability<float>() *
                       data_provider->remaining_bytes());
  while (data_provider->remaining_bytes() > bytes_left_for_read) {
    DataType curr_type = data_provider->ConsumeEnum<DataType>();
    bool variant = data_provider->ConsumeBool();
    switch (curr_type) {
      case kUint8:
        GenerateIntAndAppendValue<uint8_t>(data_provider, &writer, variant);
        break;
      case kUint16:
        GenerateIntAndAppendValue<uint16_t>(data_provider, &writer, variant);
        break;
      case kUint32:
        GenerateIntAndAppendValue<uint32_t>(data_provider, &writer, variant);
        break;
      case kUint64:
        GenerateIntAndAppendValue<uint64_t>(data_provider, &writer, variant);
        break;
      case kInt16:
        GenerateIntAndAppendValue<int16_t>(data_provider, &writer, variant);
        break;
      case kInt32:
        GenerateIntAndAppendValue<int32_t>(data_provider, &writer, variant);
        break;
      case kInt64:
        GenerateIntAndAppendValue<int64_t>(data_provider, &writer, variant);
        break;
      case kBool:
        AppendValue(&writer, variant, data_provider->ConsumeBool());
        break;
      case kDouble:
        AppendValue(&writer, variant,
                    data_provider->ConsumeProbability<double>());
        break;
      case kString:
        AppendValue(&writer, variant, GenerateValidUTF8(data_provider));
        break;
      case kObjectPath: {
        std::string object_path =
            data_provider->ConsumeRandomLengthString(kRandomMaxDataLength);
        // If this isn't valid we'll hit a CHECK failure.
        if (dbus::IsValidObjectPath(object_path))
          AppendValue(&writer, variant, dbus::ObjectPath(object_path));
        break;
      }
      case kVectorInt16: {
        int vec_size = data_provider->ConsumeIntegralInRange<int>(
            0, kRandomMaxContainerSize);
        std::vector<int16_t> vec(vec_size);
        for (int i = 0; i < vec_size; i++)
          vec[i] = data_provider->ConsumeIntegral<int16_t>();
        AppendValue(&writer, variant, vec);
        break;
      }
      case kVectorString: {
        int vec_size = data_provider->ConsumeIntegralInRange<int>(
            0, kRandomMaxContainerSize);
        std::vector<std::string> vec(vec_size);
        for (int i = 0; i < vec_size; i++)
          vec[i] = GenerateValidUTF8(data_provider);
        AppendValue(&writer, variant, vec);
        break;
      }
      case kPairBoolInt64:
        AppendValue(&writer, variant,
                    std::pair<bool, int64_t>{
                        data_provider->ConsumeBool(),
                        data_provider->ConsumeIntegral<int64_t>()});
        break;
      case kPairUint32String:
        AppendValue(&writer, variant,
                    std::pair<uint32_t, std::string>{
                        data_provider->ConsumeIntegral<uint32_t>(),
                        GenerateValidUTF8(data_provider)});
        break;
      case kTupleUint16StringBool:
        AppendValue(&writer, variant,
                    std::tuple<uint32_t, std::string, bool>{
                        data_provider->ConsumeIntegral<uint32_t>(),
                        GenerateValidUTF8(data_provider),
                        data_provider->ConsumeBool()});
        break;
      case kTupleDoubleInt32ObjectPath: {
        std::string object_path =
            data_provider->ConsumeRandomLengthString(kRandomMaxDataLength);
        // If this isn't valid we'll hit a CHECK failure.
        if (dbus::IsValidObjectPath(object_path)) {
          AppendValue(&writer, variant,
                      std::tuple<double, int32_t, dbus::ObjectPath>{
                          data_provider->ConsumeProbability<double>(),
                          data_provider->ConsumeIntegral<int32_t>(),
                          dbus::ObjectPath(object_path)});
        }
        break;
      }
      case kMapInt32String: {
        int map_size = data_provider->ConsumeIntegralInRange<int>(
            0, kRandomMaxContainerSize);
        std::map<int32_t, std::string> map;
        for (int i = 0; i < map_size; i++)
          map[data_provider->ConsumeIntegral<int32_t>()] =
              GenerateValidUTF8(data_provider);
        AppendValue(&writer, variant, map);
        break;
      }
      case kMapDoubleBool: {
        int map_size = data_provider->ConsumeIntegralInRange<int>(
            0, kRandomMaxContainerSize);
        std::map<double, bool> map;
        for (int i = 0; i < map_size; i++)
          map[data_provider->ConsumeProbability<double>()] =
              data_provider->ConsumeBool();
        AppendValue(&writer, variant, map);
        break;
      }
    }
  }

  return message;
}

class Environment {
 public:
  Environment() {
    // Disable logging.
    logging::SetMinLogLevel(logging::LOGGING_FATAL);
  }
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;

  FuzzedDataProvider data_provider(data, size);

  std::unique_ptr<dbus::Response> message;
  if (data_provider.ConsumeBool())
    message = DemarshalRandomDBusResponse(&data_provider);
  else
    message = WriteRandomDBusResponse(&data_provider);
  if (!message)
    return 0;

  dbus::MessageReader reader(message.get());
  while (data_provider.remaining_bytes()) {
    DataType curr_type = data_provider.ConsumeEnum<DataType>();
    bool variant = data_provider.ConsumeBool();
    switch (curr_type) {
      case kUint8: {
        uint8_t value;
        PopValue(&reader, variant, &value);
        break;
      }
      case kUint16: {
        uint16_t value;
        PopValue(&reader, variant, &value);
        break;
      }
      case kUint32: {
        uint32_t value;
        PopValue(&reader, variant, &value);
        break;
      }
      case kUint64: {
        uint64_t value;
        PopValue(&reader, variant, &value);
        break;
      }
      case kInt16: {
        int16_t value;
        PopValue(&reader, variant, &value);
        break;
      }
      case kInt32: {
        int32_t value;
        PopValue(&reader, variant, &value);
        break;
      }
      case kInt64: {
        int64_t value;
        PopValue(&reader, variant, &value);
        break;
      }
      case kBool: {
        bool value;
        PopValue(&reader, variant, &value);
        break;
      }
      case kDouble: {
        double value;
        PopValue(&reader, variant, &value);
        break;
      }
      case kString: {
        std::string value;
        PopValue(&reader, variant, &value);
        break;
      }
      case kObjectPath: {
        dbus::ObjectPath value;
        PopValue(&reader, variant, &value);
        break;
      }
      case kVectorInt16: {
        std::vector<int16_t> value;
        PopValue(&reader, variant, &value);
        break;
      }
      case kVectorString: {
        std::vector<std::string> value;
        PopValue(&reader, variant, &value);
        break;
      }
      case kPairBoolInt64: {
        std::pair<bool, int64_t> value;
        PopValue(&reader, variant, &value);
        break;
      }
      case kPairUint32String: {
        std::pair<uint32_t, std::string> value;
        PopValue(&reader, variant, &value);
        break;
      }
      case kTupleUint16StringBool: {
        std::tuple<uint16_t, std::string, bool> value;
        break;
      }
      case kTupleDoubleInt32ObjectPath: {
        std::tuple<double, int32_t, dbus::ObjectPath> value;
        PopValue(&reader, variant, &value);
        break;
      }
      case kMapInt32String: {
        std::map<int32_t, std::string> value;
        PopValue(&reader, variant, &value);
        break;
      }
      case kMapDoubleBool: {
        std::map<double, bool> value;
        PopValue(&reader, variant, &value);
        break;
      }
    }
  }

  return 0;
}
