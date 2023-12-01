// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <base/check.h>
#include <base/command_line.h>
#include <base/files/file_descriptor_watcher_posix.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/run_loop.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/task/single_thread_task_executor.h>

#include <brillo/flag_helper.h>

#include <chromeos/dbus/service_constants.h>

#include "biod/biod_constants.h"
#include "biod/biod_proxy/biometrics_manager_proxy_base.h"
#include "biod/biod_version.h"
#include "biod/biometrics_manager.h"
#include "biod/proto_bindings/constants.pb.h"
#include "biod/proto_bindings/messages.pb.h"

static const char kHelpText[] =
    "biod_client_tool, used to pretend to be a biometrics client, like a lock "
    "screen or fingerprint enrollment app\n\n"
    "commands:\n"
    "  enroll <biometrics manager> <user id> <label> - Starts an enroll "
    "session for the biometrics manager that will result in the enrollment of "
    "a record with the given user ID and label.\n"
    "  authenticate <biometrics manager> - Performs authentication with the "
    "given biometrics manager until the program is interrupted.\n"
    "  list [<user_id>] - Lists available biometrics managers and optionally "
    "user's records.\n"
    "  unenroll <record> - Removes the given record.\n"
    "  set_label <record> <label> - Sets the label for the given record to "
    "<label>.\n"
    "  destroy_all [<biometrics manager>] - Destroys all records for the given "
    "biometrics manager, or all biometrics managers if no object path is "
    "given.\n"
    "  listen <biometrics manager> - Listens to the signal from given "
    "biometrics manager until the program is interrupted.\n\n"
    "The <biometrics manager> parameter is the D-Bus object path of the "
    "biometrics manager, and can be abbreviated as the path's basename (the "
    "part after the last forward slash)\n\n"
    "The <record> parameter is also a D-Bus object path.";

using BiometricsManagerType = biod::BiometricType;
using ScanResult = biod::ScanResult;
using EnrollScanDoneCallback = biod::BiometricsManager::EnrollScanDoneCallback;
using AuthScanDoneCallback = biod::BiometricsManager::AuthScanDoneCallback;
using SessionFailedCallback = biod::BiometricsManager::SessionFailedCallback;

const char* BiometricsManagerTypeToString(BiometricsManagerType type) {
  switch (type) {
    case BiometricsManagerType::BIOMETRIC_TYPE_UNKNOWN:
      return "Unknown";
    case BiometricsManagerType::BIOMETRIC_TYPE_FINGERPRINT:
      return "Fingerprint";
    default:
      return "Unknown";
  }
}

class RecordProxy {
 public:
  RecordProxy(const scoped_refptr<dbus::Bus>& bus, const dbus::ObjectPath& path)
      : bus_(bus), path_(path) {
    proxy_ = bus_->GetObjectProxy(biod::kBiodServiceName, path_);
    GetLabel();
  }

  const dbus::ObjectPath& path() const { return path_; }
  const std::string& label() const { return label_; }

  bool SetLabel(const std::string& label) {
    dbus::MethodCall method_call(biod::kRecordInterface,
                                 biod::kRecordSetLabelMethod);
    dbus::MessageWriter method_writer(&method_call);
    method_writer.AppendString(label);
    return !!proxy_->CallMethodAndBlock(&method_call,
                                        biod::dbus_constants::kDbusTimeoutMs);
  }

  bool Remove() {
    dbus::MethodCall method_call(biod::kRecordInterface,
                                 biod::kRecordRemoveMethod);
    return !!proxy_->CallMethodAndBlock(&method_call,
                                        biod::dbus_constants::kDbusTimeoutMs);
  }

 private:
  void GetLabel() {
    dbus::MethodCall method_call(dbus::kPropertiesInterface,
                                 dbus::kPropertiesGet);
    dbus::MessageWriter method_writer(&method_call);
    method_writer.AppendString(biod::kRecordInterface);
    method_writer.AppendString(biod::kRecordLabelProperty);
    std::unique_ptr<dbus::Response> response = proxy_->CallMethodAndBlock(
        &method_call, biod::dbus_constants::kDbusTimeoutMs);
    CHECK(response);

    dbus::MessageReader response_reader(response.get());
    CHECK(response_reader.PopVariantOfString(&label_));
  }

  scoped_refptr<dbus::Bus> bus_;
  dbus::ObjectPath path_;
  dbus::ObjectProxy* proxy_;

  std::string label_;
};

class BiometricsManagerProxy : public biod::BiometricsManagerProxyBase {
 public:
  using FinishCallback = base::RepeatingCallback<void(bool success)>;

  static std::unique_ptr<BiometricsManagerProxy> Create(
      const scoped_refptr<dbus::Bus>& bus,
      const dbus::ObjectPath& path,
      dbus::MessageReader* pset_reader) {
    auto biometrics_manager_proxy =
        base::WrapUnique(new BiometricsManagerProxy());

    if (!biometrics_manager_proxy->Initialize(bus, path, pset_reader))
      return nullptr;
    return biometrics_manager_proxy;
  }

  BiometricsManagerType type() const { return type_; }

  dbus::ObjectProxy* StartEnrollSession(const std::string& user_id,
                                        const std::string& label) {
    dbus::MethodCall method_call(
        biod::kBiometricsManagerInterface,
        biod::kBiometricsManagerStartEnrollSessionMethod);
    dbus::MessageWriter method_writer(&method_call);
    method_writer.AppendString(user_id);
    method_writer.AppendString(label);

    std::unique_ptr<dbus::Response> response = proxy_->CallMethodAndBlock(
        &method_call, biod::dbus_constants::kDbusTimeoutMs);
    if (!response)
      return nullptr;

    dbus::MessageReader response_reader(response.get());
    dbus::ObjectPath enroll_session_path;
    CHECK(response_reader.PopObjectPath(&enroll_session_path));
    dbus::ObjectProxy* enroll_session_proxy =
        bus_->GetObjectProxy(biod::kBiodServiceName, enroll_session_path);
    return enroll_session_proxy;
  }

  bool DestroyAllRecords() {
    dbus::MethodCall method_call(
        biod::kBiometricsManagerInterface,
        biod::kBiometricsManagerDestroyAllRecordsMethod);
    return !!proxy_->CallMethodAndBlock(&method_call,
                                        biod::dbus_constants::kDbusTimeoutMs);
  }

  std::vector<RecordProxy> GetRecordsForUser(const std::string& user_id) const {
    dbus::MethodCall method_call(
        biod::kBiometricsManagerInterface,
        biod::kBiometricsManagerGetRecordsForUserMethod);
    dbus::MessageWriter method_writer(&method_call);
    method_writer.AppendString(user_id);

    std::unique_ptr<dbus::Response> response = proxy_->CallMethodAndBlock(
        &method_call, biod::dbus_constants::kDbusTimeoutMs);

    std::vector<RecordProxy> records;
    if (!response)
      return records;

    dbus::MessageReader response_reader(response.get());
    dbus::MessageReader records_reader(nullptr);
    CHECK(response_reader.PopArray(&records_reader));
    while (records_reader.HasMoreData()) {
      dbus::ObjectPath record_path;
      CHECK(records_reader.PopObjectPath(&record_path));
      records.emplace_back(bus_, record_path);
    }
    return records;
  }

  base::WeakPtr<BiometricsManagerProxy> GetWeakPtr() {
    return weak_factory_.GetWeakPtr();
  }

 private:
  BiometricsManagerProxy() : weak_factory_(this) {}
  BiometricsManagerProxy(const BiometricsManagerProxy&) = delete;
  BiometricsManagerProxy& operator=(const BiometricsManagerProxy&) = delete;

  bool Initialize(const scoped_refptr<dbus::Bus>& bus,
                  const dbus::ObjectPath& path,
                  dbus::MessageReader* pset_reader) {
    if (!BiometricsManagerProxyBase::Initialize(bus, path)) {
      LOG(ERROR) << "Cannot get dbus object proxy for biod";
      return false;
    }

    while (pset_reader->HasMoreData()) {
      dbus::MessageReader pset_entry_reader(nullptr);
      std::string property_name;
      CHECK(pset_reader->PopDictEntry(&pset_entry_reader));
      CHECK(pset_entry_reader.PopString(&property_name));

      if (property_name == biod::kBiometricsManagerBiometricTypeProperty) {
        CHECK(pset_entry_reader.PopVariantOfUint32(
            reinterpret_cast<uint32_t*>(&type_)));
      }
    }

    proxy_->ConnectToSignal(
        biod::kBiometricsManagerInterface,
        biod::kBiometricsManagerEnrollScanDoneSignal,
        base::BindRepeating(&BiometricsManagerProxy::OnEnrollScanDone,
                            weak_factory_.GetWeakPtr()),
        base::BindOnce(&BiometricsManagerProxy::OnSignalConnected,
                       weak_factory_.GetWeakPtr()));
    proxy_->ConnectToSignal(
        biod::kBiometricsManagerInterface,
        biod::kBiometricsManagerAuthScanDoneSignal,
        base::BindRepeating(&BiometricsManagerProxy::OnAuthScanDone,
                            weak_factory_.GetWeakPtr()),
        base::BindOnce(&BiometricsManagerProxy::OnSignalConnected,
                       weak_factory_.GetWeakPtr()));
    proxy_->ConnectToSignal(
        biod::kBiometricsManagerInterface,
        biod::kBiometricsManagerStatusChangedSignal,
        base::BindRepeating(&BiometricsManagerProxy::OnStatusChanged,
                            weak_factory_.GetWeakPtr()),
        base::BindOnce(&BiometricsManagerProxy::OnSignalConnected,
                       weak_factory_.GetWeakPtr()));
    return true;
  }

  void OnEnrollScanDone(dbus::Signal* signal) {
    dbus::MessageReader signal_reader(signal);
    biod::EnrollScanDone proto;
    if (!signal_reader.PopArrayOfBytesAsProto(&proto)) {
      LOG(ERROR) << "Unable to decode protocol buffer from "
                 << biod::kBiometricsManagerEnrollScanDoneSignal << " signal.";
      return;
    }
    if (proto.has_percent_complete()) {
      LOG(INFO) << "Biometric Scanned: "
                << ScanResultToString(proto.scan_result()) << " "
                << proto.percent_complete() << "% complete";
    } else {
      LOG(INFO) << "Biometric Scanned: "
                << ScanResultToString(proto.scan_result());
    }

    if (proto.done()) {
      LOG(INFO) << "Biometric enrollment complete";
      OnFinish(true);
    }
  }

  void OnAuthScanDone(dbus::Signal* signal) {
    dbus::MessageReader signal_reader(signal);

    biod::FingerprintMessage proto;
    dbus::MessageReader matches_reader(nullptr);
    std::vector<std::string> user_ids;

    CHECK(signal_reader.PopArrayOfBytesAsProto(&proto));
    switch (proto.msg_case()) {
      case biod::FingerprintMessage::MsgCase::kScanResult:
        LOG(INFO) << "Authentication: "
                  << ScanResultToString(proto.scan_result());
        break;
      case biod::FingerprintMessage::MsgCase::kError:
        LOG(WARNING) << "Authentication failed: "
                     << FingerprintErrorToString(proto.error());
        break;
      case biod::FingerprintMessage::MsgCase::MSG_NOT_SET:
        LOG(WARNING) << "Fingerprint response doesn't contain any data";
        break;
      default:
        LOG(ERROR) << "Unsupported message received";
    }

    CHECK(signal_reader.PopArray(&matches_reader));
    while (matches_reader.HasMoreData()) {
      dbus::MessageReader entry_reader(nullptr);
      CHECK(matches_reader.PopDictEntry(&entry_reader));

      std::string user_id;
      CHECK(entry_reader.PopString(&user_id));

      dbus::MessageReader record_object_paths_reader(nullptr);
      CHECK(entry_reader.PopArray(&record_object_paths_reader));
      std::stringstream record_object_paths_joined;
      while (record_object_paths_reader.HasMoreData()) {
        dbus::ObjectPath record_object_path;
        CHECK(record_object_paths_reader.PopObjectPath(&record_object_path));
        record_object_paths_joined << " \"" << record_object_path.value()
                                   << "\"";
      }

      LOG(INFO) << "Recognized user ID \"" << user_id
                << "\" with record object paths"
                << record_object_paths_joined.str();
    }
  }

  void OnStatusChanged(dbus::Signal* signal) {
    biod::BiometricsManagerStatusChanged proto;

    dbus::MessageReader reader(signal);
    CHECK(reader.PopArrayOfBytesAsProto(&proto));

    LOG(INFO) << "Status changed to: "
              << BiometricsManagerStatusToString(proto.status());
  }

  BiometricsManagerType type_ = BiometricsManagerType::BIOMETRIC_TYPE_UNKNOWN;
  std::vector<RecordProxy> records_;
  base::WeakPtrFactory<BiometricsManagerProxy> weak_factory_;
};

class BiodProxy {
 public:
  explicit BiodProxy(const scoped_refptr<dbus::Bus>& bus) : bus_(bus) {
    proxy_ = bus_->GetObjectProxy(biod::kBiodServiceName,
                                  dbus::ObjectPath(biod::kBiodServicePath));

    dbus::MethodCall get_objects_method(dbus::kObjectManagerInterface,
                                        dbus::kObjectManagerGetManagedObjects);

    std::unique_ptr<dbus::Response> objects_msg = proxy_->CallMethodAndBlock(
        &get_objects_method, biod::dbus_constants::kDbusTimeoutMs);
    CHECK(objects_msg) << "Failed to retrieve biometrics managers.";

    dbus::MessageReader reader(objects_msg.get());
    dbus::MessageReader array_reader(nullptr);
    CHECK(reader.PopArray(&array_reader));

    while (array_reader.HasMoreData()) {
      dbus::MessageReader dict_entry_reader(nullptr);
      dbus::ObjectPath object_path;
      CHECK(array_reader.PopDictEntry(&dict_entry_reader));
      CHECK(dict_entry_reader.PopObjectPath(&object_path));

      dbus::MessageReader interface_reader(nullptr);
      CHECK(dict_entry_reader.PopArray(&interface_reader));

      while (interface_reader.HasMoreData()) {
        dbus::MessageReader interface_entry_reader(nullptr);
        std::string interface_name;
        CHECK(interface_reader.PopDictEntry(&interface_entry_reader));
        CHECK(interface_entry_reader.PopString(&interface_name));

        dbus::MessageReader pset_reader(nullptr);
        CHECK(interface_entry_reader.PopArray(&pset_reader));
        if (interface_name == biod::kBiometricsManagerInterface) {
          auto biometrics_manager =
              BiometricsManagerProxy::Create(bus_, object_path, &pset_reader);
          if (biometrics_manager)
            biometrics_managers_.emplace_back(std::move(biometrics_manager));
        }
      }
    }
  }

  base::WeakPtr<BiometricsManagerProxy> GetBiometricsManager(
      base::StringPiece path) {
    bool short_path =
        !base::StartsWith(path, "/", base::CompareCase::SENSITIVE);

    for (auto& biometrics_manager : biometrics_managers_) {
      std::string biometrics_manager_path = biometrics_manager->path().value();
      if (short_path) {
        if (base::EndsWith(biometrics_manager_path, path,
                           base::CompareCase::SENSITIVE)) {
          return biometrics_manager->GetWeakPtr();
        }
      } else if (biometrics_manager_path == path) {
        return biometrics_manager->GetWeakPtr();
      }
    }
    return nullptr;
  }

  const std::vector<std::unique_ptr<BiometricsManagerProxy>>&
  biometrics_managers() const {
    return biometrics_managers_;
  }

  int DestroyAllRecords() {
    int ret = 0;
    for (auto& biometrics_manager : biometrics_managers_) {
      if (!biometrics_manager->DestroyAllRecords()) {
        LOG(ERROR) << "Failed to destroy record from BiometricsManager at "
                   << biometrics_manager->path().value();
        ret = 1;
      }
    }
    if (ret)
      LOG(WARNING) << "Not all records were destroyed";
    return ret;
  }

 private:
  scoped_refptr<dbus::Bus> bus_;
  dbus::ObjectProxy* proxy_;

  std::vector<std::unique_ptr<BiometricsManagerProxy>> biometrics_managers_;
};

void OnFinish(base::RunLoop* run_loop, int* ret_ptr, bool success) {
  *ret_ptr = success ? 0 : 1;
  run_loop->Quit();
}

int DoEnroll(base::WeakPtr<BiometricsManagerProxy> biometrics_manager,
             const std::string& user_id,
             const std::string& label) {
  dbus::ObjectProxy* enroll_session_object =
      biometrics_manager->StartEnrollSession(user_id, label);

  if (enroll_session_object) {
    LOG(INFO) << "Biometric enrollment started";
  } else {
    LOG(ERROR) << "Biometric enrollment failed to start";
    return 1;
  }

  base::RunLoop run_loop;

  int ret = 1;
  biometrics_manager->SetFinishHandler(
      base::BindRepeating(&OnFinish, &run_loop, &ret));

  run_loop.Run();

  if (ret) {
    LOG(INFO) << "Ending biometric enrollment";
    dbus::MethodCall cancel_call(biod::kEnrollSessionInterface,
                                 biod::kEnrollSessionCancelMethod);
    enroll_session_object->CallMethodAndBlock(
        &cancel_call, biod::dbus_constants::kDbusTimeoutMs);
  }

  return ret;
}

int DoAuthenticate(base::WeakPtr<BiometricsManagerProxy> biometrics_manager) {
  bool success = biometrics_manager->StartAuthSession();

  if (!success) {
    LOG(ERROR) << "Biometric authentication failed to start";
    return 1;
  }
  LOG(INFO) << "Biometric authentication started";

  base::RunLoop run_loop;

  int ret = 1;
  biometrics_manager->SetFinishHandler(
      base::BindRepeating(&OnFinish, &run_loop, &ret));

  run_loop.Run();

  if (ret) {
    biometrics_manager->EndAuthSession();
  }

  return ret;
}

int DoListen(base::WeakPtr<BiometricsManagerProxy> biometrics_manager) {
  base::RunLoop run_loop;

  int ret = 1;
  biometrics_manager->SetFinishHandler(
      base::BindRepeating(&OnFinish, &run_loop, &ret));

  run_loop.Run();

  return ret;
}

int DoList(BiodProxy* biod, const std::string& user_id) {
  LOG(INFO) << biod::kBiodServicePath << " : BioD Root Object Path";
  for (const auto& biometrics_manager : biod->biometrics_managers()) {
    std::string biometrics_manager_path = biometrics_manager->path().value();
    if (base::StartsWith(biometrics_manager_path, biod::kBiodServicePath,
                         base::CompareCase::SENSITIVE)) {
      biometrics_manager_path =
          biometrics_manager_path.substr(sizeof(biod::kBiodServicePath));
    }
    LOG(INFO) << "  " << biometrics_manager_path << " : "
              << BiometricsManagerTypeToString(biometrics_manager->type())
              << " Biometric";

    biometrics_manager_path = biometrics_manager->path().value();

    if (user_id.empty())
      continue;

    for (const RecordProxy& record :
         biometrics_manager->GetRecordsForUser(user_id)) {
      std::string record_path(record.path().value());
      if (base::StartsWith(record_path, biometrics_manager_path,
                           base::CompareCase::SENSITIVE)) {
        record_path = record_path.substr(biometrics_manager_path.size() + 1);
      }
      LOG(INFO) << "    " << record_path
                << " : Record Label=" << record.label();
    }
  }
  return 0;
}

int main(int argc, char* argv[]) {
  brillo::FlagHelper::Init(argc, argv, kHelpText);

  biod::LogVersion();

  base::CommandLine::StringVector args =
      base::CommandLine::ForCurrentProcess()->GetArgs();

  if (args.size() == 0) {
    LOG(ERROR) << "Expected a command.";
    LOG(INFO) << "Get help with with the --help flag.";
    return 1;
  }

  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);
  base::FileDescriptorWatcher watcher(task_executor.task_runner());
  dbus::Bus::Options bus_options;
  bus_options.bus_type = dbus::Bus::SYSTEM;
  auto bus = base::MakeRefCounted<dbus::Bus>(bus_options);
  CHECK(bus->Connect()) << "Failed to connect to system D-Bus.";

  BiodProxy biod(bus.get());

  const auto& command = args[0];
  if (command == "enroll") {
    if (args.size() < 4) {
      LOG(ERROR) << "Expected 3 parameters for enroll command.";
      return 1;
    }
    base::WeakPtr<BiometricsManagerProxy> biometrics_manager =
        biod.GetBiometricsManager(args[1]);
    CHECK(biometrics_manager)
        << "Failed to find biometrics manager with given path";
    return DoEnroll(biometrics_manager, args[2], args[3]);
  }

  if (command == "authenticate") {
    if (args.size() < 2) {
      LOG(ERROR) << "Expected 2 parameters for authenticate command.";
      return 1;
    }
    base::WeakPtr<BiometricsManagerProxy> biometrics_manager =
        biod.GetBiometricsManager(args[1]);
    CHECK(biometrics_manager)
        << "Failed to find biometrics manager with given path";
    return DoAuthenticate(biometrics_manager);
  }

  if (command == "list") {
    return DoList(&biod, args.size() < 2 ? "" : args[1]);
  }

  if (command == "unenroll") {
    if (args.size() < 2) {
      LOG(ERROR) << "Expected 1 parameter for unenroll command.";
      return 1;
    }
    RecordProxy record(bus, dbus::ObjectPath(args[1]));
    return record.Remove() ? 0 : 1;
  }

  if (command == "set_label") {
    if (args.size() < 3) {
      LOG(ERROR) << "Expected 2 parameters for set_label command.";
      return 1;
    }
    RecordProxy record(bus, dbus::ObjectPath(args[1]));
    return record.SetLabel(args[2]);
  }

  if (command == "destroy_all") {
    if (args.size() >= 2) {
      base::WeakPtr<BiometricsManagerProxy> biometrics_manager =
          biod.GetBiometricsManager(args[1]);
      CHECK(biometrics_manager)
          << "Failed to find biometrics_manager with given path";
      return biometrics_manager->DestroyAllRecords() ? 0 : 1;
    } else {
      return biod.DestroyAllRecords();
    }
  }

  if (command == "listen") {
    if (args.size() != 2) {
      LOG(ERROR) << "Expected 2 parameters for listen command.";
      return 1;
    }
    base::WeakPtr<BiometricsManagerProxy> biometrics_manager =
        biod.GetBiometricsManager(args[1]);
    CHECK(biometrics_manager)
        << "Failed to find biometrics manager with given path";
    return DoListen(biometrics_manager);
  }

  LOG(ERROR) << "Unrecognized command " << command;
  LOG(INFO) << kHelpText;

  return 1;
}
