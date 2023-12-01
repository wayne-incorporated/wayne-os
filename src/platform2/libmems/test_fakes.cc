// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libmems/test_fakes.h"

#include <linux/iio/events.h>
#include <sys/eventfd.h>

#include <array>
#include <iterator>
#include <optional>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include "base/posix/eintr_wrapper.h"

#include "libmems/common_types.h"

namespace libmems {
namespace fakes {

FakeIioChannel::FakeIioChannel(const std::string& id, bool enabled)
    : id_(id), enabled_(enabled) {}

void FakeIioChannel::SetEnabled(bool en) {
  enabled_ = en;
}

bool FakeIioChannel::SetScanElementsEnabled(bool en) {
  scan_elements_enabled_ = en;
  return true;
}

template <typename T>
std::optional<T> FakeReadAttributes(const std::string& name,
                                    std::map<std::string, T> attributes) {
  auto k = attributes.find(name);
  if (k == attributes.end())
    return std::nullopt;
  return k->second;
}

std::optional<std::string> FakeIioChannel::ReadStringAttribute(
    const std::string& name) const {
  return FakeReadAttributes<>(name, text_attributes_);
}
std::optional<int64_t> FakeIioChannel::ReadNumberAttribute(
    const std::string& name) const {
  return FakeReadAttributes<>(name, numeric_attributes_);
}
std::optional<double> FakeIioChannel::ReadDoubleAttribute(
    const std::string& name) const {
  return FakeReadAttributes<>(name, double_attributes_);
}

bool FakeIioChannel::WriteStringAttribute(const std::string& name,
                                          const std::string& value) {
  text_attributes_[name] = value;
  return true;
}
bool FakeIioChannel::WriteNumberAttribute(const std::string& name,
                                          int64_t value) {
  numeric_attributes_[name] = value;
  return true;
}
bool FakeIioChannel::WriteDoubleAttribute(const std::string& name,
                                          double value) {
  double_attributes_[name] = value;
  return true;
}

std::optional<int64_t> FakeIioChannel::GetData(int index) {
  if (!enabled_ || index < 0 || index >= std::size(kFakeAccelSamples))
    return std::nullopt;

  auto raw = ReadNumberAttribute(kRawAttr);
  if (raw.has_value())
    return raw;

  for (int i = 0; i < std::size(kFakeAccelChns); ++i) {
    if (id_.compare(kFakeAccelChns[i]) == 0)
      return kFakeAccelSamples[index][i];
  }

  return std::nullopt;
}

FakeIioEvent::FakeIioEvent(iio_chan_type chan_type,
                           iio_event_type event_type,
                           iio_event_direction direction,
                           int channel)
    : IioEvent(chan_type, event_type, direction, channel) {}

void FakeIioEvent::SetEnabled(bool en) {
  enabled_ = en;
}

std::optional<std::string> FakeIioEvent::ReadStringAttribute(
    const std::string& name) const {
  auto k = text_attributes_.find(name);
  if (k == text_attributes_.end())
    return std::nullopt;
  return k->second;
}

bool FakeIioEvent::WriteStringAttribute(const std::string& name,
                                        const std::string& value) {
  text_attributes_[name] = value;
  return true;
}

std::optional<uint64_t> FakeIioEvent::GetData(int index) {
  if (index >= kEventNumber)
    return std::nullopt;

  iio_event_direction dir =
      (direction_ == iio_event_direction::IIO_EV_DIR_EITHER)
          ? (dir_turn_ ? iio_event_direction::IIO_EV_DIR_RISING
                       : iio_event_direction::IIO_EV_DIR_FALLING)
          : direction_;

  dir_turn_ = !dir_turn_;
  return IioEventCode(chan_type_, event_type_, dir, channel_);
}

FakeIioDevice::FakeIioDevice(FakeIioContext* ctx,
                             const std::string& name,
                             int id)
    : IioDevice(), context_(ctx), name_(name), id_(id) {}

base::FilePath FakeIioDevice::GetPath() const {
  if (!path_.empty())
    return path_;

  std::string id_str(kDeviceIdPrefix);
  id_str.append(std::to_string(GetId()));
  return base::FilePath(kSysDevString).Append(id_str);
}

std::optional<std::string> FakeIioDevice::ReadStringAttribute(
    const std::string& name) const {
  if (name.compare(kDeviceName) == 0)
    return name_;
  return FakeReadAttributes<>(name, text_attributes_);
}
std::optional<int64_t> FakeIioDevice::ReadNumberAttribute(
    const std::string& name) const {
  return FakeReadAttributes<>(name, numeric_attributes_);
}
std::optional<double> FakeIioDevice::ReadDoubleAttribute(
    const std::string& name) const {
  return FakeReadAttributes<>(name, double_attributes_);
}

bool FakeIioDevice::WriteStringAttribute(const std::string& name,
                                         const std::string& value) {
  text_attributes_[name] = value;
  return true;
}
bool FakeIioDevice::WriteNumberAttribute(const std::string& name,
                                         int64_t value) {
  numeric_attributes_[name] = value;
  return true;
}
bool FakeIioDevice::WriteDoubleAttribute(const std::string& name,
                                         double value) {
  double_attributes_[name] = value;
  return true;
}

bool FakeIioDevice::SetTrigger(IioDevice* trigger) {
  trigger_ = trigger;
  return true;
}

bool FakeIioDevice::EnableBuffer(size_t n) {
  buffer_length_ = n;
  buffer_enabled_ = true;
  return true;
}
bool FakeIioDevice::DisableBuffer() {
  buffer_enabled_ = false;
  return true;
}
bool FakeIioDevice::IsBufferEnabled(size_t* n) const {
  if (n && buffer_enabled_)
    *n = buffer_length_;
  return buffer_enabled_;
}

bool FakeIioDevice::CreateBuffer() {
  if (disabled_fd_ || sample_fd_.is_valid())
    return false;

  int fd = eventfd(0, 0);
  CHECK_GE(fd, 0);
  sample_fd_.fd.reset(fd);

  if (sample_fd_.index >= std::size(kFakeAccelSamples) || sample_fd_.is_paused)
    return true;

  if (!sample_fd_.WriteByte()) {
    sample_fd_.ClosePipe();
    return false;
  }

  return true;
}

std::optional<int32_t> FakeIioDevice::GetBufferFd() {
  if (disabled_fd_ || !sample_fd_.is_valid())
    return std::nullopt;

  return sample_fd_.get();
}

std::optional<IioDevice::IioSample> FakeIioDevice::ReadSample() {
  if (sample_fd_.is_paused || disabled_fd_ || !sample_fd_.is_valid())
    return std::nullopt;

  if (!sample_fd_.failed_read_queue.empty()) {
    CHECK_GE(sample_fd_.failed_read_queue.top(), sample_fd_.index);
    if (sample_fd_.failed_read_queue.top() == sample_fd_.index) {
      sample_fd_.failed_read_queue.pop();
      return std::nullopt;
    }
  }

  if (!sample_fd_.ReadByte())
    return std::nullopt;

  std::optional<double> freq_opt = ReadDoubleAttribute(kSamplingFrequencyAttr);
  if (!freq_opt.has_value()) {
    LOG(ERROR) << "sampling_frequency not set";
    return std::nullopt;
  }
  double frequency = freq_opt.value();
  if (frequency <= 0.0) {
    LOG(ERROR) << "Invalid frequency: " << frequency;
    return std::nullopt;
  }

  IioDevice::IioSample sample;
  auto channels = GetAllChannels();
  for (int32_t i = 0; i < channels.size(); ++i) {
    FakeIioChannel* chn = dynamic_cast<FakeIioChannel*>(channels[i]);
    auto value = chn->GetData(sample_fd_.index);
    if (!value.has_value()) {
      LOG(ERROR) << "Channel: " << channels_[i].chn_id << " has no sample";
      return std::nullopt;
    }

    sample[i] = value.value();
  }

  sample_fd_.index += 1;

  if (sample_fd_.index < std::size(kFakeAccelSamples)) {
    if (sample_fd_.pause_index.has_value() &&
        sample_fd_.index == sample_fd_.pause_index.value()) {
      sample_fd_.SetPause();
    } else if (!sample_fd_.WriteByte()) {
      return std::nullopt;
    }
  }

  return sample;
}

void FakeIioDevice::FreeBuffer() {
  sample_fd_.ClosePipe();
}

std::optional<int32_t> FakeIioDevice::GetEventFd() {
  if (disabled_fd_)
    return std::nullopt;

  if (!event_fd_.is_valid()) {
    int fd = eventfd(0, 0);
    CHECK_GE(fd, 0);
    event_fd_.fd.reset(fd);

    if (event_fd_.index < kEventNumber && !event_fd_.is_paused &&
        !event_fd_.readable) {
      if (!event_fd_.WriteByte()) {
        event_fd_.ClosePipe();
        return std::nullopt;
      }
    }
  }

  return event_fd_.get();
}

std::optional<iio_event_data> FakeIioDevice::ReadEvent() {
  if (event_fd_.is_paused || disabled_fd_ || !event_fd_.is_valid())
    return std::nullopt;

  if (!event_fd_.failed_read_queue.empty()) {
    CHECK_GE(event_fd_.failed_read_queue.top(), event_fd_.index);
    if (event_fd_.failed_read_queue.top() == event_fd_.index) {
      event_fd_.failed_read_queue.pop();
      return std::nullopt;
    }
  }

  if (!event_fd_.ReadByte())
    return std::nullopt;

  iio_event_data data;
  data.timestamp = 1000000000LL * (int64_t)event_fd_.index;

  auto iio_events = GetAllEvents();
  if (!iio_events.empty()) {
    FakeIioEvent* iio_event = dynamic_cast<FakeIioEvent*>(
        iio_events[event_fd_.index % iio_events.size()]);
    auto value = iio_event->GetData(event_fd_.index);
    if (value.has_value()) {
      data.id = value.value();
    } else {
      LOG(ERROR) << "Event: " << event_fd_.index % iio_events.size()
                 << " has no data";
    }
  }

  event_fd_.index += 1;

  if (event_fd_.index < kEventNumber) {
    if (event_fd_.pause_index.has_value() &&
        event_fd_.index == event_fd_.pause_index.value()) {
      event_fd_.SetPause();
    } else if (!event_fd_.WriteByte()) {
      return std::nullopt;
    }
  }

  return data;
}

void FakeIioDevice::DisableFd() {
  disabled_fd_ = true;
  if (sample_fd_.readable)
    CHECK(sample_fd_.ReadByte());
}

void FakeIioDevice::AddFailedReadAtKthSample(int k) {
  CHECK_GE(k, sample_fd_.index);

  sample_fd_.failed_read_queue.push(k);
}

void FakeIioDevice::SetPauseCallbackAtKthSamples(
    int k, base::OnceCallback<void()> callback) {
  CHECK_GE(k, sample_fd_.index);
  CHECK_LE(k, std::size(kFakeAccelSamples));
  CHECK(!sample_fd_.pause_index.has_value());  // pause callback hasn't been set

  sample_fd_.pause_index = k;
  sample_fd_.pause_callback = std::move(callback);

  if (sample_fd_.pause_index.value() != sample_fd_.index)
    return;

  sample_fd_.SetPause();
}

void FakeIioDevice::ResumeReadingSamples() {
  sample_fd_.ResumeReading();
}

void FakeIioDevice::AddFailedReadAtKthEvent(int k) {
  CHECK_GE(k, event_fd_.index);

  event_fd_.failed_read_queue.push(k);
}

void FakeIioDevice::SetPauseCallbackAtKthEvents(
    int k, base::OnceCallback<void()> callback) {
  CHECK_GE(k, event_fd_.index);
  CHECK_LE(k, kEventNumber);
  CHECK(!event_fd_.pause_index.has_value());  // pause callback hasn't been set

  event_fd_.pause_index = k;
  event_fd_.pause_callback = std::move(callback);

  if (event_fd_.pause_index.value() != event_fd_.index)
    return;

  event_fd_.SetPause();
}

void FakeIioDevice::ResumeReadingEvents() {
  event_fd_.ResumeReading();
}

bool FakeIioDevice::FakeFD::WriteByte() {
  if (!is_valid())
    return false;

  CHECK(!readable);
  uint64_t val = 1;
  CHECK_EQ(write(get(), &val, sizeof(uint64_t)), sizeof(uint64_t));
  readable = true;

  return true;
}

bool FakeIioDevice::FakeFD::ReadByte() {
  if (!is_valid())
    return false;

  CHECK(readable);
  int64_t val = 1;
  CHECK_EQ(read(get(), &val, sizeof(uint64_t)), sizeof(uint64_t));
  readable = false;

  return true;
}

void FakeIioDevice::FakeFD::ClosePipe() {
  fd.reset();
}

void FakeIioDevice::FakeFD::SetPause() {
  is_paused = true;
  pause_index.reset();
  std::move(pause_callback).Run();
  if (readable)
    CHECK(ReadByte());
}

void FakeIioDevice::FakeFD::ResumeReading() {
  CHECK(is_paused);

  is_paused = false;
  if (is_valid() && !readable)
    CHECK(WriteByte());
}

void FakeIioContext::AddDevice(std::unique_ptr<FakeIioDevice> device) {
  CHECK(device.get());
  devices_.emplace(device->GetId(), std::move(device));
}

void FakeIioContext::AddTrigger(std::unique_ptr<FakeIioDevice> trigger) {
  CHECK(trigger.get());
  triggers_.emplace(trigger->GetId(), std::move(trigger));
}

std::vector<IioDevice*> FakeIioContext::GetDevicesByName(
    const std::string& name) {
  return GetFakeByName(name, devices_);
}

IioDevice* FakeIioContext::GetDeviceById(int id) {
  return GetFakeById(id, devices_);
}

std::vector<IioDevice*> FakeIioContext::GetAllDevices() {
  return GetFakeAll(devices_);
}

std::vector<IioDevice*> FakeIioContext::GetTriggersByName(
    const std::string& name) {
  return GetFakeByName(name, triggers_);
}

IioDevice* FakeIioContext::GetTriggerById(int id) {
  return GetFakeById(id, triggers_);
}

std::vector<IioDevice*> FakeIioContext::GetAllTriggers() {
  return GetFakeAll(triggers_);
}

IioDevice* FakeIioContext::GetFakeById(
    int id, const std::map<int, std::unique_ptr<FakeIioDevice>>& devices_map) {
  auto k = devices_map.find(id);
  return (k == devices_map.end()) ? nullptr : k->second.get();
}

std::vector<IioDevice*> FakeIioContext::GetFakeByName(
    const std::string& name,
    const std::map<int, std::unique_ptr<FakeIioDevice>>& devices_map) {
  std::vector<IioDevice*> devices;
  for (auto const& it : devices_map) {
    if (name.compare(it.second->GetName()) == 0)
      devices.push_back(it.second.get());
  }

  return devices;
}

std::vector<IioDevice*> FakeIioContext::GetFakeAll(
    const std::map<int, std::unique_ptr<FakeIioDevice>>& devices_map) {
  std::vector<IioDevice*> devices;
  for (auto const& it : devices_map)
    devices.push_back(it.second.get());

  return devices;
}

}  // namespace fakes
}  // namespace libmems
