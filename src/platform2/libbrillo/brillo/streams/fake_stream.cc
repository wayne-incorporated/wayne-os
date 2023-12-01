// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <brillo/streams/fake_stream.h>

#include <algorithm>
#include <utility>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <brillo/message_loops/message_loop.h>
#include <brillo/streams/stream_utils.h>

namespace brillo {

namespace {

// Gets a delta between the two times, makes sure that the delta is positive.
base::TimeDelta CalculateDelay(const base::Time& now,
                               const base::Time& delay_until) {
  const base::TimeDelta zero_delay;
  if (delay_until.is_null() || now >= delay_until) {
    return zero_delay;
  }

  base::TimeDelta delay = delay_until - now;
  if (delay < zero_delay)
    delay = zero_delay;
  return delay;
}

}  // anonymous namespace

FakeStream::FakeStream(Stream::AccessMode mode, base::Clock* clock)
    : mode_{mode}, clock_{clock} {}

void FakeStream::AddReadPacketData(base::TimeDelta delay,
                                   const void* data,
                                   size_t size) {
  auto* byte_ptr = static_cast<const uint8_t*>(data);
  AddReadPacketData(delay, brillo::Blob{byte_ptr, byte_ptr + size});
}

void FakeStream::AddReadPacketData(base::TimeDelta delay, brillo::Blob data) {
  InputDataPacket packet;
  packet.data = std::move(data);
  packet.delay_before = delay;
  incoming_queue_.push(std::move(packet));
}

void FakeStream::AddReadPacketString(base::TimeDelta delay,
                                     const std::string& data) {
  AddReadPacketData(delay, brillo::Blob{data.begin(), data.end()});
}

void FakeStream::QueueReadError(base::TimeDelta delay) {
  QueueReadErrorWithMessage(delay, std::string{});
}

void FakeStream::QueueReadErrorWithMessage(base::TimeDelta delay,
                                           const std::string& message) {
  InputDataPacket packet;
  packet.data.assign(message.begin(), message.end());
  packet.delay_before = delay;
  packet.read_error = true;
  incoming_queue_.push(std::move(packet));
}

void FakeStream::ClearReadQueue() {
  std::queue<InputDataPacket>().swap(incoming_queue_);
  delay_input_until_ = base::Time{};
  input_buffer_.clear();
  input_ptr_ = 0;
  report_read_error_ = 0;
}

void FakeStream::ExpectWritePacketSize(base::TimeDelta delay,
                                       size_t data_size) {
  OutputDataPacket packet;
  packet.expected_size = data_size;
  packet.delay_before = delay;
  outgoing_queue_.push(std::move(packet));
}

void FakeStream::ExpectWritePacketData(base::TimeDelta delay,
                                       const void* data,
                                       size_t size) {
  auto* byte_ptr = static_cast<const uint8_t*>(data);
  ExpectWritePacketData(delay, brillo::Blob{byte_ptr, byte_ptr + size});
}

void FakeStream::ExpectWritePacketData(base::TimeDelta delay,
                                       brillo::Blob data) {
  OutputDataPacket packet;
  packet.expected_size = data.size();
  packet.data = std::move(data);
  packet.delay_before = delay;
  outgoing_queue_.push(std::move(packet));
}

void FakeStream::ExpectWritePacketString(base::TimeDelta delay,
                                         const std::string& data) {
  ExpectWritePacketData(delay, brillo::Blob{data.begin(), data.end()});
}

void FakeStream::QueueWriteError(base::TimeDelta delay) {
  QueueWriteErrorWithMessage(delay, std::string{});
}

void FakeStream::QueueWriteErrorWithMessage(base::TimeDelta delay,
                                            const std::string& message) {
  OutputDataPacket packet;
  packet.expected_size = 0;
  packet.data.assign(message.begin(), message.end());
  packet.delay_before = delay;
  packet.write_error = true;
  outgoing_queue_.push(std::move(packet));
}

void FakeStream::ClearWriteQueue() {
  std::queue<OutputDataPacket>().swap(outgoing_queue_);
  delay_output_until_ = base::Time{};
  output_buffer_.clear();
  expected_output_data_.clear();
  max_output_buffer_size_ = 0;
  all_output_data_.clear();
  report_write_error_ = 0;
}

const brillo::Blob& FakeStream::GetFlushedOutputData() const {
  return all_output_data_;
}

std::string FakeStream::GetFlushedOutputDataAsString() const {
  return std::string{all_output_data_.begin(), all_output_data_.end()};
}

bool FakeStream::CanRead() const {
  return stream_utils::IsReadAccessMode(mode_);
}

bool FakeStream::CanWrite() const {
  return stream_utils::IsWriteAccessMode(mode_);
}

bool FakeStream::SetSizeBlocking(uint64_t /* size */, ErrorPtr* error) {
  return stream_utils::ErrorOperationNotSupported(FROM_HERE, error);
}

bool FakeStream::Seek(int64_t /* offset */,
                      Whence /* whence */,
                      uint64_t* /* new_position */,
                      ErrorPtr* error) {
  return stream_utils::ErrorOperationNotSupported(FROM_HERE, error);
}

bool FakeStream::IsReadBufferEmpty() const {
  return input_ptr_ >= input_buffer_.size();
}

bool FakeStream::PopReadPacket() {
  if (incoming_queue_.empty())
    return false;
  InputDataPacket& packet = incoming_queue_.front();
  input_ptr_ = 0;
  input_buffer_ = std::move(packet.data);
  delay_input_until_ = clock_->Now() + packet.delay_before;
  report_read_error_ = packet.read_error;
  incoming_queue_.pop();
  return true;
}

bool FakeStream::ReadNonBlocking(void* buffer,
                                 size_t size_to_read,
                                 size_t* size_read,
                                 bool* end_of_stream,
                                 ErrorPtr* error) {
  if (!CanRead())
    return stream_utils::ErrorOperationNotSupported(FROM_HERE, error);

  if (!IsOpen())
    return stream_utils::ErrorStreamClosed(FROM_HERE, error);

  for (;;) {
    if (!delay_input_until_.is_null() && clock_->Now() < delay_input_until_) {
      *size_read = 0;
      if (end_of_stream)
        *end_of_stream = false;
      break;
    }

    if (report_read_error_) {
      report_read_error_ = false;
      std::string message{input_buffer_.begin(), input_buffer_.end()};
      if (message.empty())
        message = "Simulating read error for tests";
      input_buffer_.clear();
      Error::AddTo(error, FROM_HERE, "fake_stream", "read_error", message);
      return false;
    }

    if (!IsReadBufferEmpty()) {
      size_to_read = std::min(size_to_read, input_buffer_.size() - input_ptr_);
      std::memcpy(buffer, input_buffer_.data() + input_ptr_, size_to_read);
      input_ptr_ += size_to_read;
      *size_read = size_to_read;
      if (end_of_stream)
        *end_of_stream = false;
      break;
    }

    if (!PopReadPacket()) {
      *size_read = 0;
      if (end_of_stream)
        *end_of_stream = true;
      break;
    }
  }
  return true;
}

bool FakeStream::IsWriteBufferFull() const {
  return output_buffer_.size() >= max_output_buffer_size_;
}

bool FakeStream::PopWritePacket() {
  if (outgoing_queue_.empty())
    return false;
  OutputDataPacket& packet = outgoing_queue_.front();
  expected_output_data_ = std::move(packet.data);
  delay_output_until_ = clock_->Now() + packet.delay_before;
  max_output_buffer_size_ = packet.expected_size;
  report_write_error_ = packet.write_error;
  outgoing_queue_.pop();
  return true;
}

bool FakeStream::WriteNonBlocking(const void* buffer,
                                  size_t size_to_write,
                                  size_t* size_written,
                                  ErrorPtr* error) {
  if (!CanWrite())
    return stream_utils::ErrorOperationNotSupported(FROM_HERE, error);

  if (!IsOpen())
    return stream_utils::ErrorStreamClosed(FROM_HERE, error);

  for (;;) {
    if (!delay_output_until_.is_null() && clock_->Now() < delay_output_until_) {
      *size_written = 0;
      return true;
    }

    if (report_write_error_) {
      report_write_error_ = false;
      std::string message{expected_output_data_.begin(),
                          expected_output_data_.end()};
      if (message.empty())
        message = "Simulating write error for tests";
      output_buffer_.clear();
      max_output_buffer_size_ = 0;
      expected_output_data_.clear();
      Error::AddTo(error, FROM_HERE, "fake_stream", "write_error", message);
      return false;
    }

    if (!IsWriteBufferFull()) {
      bool success = true;
      size_to_write = std::min(size_to_write,
                               max_output_buffer_size_ - output_buffer_.size());
      auto byte_ptr = static_cast<const uint8_t*>(buffer);
      output_buffer_.insert(output_buffer_.end(), byte_ptr,
                            byte_ptr + size_to_write);
      if (output_buffer_.size() == max_output_buffer_size_) {
        if (!expected_output_data_.empty() &&
            expected_output_data_ != output_buffer_) {
          // We expected different data to be written, report an error.
          Error::AddTo(error, FROM_HERE, "fake_stream", "data_mismatch",
                       "Unexpected data written");
          success = false;
        }

        all_output_data_.insert(all_output_data_.end(), output_buffer_.begin(),
                                output_buffer_.end());

        output_buffer_.clear();
        max_output_buffer_size_ = 0;
        expected_output_data_.clear();
      }
      *size_written = size_to_write;
      return success;
    }

    if (!PopWritePacket()) {
      // No more data expected.
      Error::AddTo(error, FROM_HERE, "fake_stream", "full",
                   "No more output data expected");
      return false;
    }
  }
}

bool FakeStream::FlushBlocking(ErrorPtr* error) {
  if (!CanWrite())
    return stream_utils::ErrorOperationNotSupported(FROM_HERE, error);

  if (!IsOpen())
    return stream_utils::ErrorStreamClosed(FROM_HERE, error);

  bool success = true;
  if (!output_buffer_.empty()) {
    if (!expected_output_data_.empty() &&
        expected_output_data_ != output_buffer_) {
      // We expected different data to be written, report an error.
      Error::AddTo(error, FROM_HERE, "fake_stream", "data_mismatch",
                   "Unexpected data written");
      success = false;
    }
    all_output_data_.insert(all_output_data_.end(), output_buffer_.begin(),
                            output_buffer_.end());

    output_buffer_.clear();
    max_output_buffer_size_ = 0;
    expected_output_data_.clear();
  }
  return success;
}

bool FakeStream::CloseBlocking(ErrorPtr* /* error */) {
  is_open_ = false;
  return true;
}

bool FakeStream::WaitForDataRead(base::OnceClosure callback, ErrorPtr* error) {
  if (!CanRead())
    return stream_utils::ErrorOperationNotSupported(FROM_HERE, error);

  if (IsReadBufferEmpty())
    PopReadPacket();

  base::TimeDelta delay = CalculateDelay(clock_->Now(), delay_input_until_);
  MessageLoop::current()->PostDelayedTask(FROM_HERE, std::move(callback),
                                          delay);
  return true;
}

bool FakeStream::WaitForDataReadBlocking(base::TimeDelta timeout,
                                         ErrorPtr* error) {
  if (!CanRead())
    return stream_utils::ErrorOperationNotSupported(FROM_HERE, error);

  base::TimeDelta delay = CalculateDelay(clock_->Now(), delay_input_until_);

  if (timeout < delay)
    return stream_utils::ErrorOperationTimeout(FROM_HERE, error);

  LOG(INFO) << "TEST: Would have blocked for " << delay.InMilliseconds()
            << " ms.";

  return true;
}

bool FakeStream::WaitForDataWrite(base::OnceClosure callback, ErrorPtr* error) {
  if (!CanWrite())
    return stream_utils::ErrorOperationNotSupported(FROM_HERE, error);

  if (IsWriteBufferFull())
    PopWritePacket();

  base::TimeDelta delay = CalculateDelay(clock_->Now(), delay_output_until_);
  MessageLoop::current()->PostDelayedTask(FROM_HERE, std::move(callback),
                                          delay);
  return true;
}

bool FakeStream::WaitForDataWriteBlocking(base::TimeDelta timeout,
                                          ErrorPtr* error) {
  if (!CanWrite())
    return stream_utils::ErrorOperationNotSupported(FROM_HERE, error);

  base::TimeDelta delay = CalculateDelay(clock_->Now(), delay_output_until_);

  if (timeout < delay)
    return stream_utils::ErrorOperationTimeout(FROM_HERE, error);

  LOG(INFO) << "TEST: Would have blocked for " << delay.InMilliseconds()
            << " ms.";

  return true;
}

}  // namespace brillo
