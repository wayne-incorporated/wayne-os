// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/check.h>
#include <brillo/streams/stream.h>

#include <algorithm>
#include <utility>

#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <brillo/message_loops/message_loop.h>
#include <brillo/pointer_utils.h>
#include <brillo/streams/stream_errors.h>
#include <brillo/streams/stream_utils.h>

namespace brillo {

bool Stream::TruncateBlocking(ErrorPtr* error) {
  return SetSizeBlocking(GetPosition(), error);
}

bool Stream::SetPosition(uint64_t position, ErrorPtr* error) {
  if (!stream_utils::CheckInt64Overflow(FROM_HERE, position, 0, error))
    return false;
  return Seek(position, Whence::FROM_BEGIN, nullptr, error);
}

bool Stream::ReadAsync(void* buffer,
                       size_t size_to_read,
                       base::OnceCallback<void(size_t)> success_callback,
                       ErrorCallback error_callback,
                       ErrorPtr* error) {
  if (is_async_read_pending_) {
    Error::AddTo(error, FROM_HERE, errors::stream::kDomain,
                 errors::stream::kOperationNotSupported,
                 "Another asynchronous operation is still pending");
    return false;
  }

  auto callback =
      base::BindOnce(&Stream::IgnoreEOSCallback, std::move(success_callback));
  // If we can read some data right away non-blocking we should still run the
  // callback from the main loop, so we pass true here for force_async_callback.
  return ReadAsyncImpl(buffer, size_to_read, std::move(callback),
                       std::move(error_callback), error, true);
}

bool Stream::ReadAllAsync(void* buffer,
                          size_t size_to_read,
                          base::OnceClosure success_callback,
                          ErrorCallback error_callback,
                          ErrorPtr* error) {
  if (is_async_read_pending_) {
    Error::AddTo(error, FROM_HERE, errors::stream::kDomain,
                 errors::stream::kOperationNotSupported,
                 "Another asynchronous operation is still pending");
    return false;
  }

  auto [error_cb1, error_cb2] =
      base::SplitOnceCallback(std::move(error_callback));
  auto callback = base::BindOnce(
      &Stream::ReadAllAsyncCallback, weak_ptr_factory_.GetWeakPtr(), buffer,
      size_to_read, std::move(success_callback), std::move(error_cb1));
  return ReadAsyncImpl(buffer, size_to_read, std::move(callback),
                       std::move(error_cb2), error, true);
}

bool Stream::ReadBlocking(void* buffer,
                          size_t size_to_read,
                          size_t* size_read,
                          ErrorPtr* error) {
  for (;;) {
    bool eos = false;
    if (!ReadNonBlocking(buffer, size_to_read, size_read, &eos, error))
      return false;

    if (*size_read > 0 || eos)
      break;

    if (!WaitForDataReadBlocking(base::TimeDelta::Max(), error)) {
      return false;
    }
  }
  return true;
}

bool Stream::ReadAllBlocking(void* buffer,
                             size_t size_to_read,
                             ErrorPtr* error) {
  while (size_to_read > 0) {
    size_t size_read = 0;
    if (!ReadBlocking(buffer, size_to_read, &size_read, error))
      return false;

    if (size_read == 0)
      return stream_utils::ErrorReadPastEndOfStream(FROM_HERE, error);

    size_to_read -= size_read;
    buffer = AdvancePointer(buffer, size_read);
  }
  return true;
}

bool Stream::WriteAsync(const void* buffer,
                        size_t size_to_write,
                        base::OnceCallback<void(size_t)> success_callback,
                        ErrorCallback error_callback,
                        ErrorPtr* error) {
  if (is_async_write_pending_) {
    Error::AddTo(error, FROM_HERE, errors::stream::kDomain,
                 errors::stream::kOperationNotSupported,
                 "Another asynchronous operation is still pending");
    return false;
  }
  // If we can read some data right away non-blocking we should still run the
  // callback from the main loop, so we pass true here for force_async_callback.
  return WriteAsyncImpl(buffer, size_to_write, std::move(success_callback),
                        std::move(error_callback), error, true);
}

bool Stream::WriteAllAsync(const void* buffer,
                           size_t size_to_write,
                           base::OnceClosure success_callback,
                           ErrorCallback error_callback,
                           ErrorPtr* error) {
  if (is_async_write_pending_) {
    Error::AddTo(error, FROM_HERE, errors::stream::kDomain,
                 errors::stream::kOperationNotSupported,
                 "Another asynchronous operation is still pending");
    return false;
  }

  auto [error_cb1, error_cb2] =
      base::SplitOnceCallback(std::move(error_callback));
  auto callback = base::BindOnce(
      &Stream::WriteAllAsyncCallback, weak_ptr_factory_.GetWeakPtr(), buffer,
      size_to_write, std::move(success_callback), std::move(error_cb1));
  return WriteAsyncImpl(buffer, size_to_write, std::move(callback),
                        std::move(error_cb2), error, true);
}

bool Stream::WriteBlocking(const void* buffer,
                           size_t size_to_write,
                           size_t* size_written,
                           ErrorPtr* error) {
  for (;;) {
    if (!WriteNonBlocking(buffer, size_to_write, size_written, error))
      return false;

    if (*size_written > 0 || size_to_write == 0)
      break;

    if (!WaitForDataWriteBlocking(base::TimeDelta::Max(), error)) {
      return false;
    }
  }
  return true;
}

bool Stream::WriteAllBlocking(const void* buffer,
                              size_t size_to_write,
                              ErrorPtr* error) {
  while (size_to_write > 0) {
    size_t size_written = 0;
    if (!WriteBlocking(buffer, size_to_write, &size_written, error))
      return false;

    if (size_written == 0) {
      Error::AddTo(error, FROM_HERE, errors::stream::kDomain,
                   errors::stream::kPartialData,
                   "Failed to write all the data");
      return false;
    }
    size_to_write -= size_written;
    buffer = AdvancePointer(buffer, size_written);
  }
  return true;
}

bool Stream::FlushAsync(base::OnceClosure success_callback,
                        ErrorCallback error_callback,
                        ErrorPtr* /* error */) {
  MessageLoop::current()->PostTask(
      FROM_HERE,
      base::BindOnce(&Stream::FlushAsyncCallback,
                     weak_ptr_factory_.GetWeakPtr(),
                     std::move(success_callback), std::move(error_callback)));
  return true;
}

void Stream::IgnoreEOSCallback(
    base::OnceCallback<void(size_t)> success_callback,
    size_t bytes,
    bool /* eos */) {
  std::move(success_callback).Run(bytes);
}

bool Stream::ReadAsyncImpl(
    void* buffer,
    size_t size_to_read,
    base::OnceCallback<void(size_t, bool)> success_callback,
    ErrorCallback error_callback,
    ErrorPtr* error,
    bool force_async_callback) {
  CHECK(!is_async_read_pending_);
  // We set this value to true early in the function so calling others will
  // prevent us from calling WaitForDataRead() to make calls to
  // ReadAsync() fail while we run WaitForDataRead().
  is_async_read_pending_ = true;

  size_t read = 0;
  bool eos = false;
  if (!ReadNonBlocking(buffer, size_to_read, &read, &eos, error))
    return false;

  if (read > 0 || eos) {
    if (force_async_callback) {
      MessageLoop::current()->PostTask(
          FROM_HERE, base::BindOnce(&Stream::OnReadAsyncDone,
                                    weak_ptr_factory_.GetWeakPtr(),
                                    std::move(success_callback), read, eos));
    } else {
      is_async_read_pending_ = false;
      std::move(success_callback).Run(read, eos);
    }
    return true;
  }

  is_async_read_pending_ = WaitForDataRead(
      base::BindOnce(&Stream::OnReadAvailable, weak_ptr_factory_.GetWeakPtr(),
                     buffer, size_to_read, std::move(success_callback),
                     std::move(error_callback)),
      error);
  return is_async_read_pending_;
}

void Stream::OnReadAsyncDone(
    base::OnceCallback<void(size_t, bool)> success_callback,
    size_t bytes_read,
    bool eos) {
  is_async_read_pending_ = false;
  std::move(success_callback).Run(bytes_read, eos);
}

void Stream::OnReadAvailable(
    void* buffer,
    size_t size_to_read,
    base::OnceCallback<void(size_t, bool)> success_callback,
    ErrorCallback error_callback) {
  CHECK(is_async_read_pending_);
  is_async_read_pending_ = false;
  ErrorPtr error;
  auto split_error_callback =
      base::SplitOnceCallback(std::move(error_callback));
  // Just reschedule the read operation but don't need to run the callback from
  // the main loop since we are already running on a callback.
  if (!ReadAsyncImpl(buffer, size_to_read, std::move(success_callback),
                     std::move(split_error_callback.first), &error, false)) {
    std::move(split_error_callback.second).Run(error.get());
  }
}

bool Stream::WriteAsyncImpl(const void* buffer,
                            size_t size_to_write,
                            base::OnceCallback<void(size_t)> success_callback,
                            ErrorCallback error_callback,
                            ErrorPtr* error,
                            bool force_async_callback) {
  CHECK(!is_async_write_pending_);
  // We set this value to true early in the function so calling others will
  // prevent us from calling WaitForDataWrite() to make calls to
  // ReadAsync() fail while we run WaitForDataWrite().
  is_async_write_pending_ = true;

  size_t written = 0;
  if (!WriteNonBlocking(buffer, size_to_write, &written, error))
    return false;

  if (written > 0) {
    if (force_async_callback) {
      MessageLoop::current()->PostTask(
          FROM_HERE, base::BindOnce(&Stream::OnWriteAsyncDone,
                                    weak_ptr_factory_.GetWeakPtr(),
                                    std::move(success_callback), written));
    } else {
      is_async_write_pending_ = false;
      std::move(success_callback).Run(written);
    }
    return true;
  }
  is_async_write_pending_ = WaitForDataWrite(
      base::BindOnce(&Stream::OnWriteAvailable, weak_ptr_factory_.GetWeakPtr(),
                     buffer, size_to_write, std::move(success_callback),
                     std::move(error_callback)),
      error);
  return is_async_write_pending_;
}

void Stream::OnWriteAsyncDone(base::OnceCallback<void(size_t)> success_callback,
                              size_t size_written) {
  is_async_write_pending_ = false;
  std::move(success_callback).Run(size_written);
}

void Stream::OnWriteAvailable(const void* buffer,
                              size_t size,
                              base::OnceCallback<void(size_t)> success_callback,
                              ErrorCallback error_callback) {
  CHECK(is_async_write_pending_);
  is_async_write_pending_ = false;
  ErrorPtr error;
  auto split_error_callback =
      base::SplitOnceCallback(std::move(error_callback));
  // Just reschedule the read operation but don't need to run the callback from
  // the main loop since we are already running on a callback.
  if (!WriteAsyncImpl(buffer, size, std::move(success_callback),
                      std::move(split_error_callback.first), &error, false)) {
    std::move(split_error_callback.second).Run(error.get());
  }
}

void Stream::ReadAllAsyncCallback(void* buffer,
                                  size_t size_to_read,
                                  base::OnceClosure success_callback,
                                  ErrorCallback error_callback,
                                  size_t size_read,
                                  bool eos) {
  ErrorPtr error;
  size_to_read -= size_read;
  if (size_to_read != 0 && eos) {
    stream_utils::ErrorReadPastEndOfStream(FROM_HERE, &error);
    std::move(error_callback).Run(error.get());
    return;
  }

  if (size_to_read) {
    buffer = AdvancePointer(buffer, size_read);
    auto [error_cb1, error_tmp] =
        base::SplitOnceCallback(std::move(error_callback));
    auto [error_cb2, error_cb3] = base::SplitOnceCallback(std::move(error_tmp));
    auto callback = base::BindOnce(
        &Stream::ReadAllAsyncCallback, weak_ptr_factory_.GetWeakPtr(), buffer,
        size_to_read, std::move(success_callback), std::move(error_cb1));
    if (!ReadAsyncImpl(buffer, size_to_read, std::move(callback),
                       std::move(error_cb2), &error, false)) {
      std::move(error_cb3).Run(error.get());
    }
  } else {
    std::move(success_callback).Run();
  }
}

void Stream::WriteAllAsyncCallback(const void* buffer,
                                   size_t size_to_write,
                                   base::OnceClosure success_callback,
                                   ErrorCallback error_callback,
                                   size_t size_written) {
  ErrorPtr error;
  if (size_to_write != 0 && size_written == 0) {
    Error::AddTo(&error, FROM_HERE, errors::stream::kDomain,
                 errors::stream::kPartialData, "Failed to write all the data");
    std::move(error_callback).Run(error.get());
    return;
  }
  size_to_write -= size_written;
  if (size_to_write) {
    buffer = AdvancePointer(buffer, size_written);
    auto [error_cb1, error_tmp] =
        base::SplitOnceCallback(std::move(error_callback));
    auto [error_cb2, error_cb3] = base::SplitOnceCallback(std::move(error_tmp));
    auto callback = base::BindOnce(
        &Stream::WriteAllAsyncCallback, weak_ptr_factory_.GetWeakPtr(), buffer,
        size_to_write, std::move(success_callback), std::move(error_cb1));
    if (!WriteAsyncImpl(buffer, size_to_write, std::move(callback),
                        std::move(error_cb2), &error, false)) {
      std::move(error_cb3).Run(error.get());
    }
  } else {
    std::move(success_callback).Run();
  }
}

void Stream::FlushAsyncCallback(base::OnceClosure success_callback,
                                ErrorCallback error_callback) {
  ErrorPtr error;
  if (FlushBlocking(&error)) {
    std::move(success_callback).Run();
  } else {
    std::move(error_callback).Run(error.get());
  }
}

void Stream::CancelPendingAsyncOperations() {
  weak_ptr_factory_.InvalidateWeakPtrs();
  is_async_read_pending_ = false;
  is_async_write_pending_ = false;
}

}  // namespace brillo
