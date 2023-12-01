// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/check.h>
#include <brillo/streams/file_stream.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <utility>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/posix/eintr_wrapper.h>
#include <brillo/errors/error_codes.h>
#include <brillo/message_loops/message_loop.h>
#include <brillo/streams/stream_errors.h>
#include <brillo/streams/stream_utils.h>

namespace brillo {

// FileDescriptor is a helper class that serves two purposes:
// 1. It wraps low-level system APIs (as FileDescriptorInterface) to allow
//    mocking calls to them in tests.
// 2. It provides file descriptor watching services using FileDescriptorWatcher
//    and MessageLoopForIO::Watcher interface.
// The real FileStream uses this class to perform actual file I/O on the
// contained file descriptor.
class FileDescriptor : public FileStream::FileDescriptorInterface {
 public:
  FileDescriptor(int fd, bool own) : fd_{fd}, own_{own} {}
  FileDescriptor(const FileDescriptor&) = delete;
  FileDescriptor& operator=(const FileDescriptor&) = delete;
  ~FileDescriptor() override {
    if (IsOpen()) {
      Close();
    }
  }

  // Overrides for FileStream::FileDescriptorInterface methods.
  bool IsOpen() const override { return fd_ >= 0; }

  ssize_t Read(void* buf, size_t nbyte) override {
    return HANDLE_EINTR(read(fd_, buf, nbyte));
  }

  ssize_t Write(const void* buf, size_t nbyte) override {
    return HANDLE_EINTR(write(fd_, buf, nbyte));
  }

  off64_t Seek(off64_t offset, int whence) override {
    return lseek64(fd_, offset, whence);
  }

  mode_t GetFileMode() const override {
    struct stat file_stat;
    if (fstat(fd_, &file_stat) < 0)
      return 0;
    return file_stat.st_mode;
  }

  uint64_t GetSize() const override {
    struct stat file_stat;
    if (fstat(fd_, &file_stat) < 0)
      return 0;
    return file_stat.st_size;
  }

  int Truncate(off64_t length) const override {
    return HANDLE_EINTR(ftruncate(fd_, length));
  }

  int Close() override {
    int fd = -1;
    // The stream may or may not own the file descriptor stored in |fd_|.
    // Despite that, we will need to set |fd_| to -1 when Close() finished.
    // So, here we set it to -1 first and if we own the old descriptor, close
    // it before exiting.
    std::swap(fd, fd_);
    CancelPendingAsyncOperations();
    return own_ ? IGNORE_EINTR(close(fd)) : 0;
  }

  bool WaitForDataRead(DataCallback data_callback, ErrorPtr* error) override {
    CHECK(read_data_callback_.is_null());
    read_watcher_ = base::FileDescriptorWatcher::WatchReadable(
        fd_, base::BindRepeating(&FileDescriptor::OnReadable,
                                 base::Unretained(this)));
    if (!read_watcher_) {
      Error::AddTo(error, FROM_HERE, errors::stream::kDomain,
                   errors::stream::kInvalidParameter,
                   "File descriptor doesn't support watching for reading.");
      return false;
    }
    read_data_callback_ = std::move(data_callback);
    return true;
  }

  int WaitForDataReadBlocking(base::TimeDelta timeout) override {
    return WaitForDataBlocking(Stream::AccessMode::READ, timeout);
  }

  bool WaitForDataWrite(DataCallback data_callback, ErrorPtr* error) override {
    CHECK(write_data_callback_.is_null());
    write_watcher_ = base::FileDescriptorWatcher::WatchWritable(
        fd_, base::BindRepeating(&FileDescriptor::OnWritable,
                                 base::Unretained(this)));
    if (!write_watcher_) {
      Error::AddTo(error, FROM_HERE, errors::stream::kDomain,
                   errors::stream::kInvalidParameter,
                   "File descriptor doesn't support watching for writing.");
      return false;
    }
    write_data_callback_ = std::move(data_callback);
    return true;
  }

  int WaitForDataWriteBlocking(base::TimeDelta timeout) override {
    return WaitForDataBlocking(Stream::AccessMode::WRITE, timeout);
  }

  void CancelPendingAsyncOperations() override {
    read_data_callback_.Reset();
    read_watcher_ = nullptr;
    write_data_callback_.Reset();
    write_watcher_ = nullptr;
  }

  // Called from the brillo::MessageLoop when the file descriptor is available
  // for reading.
  void OnReadable() {
    CHECK(!read_data_callback_.is_null());

    read_watcher_ = nullptr;
    std::move(read_data_callback_).Run();
  }

  void OnWritable() {
    CHECK(!write_data_callback_.is_null());

    write_watcher_ = nullptr;
    std::move(write_data_callback_).Run();
  }

 private:
  int WaitForDataBlocking(Stream::AccessMode mode, base::TimeDelta timeout) {
    fd_set read_fds;
    fd_set write_fds;
    fd_set error_fds;

    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    FD_ZERO(&error_fds);

    if (stream_utils::IsReadAccessMode(mode))
      FD_SET(fd_, &read_fds);

    if (stream_utils::IsWriteAccessMode(mode))
      FD_SET(fd_, &write_fds);

    FD_SET(fd_, &error_fds);
    timeval timeout_val = {};
    if (!timeout.is_max()) {
      const timespec ts = timeout.ToTimeSpec();
      TIMESPEC_TO_TIMEVAL(&timeout_val, &ts);
    }
    return HANDLE_EINTR(select(fd_ + 1, &read_fds, &write_fds, &error_fds,
                               timeout.is_max() ? nullptr : &timeout_val));
  }

  // The actual file descriptor we are working with. Will contain -1 if the
  // file stream has been closed.
  int fd_;

  // |own_| is set to true if the file stream owns the file descriptor |fd_| and
  // must close it when the stream is closed. This will be false for file
  // descriptors that shouldn't be closed (e.g. stdin, stdout, stderr).
  bool own_;

  // Stream callbacks to be called when read and/or write operations can be
  // performed on the file descriptor without blocking.
  DataCallback read_data_callback_;
  DataCallback write_data_callback_;

  // Monitoring read/write operations on the file descriptor.
  std::unique_ptr<base::FileDescriptorWatcher::Controller> read_watcher_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller> write_watcher_;
};

StreamPtr FileStream::Open(const base::FilePath& path,
                           AccessMode mode,
                           Disposition disposition,
                           ErrorPtr* error) {
  StreamPtr stream;
  int open_flags = O_CLOEXEC;
  switch (mode) {
    case AccessMode::READ:
      open_flags |= O_RDONLY;
      break;
    case AccessMode::WRITE:
      open_flags |= O_WRONLY;
      break;
    case AccessMode::READ_WRITE:
      open_flags |= O_RDWR;
      break;
  }

  switch (disposition) {
    case Disposition::OPEN_EXISTING:
      // Nothing else to do.
      break;
    case Disposition::CREATE_ALWAYS:
      open_flags |= O_CREAT | O_TRUNC;
      break;
    case Disposition::CREATE_NEW_ONLY:
      open_flags |= O_CREAT | O_EXCL;
      break;
    case Disposition::TRUNCATE_EXISTING:
      open_flags |= O_TRUNC;
      break;
  }

  mode_t creation_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
  int fd = HANDLE_EINTR(open(path.value().c_str(), open_flags, creation_mode));
  if (fd < 0) {
    brillo::errors::system::AddSystemError(error, FROM_HERE, errno);
    return stream;
  }
  if (HANDLE_EINTR(fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)) < 0) {
    brillo::errors::system::AddSystemError(error, FROM_HERE, errno);
    IGNORE_EINTR(close(fd));
    return stream;
  }

  std::unique_ptr<FileDescriptorInterface> fd_interface{
      new FileDescriptor{fd, true}};

  stream.reset(new FileStream{std::move(fd_interface), mode});
  return stream;
}

StreamPtr FileStream::CreateTemporary(ErrorPtr* error) {
  StreamPtr stream;
  base::FilePath path;
  // The "proper" solution would be here to add O_TMPFILE flag to |open_flags|
  // below and pass just the temp directory path to open(), so the actual file
  // name isn't even needed. However this is supported only as of Linux kernel
  // 3.11 and not all our configurations have that. So, for now just create
  // a temp file first and then open it.
  if (!base::CreateTemporaryFile(&path)) {
    brillo::errors::system::AddSystemError(error, FROM_HERE, errno);
    return stream;
  }
  int open_flags = O_CLOEXEC | O_RDWR | O_CREAT | O_TRUNC;
  mode_t creation_mode = S_IRUSR | S_IWUSR;
  int fd = HANDLE_EINTR(open(path.value().c_str(), open_flags, creation_mode));
  if (fd < 0) {
    brillo::errors::system::AddSystemError(error, FROM_HERE, errno);
    return stream;
  }
  unlink(path.value().c_str());

  stream = FromFileDescriptor(fd, true, error);
  if (!stream)
    IGNORE_EINTR(close(fd));
  return stream;
}

StreamPtr FileStream::FromFileDescriptor(int file_descriptor,
                                         bool own_descriptor,
                                         ErrorPtr* error) {
  StreamPtr stream;
  if (file_descriptor < 0 || file_descriptor >= FD_SETSIZE) {
    Error::AddTo(error, FROM_HERE, errors::stream::kDomain,
                 errors::stream::kInvalidParameter,
                 "Invalid file descriptor value");
    return stream;
  }

  int fd_flags = HANDLE_EINTR(fcntl(file_descriptor, F_GETFL));
  if (fd_flags < 0) {
    brillo::errors::system::AddSystemError(error, FROM_HERE, errno);
    return stream;
  }
  int file_access_mode = (fd_flags & O_ACCMODE);
  AccessMode access_mode = AccessMode::READ_WRITE;
  if (file_access_mode == O_RDONLY)
    access_mode = AccessMode::READ;
  else if (file_access_mode == O_WRONLY)
    access_mode = AccessMode::WRITE;

  // Make sure the file descriptor is set to perform non-blocking operations
  // if not enabled already.
  if ((fd_flags & O_NONBLOCK) == 0) {
    fd_flags |= O_NONBLOCK;
    if (HANDLE_EINTR(fcntl(file_descriptor, F_SETFL, fd_flags)) < 0) {
      brillo::errors::system::AddSystemError(error, FROM_HERE, errno);
      return stream;
    }
  }

  std::unique_ptr<FileDescriptorInterface> fd_interface{
      new FileDescriptor{file_descriptor, own_descriptor}};

  stream.reset(new FileStream{std::move(fd_interface), access_mode});
  return stream;
}

FileStream::FileStream(std::unique_ptr<FileDescriptorInterface> fd_interface,
                       AccessMode mode)
    : fd_interface_(std::move(fd_interface)), access_mode_(mode) {
  switch (fd_interface_->GetFileMode() & S_IFMT) {
    case S_IFCHR:   // Character device
    case S_IFSOCK:  // Socket
    case S_IFIFO:   // FIFO/pipe
      // We know that these devices are not seekable and stream size is unknown.
      seekable_ = false;
      can_get_size_ = false;
      break;

    case S_IFBLK:  // Block device
    case S_IFDIR:  // Directory
    case S_IFREG:  // Normal file
    case S_IFLNK:  // Symbolic link
    default:
      // The above devices support seek. Also, if not sure/in doubt, err on the
      // side of "allowable".
      seekable_ = true;
      can_get_size_ = true;
      break;
  }
}

bool FileStream::IsOpen() const {
  return fd_interface_->IsOpen();
}

bool FileStream::CanRead() const {
  return IsOpen() && stream_utils::IsReadAccessMode(access_mode_);
}

bool FileStream::CanWrite() const {
  return IsOpen() && stream_utils::IsWriteAccessMode(access_mode_);
}

bool FileStream::CanSeek() const {
  return IsOpen() && seekable_;
}

bool FileStream::CanGetSize() const {
  return IsOpen() && can_get_size_;
}

uint64_t FileStream::GetSize() const {
  return IsOpen() ? fd_interface_->GetSize() : 0;
}

bool FileStream::SetSizeBlocking(uint64_t size, ErrorPtr* error) {
  if (!IsOpen())
    return stream_utils::ErrorStreamClosed(FROM_HERE, error);

  if (!stream_utils::CheckInt64Overflow(FROM_HERE, size, 0, error))
    return false;

  if (fd_interface_->Truncate(size) >= 0)
    return true;

  errors::system::AddSystemError(error, FROM_HERE, errno);
  return false;
}

uint64_t FileStream::GetRemainingSize() const {
  if (!CanGetSize())
    return 0;
  uint64_t pos = GetPosition();
  uint64_t size = GetSize();
  return (pos < size) ? (size - pos) : 0;
}

uint64_t FileStream::GetPosition() const {
  if (!CanSeek())
    return 0;

  off64_t pos = fd_interface_->Seek(0, SEEK_CUR);
  const off64_t min_pos = 0;
  return std::max(min_pos, pos);
}

bool FileStream::Seek(int64_t offset,
                      Whence whence,
                      uint64_t* new_position,
                      ErrorPtr* error) {
  if (!IsOpen())
    return stream_utils::ErrorStreamClosed(FROM_HERE, error);

  int raw_whence = 0;
  switch (whence) {
    case Whence::FROM_BEGIN:
      raw_whence = SEEK_SET;
      break;
    case Whence::FROM_CURRENT:
      raw_whence = SEEK_CUR;
      break;
    case Whence::FROM_END:
      raw_whence = SEEK_END;
      break;
    default:
      Error::AddTo(error, FROM_HERE, errors::stream::kDomain,
                   errors::stream::kInvalidParameter, "Invalid whence");
      return false;
  }
  off64_t pos = fd_interface_->Seek(offset, raw_whence);
  if (pos < 0) {
    errors::system::AddSystemError(error, FROM_HERE, errno);
    return false;
  }

  if (new_position)
    *new_position = static_cast<uint64_t>(pos);
  return true;
}

bool FileStream::ReadNonBlocking(void* buffer,
                                 size_t size_to_read,
                                 size_t* size_read,
                                 bool* end_of_stream,
                                 ErrorPtr* error) {
  if (!IsOpen())
    return stream_utils::ErrorStreamClosed(FROM_HERE, error);

  ssize_t read = fd_interface_->Read(buffer, size_to_read);
  if (read < 0) {
    // If read() fails, check if this is due to no data being currently
    // available and we do non-blocking I/O.
    if (errno == EWOULDBLOCK || errno == EAGAIN) {
      if (end_of_stream)
        *end_of_stream = false;
      *size_read = 0;
      return true;
    }
    // Otherwise a real problem occurred.
    errors::system::AddSystemError(error, FROM_HERE, errno);
    return false;
  }
  if (end_of_stream)
    *end_of_stream = (read == 0 && size_to_read != 0);
  *size_read = read;
  return true;
}

bool FileStream::WriteNonBlocking(const void* buffer,
                                  size_t size_to_write,
                                  size_t* size_written,
                                  ErrorPtr* error) {
  if (!IsOpen())
    return stream_utils::ErrorStreamClosed(FROM_HERE, error);

  ssize_t written = fd_interface_->Write(buffer, size_to_write);
  if (written < 0) {
    // If write() fails, check if this is due to the fact that no data
    // can be presently written and we do non-blocking I/O.
    if (errno == EWOULDBLOCK || errno == EAGAIN) {
      *size_written = 0;
      return true;
    }
    // Otherwise a real problem occurred.
    errors::system::AddSystemError(error, FROM_HERE, errno);
    return false;
  }
  *size_written = written;
  return true;
}

bool FileStream::FlushBlocking(ErrorPtr* error) {
  if (!IsOpen())
    return stream_utils::ErrorStreamClosed(FROM_HERE, error);

  // File descriptors don't have an internal buffer to flush.
  return true;
}

bool FileStream::CloseBlocking(ErrorPtr* error) {
  if (!IsOpen())
    return true;

  if (fd_interface_->Close() < 0) {
    errors::system::AddSystemError(error, FROM_HERE, errno);
    return false;
  }

  return true;
}

bool FileStream::WaitForDataRead(base::OnceClosure callback, ErrorPtr* error) {
  if (!IsOpen())
    return stream_utils::ErrorStreamClosed(FROM_HERE, error);

  return fd_interface_->WaitForDataRead(std::move(callback), error);
}

bool FileStream::WaitForDataReadBlocking(base::TimeDelta timeout,
                                         ErrorPtr* error) {
  if (!IsOpen())
    return stream_utils::ErrorStreamClosed(FROM_HERE, error);

  int ret = fd_interface_->WaitForDataReadBlocking(timeout);
  if (ret < 0) {
    errors::system::AddSystemError(error, FROM_HERE, errno);
    return false;
  }
  if (ret == 0)
    return stream_utils::ErrorOperationTimeout(FROM_HERE, error);

  return true;
}

bool FileStream::WaitForDataWrite(base::OnceClosure callback, ErrorPtr* error) {
  if (!IsOpen())
    return stream_utils::ErrorStreamClosed(FROM_HERE, error);

  return fd_interface_->WaitForDataWrite(std::move(callback), error);
}

bool FileStream::WaitForDataWriteBlocking(base::TimeDelta timeout,
                                          ErrorPtr* error) {
  if (!IsOpen())
    return stream_utils::ErrorStreamClosed(FROM_HERE, error);

  int ret = fd_interface_->WaitForDataWriteBlocking(timeout);
  if (ret < 0) {
    errors::system::AddSystemError(error, FROM_HERE, errno);
    return false;
  }
  if (ret == 0)
    return stream_utils::ErrorOperationTimeout(FROM_HERE, error);

  return true;
}

void FileStream::CancelPendingAsyncOperations() {
  if (IsOpen()) {
    fd_interface_->CancelPendingAsyncOperations();
  }
  Stream::CancelPendingAsyncOperations();
}

}  // namespace brillo
