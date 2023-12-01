// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P2P_COMMON_STRUCT_SERIALIZER_H_
#define P2P_COMMON_STRUCT_SERIALIZER_H_

#include <glib.h>
#include <unistd.h>

#include <base/check.h>
#include <base/logging.h>

namespace p2p {

namespace util {

// StructSerializerWrite writes the passed struct T |data| to a file descriptor
// that should be consumed by a StructSerializerWatcher in the other end.
template <typename T>
bool StructSerializerWrite(int fd, const T& data) {
  const char* p = reinterpret_cast<const char*>(&data);
  size_t to_write = sizeof(T);
  int res;

  do {
    res = write(fd, p, to_write);
    if (res < 0 && errno == EAGAIN)
      continue;
    if (res <= 0) {
      PLOG(ERROR) << "Error writing to fd " << fd;
      return false;
    }
    to_write -= res;
    p += res;
  } while (to_write > 0);
  return true;
}

// StructSerializerWarcher adds a new watch to the glib's main loop that reads
// "typename T" objects and fires the provided callback each time such object
// is received. "typename T" is required to have a fixed size and the memory
// representing it is copied from StructSerializerWrite to
// StructSerializerWatcher without any conversion, thus only suitable for
// structs of basic types and fixed length arrays of those.
template <typename T>
class StructSerializerWatcher {
 public:
  // The callback function type that will be used for a StructSerializerWatcher
  // of the struct T.
  typedef void StructSerializerCallback(const T& data, void* user_data);

  StructSerializerWatcher(int fd,
                          StructSerializerCallback* callback,
                          void* user_data)
      : source_id_(0),
        fd_(fd),
        callback_(callback),
        user_data_(user_data),
        buffer_len_(0) {
    GError* error = NULL;

    GIOChannel* io_channel = g_io_channel_unix_new(fd);
    if (g_io_channel_set_encoding(io_channel, NULL, &error) ==
        G_IO_STATUS_ERROR) {
      LOG(ERROR) << "Setting NULL encoding: " << error->message;
      g_error_free(error);
    }
    g_io_channel_set_buffered(io_channel, FALSE);
    source_id_ = g_io_add_watch(
        io_channel,
        static_cast<GIOCondition>(G_IO_IN | G_IO_PRI | G_IO_ERR | G_IO_HUP),
        OnIOChannelActivity, this);
    g_io_channel_unref(io_channel);
  }

  ~StructSerializerWatcher() {
    if (source_id_)
      g_source_remove(source_id_);
  }

 private:
  static gboolean OnIOChannelActivity(GIOChannel* source,
                                      GIOCondition condition,
                                      gpointer user_data) {
    StructSerializerWatcher<T>* watcher =
        reinterpret_cast<StructSerializerWatcher<T>*>(user_data);
    int bytes_read = 0;

    CHECK(watcher->buffer_len_ < watcher->struct_size_);
    char* char_buffer = reinterpret_cast<char*>(&watcher->buffer_);

    do {
      bytes_read = read(watcher->fd_, char_buffer + watcher->buffer_len_,
                        struct_size_ - watcher->buffer_len_);
    } while (bytes_read < 0 && errno == EAGAIN);
    if (bytes_read < 0) {
      PLOG(ERROR) << "Error reading from pipe";
      return TRUE;
    }

    if ((condition & G_IO_HUP) != 0 || bytes_read == 0) {
      watcher->source_id_ = 0;
      return FALSE;  // Stop monitoring the file.
    }

    watcher->buffer_len_ += bytes_read;
    if (watcher->buffer_len_ == watcher->struct_size_) {
      (*watcher->callback_)(watcher->buffer_, watcher->user_data_);
      watcher->buffer_len_ = 0;
    }

    return TRUE;  // Keep source around.
  }

  // The source id used to track the callback source on the main loop.
  guint source_id_;

  // The passed file descriptor.
  int fd_;

  StructSerializerCallback* callback_;

  // A user provided pointer passed back to callback on every call.
  void* user_data_;

  static const size_t struct_size_ = sizeof(T);

  // The buffer to store partial reads from the passed |fd_|.
  T buffer_;

  // The current number of bytes stored in |buffer_|.
  size_t buffer_len_;
};

}  // namespace util

}  // namespace p2p

#endif  // P2P_COMMON_STRUCT_SERIALIZER_H_
