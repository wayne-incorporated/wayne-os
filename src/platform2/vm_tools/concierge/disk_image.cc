// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <archive.h>
#include <archive_entry.h>
#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <memory>
#include <utility>

#include <base/check.h>
#include <base/files/file.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/stl_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <base/uuid.h>

#include "vm_tools/concierge/disk_image.h"
#include "vm_tools/concierge/plugin_vm_config.h"
#include "vm_tools/concierge/plugin_vm_helper.h"
#include "vm_tools/concierge/service.h"
#include "vm_tools/concierge/vmplugin_dispatcher_interface.h"

namespace {

constexpr gid_t kPluginVmGid = 20128;

}  // namespace

namespace vm_tools {
namespace concierge {

DiskImageOperation::DiskImageOperation(const VmId vm_id)
    : uuid_(base::Uuid::GenerateRandomV4().AsLowercaseString()),
      vm_id_(std::move(vm_id)),
      status_(DISK_STATUS_FAILED),
      source_size_(0),
      processed_size_(0) {
  CHECK(base::Uuid::ParseCaseInsensitive(uuid_).is_valid());
}

void DiskImageOperation::Run(uint64_t io_limit) {
  if (ExecuteIo(io_limit)) {
    Finalize();
  }
}

int DiskImageOperation::GetProgress() const {
  if (status() == DISK_STATUS_IN_PROGRESS) {
    if (source_size_ == 0)
      return 0;  // We do not know any better.

    return processed_size_ * 100 / source_size_;
  }

  // Any other status indicates completed operation (successfully or not)
  // so return 100%.
  return 100;
}

std::unique_ptr<PluginVmCreateOperation> PluginVmCreateOperation::Create(
    base::ScopedFD fd,
    const base::FilePath& iso_dir,
    uint64_t source_size,
    const VmId vm_id,
    const std::vector<std::string> params) {
  auto op = base::WrapUnique(new PluginVmCreateOperation(
      std::move(fd), source_size, std::move(vm_id), std::move(params)));

  if (op->PrepareOutput(iso_dir)) {
    op->set_status(DISK_STATUS_IN_PROGRESS);
  }

  return op;
}

PluginVmCreateOperation::PluginVmCreateOperation(
    base::ScopedFD in_fd,
    uint64_t source_size,
    const VmId vm_id,
    const std::vector<std::string> params)
    : DiskImageOperation(std::move(vm_id)),
      params_(std::move(params)),
      in_fd_(std::move(in_fd)) {
  set_source_size(source_size);
}

bool PluginVmCreateOperation::PrepareOutput(const base::FilePath& iso_dir) {
  base::File::Error dir_error;

  if (!base::CreateDirectoryAndGetError(iso_dir, &dir_error)) {
    set_failure_reason(std::string("failed to create ISO directory: ") +
                       base::File::ErrorToString(dir_error));
    return false;
  }

  CHECK(output_dir_.Set(iso_dir));

  base::FilePath iso_path = iso_dir.Append("install.iso");
  out_fd_.reset(open(iso_path.value().c_str(), O_CREAT | O_WRONLY, 0660));
  if (!out_fd_.is_valid()) {
    PLOG(ERROR) << "Failed to create output ISO file " << iso_path.value();
    set_failure_reason("failed to create ISO file");
    return false;
  }

  return true;
}

void PluginVmCreateOperation::MarkFailed(const char* msg, int error_code) {
  if (error_code != 0) {
    set_status(error_code == ENOSPC ? DISK_STATUS_NOT_ENOUGH_SPACE
                                    : DISK_STATUS_FAILED);
    set_failure_reason(base::StringPrintf("%s: %s", msg, strerror(error_code)));
  } else {
    set_status(DISK_STATUS_FAILED);
    set_failure_reason(msg);
  }

  LOG(ERROR) << vm_id().name()
             << " PluginVm create operation failed: " << failure_reason();

  in_fd_.reset();
  out_fd_.reset();

  if (output_dir_.IsValid() && !output_dir_.Delete()) {
    LOG(WARNING) << "Failed to delete output directory on error";
  }
}

bool PluginVmCreateOperation::ExecuteIo(uint64_t io_limit) {
  do {
    uint8_t buf[65536];
    int count = HANDLE_EINTR(read(in_fd_.get(), buf, sizeof(buf)));
    if (count == 0) {
      // No more data
      return true;
    }

    if (count < 0) {
      MarkFailed("failed to read data block", errno);
      break;
    }

    int ret = HANDLE_EINTR(write(out_fd_.get(), buf, count));
    if (ret != count) {
      MarkFailed("failed to write data block", errno);
      break;
    }

    io_limit -= std::min(static_cast<uint64_t>(count), io_limit);
    AccumulateProcessedSize(count);
  } while (status() == DISK_STATUS_IN_PROGRESS && io_limit > 0);

  // More copying is to be done (or there was a failure).
  return false;
}

void PluginVmCreateOperation::Finalize() {
  // Close the file descriptors.
  in_fd_.reset();
  out_fd_.reset();

  if (!pvm::helper::CreateVm(vm_id(), std::move(params_))) {
    MarkFailed("Failed to create Plugin VM", 0);
    return;
  }

  if (!pvm::helper::AttachIso(vm_id(), "cdrom0",
                              pvm::plugin::kInstallIsoPath)) {
    MarkFailed("Failed to attach install ISO to Plugin VM", 0);
    pvm::helper::DeleteVm(vm_id());
    return;
  }

  if (!pvm::helper::CreateCdromDevice(vm_id(), pvm::plugin::kToolsIsoPath)) {
    MarkFailed("Failed to attach tools ISO to Plugin VM", 0);
    pvm::helper::DeleteVm(vm_id());
    return;
  }

  // Tell it not to try cleaning directory containing our ISO as we are
  // committed to using the image.
  output_dir_.Take();

  set_status(DISK_STATUS_CREATED);
}

std::unique_ptr<VmExportOperation> VmExportOperation::Create(
    const VmId vm_id,
    const base::FilePath disk_path,
    base::ScopedFD fd,
    base::ScopedFD digest_fd,
    ArchiveFormat out_fmt) {
  auto op = base::WrapUnique(new VmExportOperation(
      std::move(vm_id), std::move(disk_path), std::move(fd),
      std::move(digest_fd), std::move(out_fmt)));

  if (op->PrepareInput() && op->PrepareOutput()) {
    op->set_status(DISK_STATUS_IN_PROGRESS);
  }

  return op;
}

VmExportOperation::VmExportOperation(const VmId vm_id,
                                     const base::FilePath disk_path,
                                     base::ScopedFD out_fd,
                                     base::ScopedFD out_digest_fd,
                                     ArchiveFormat out_fmt)
    : DiskImageOperation(std::move(vm_id)),
      src_image_path_(std::move(disk_path)),
      out_fd_(std::move(out_fd)),
      out_digest_fd_(std::move(out_digest_fd)),
      copying_data_(false),
      out_fmt_(std::move(out_fmt)),
      sha256_(crypto::SecureHash::Create(crypto::SecureHash::SHA256)) {
  base::File::Info info;
  if (GetFileInfo(src_image_path_, &info) && !info.is_directory) {
    set_source_size(info.size);
    image_is_directory_ = false;
  } else {
    set_source_size(ComputeDirectorySize(src_image_path_));
    image_is_directory_ = true;
  }
}

VmExportOperation::~VmExportOperation() {
  // Ensure that the archive reader and writers are destroyed first, as these
  // can invoke callbacks that rely on data in this object.
  in_.reset();
  out_.reset();
}

bool VmExportOperation::PrepareInput() {
  in_ = ArchiveReader(archive_read_disk_new());
  if (!in_) {
    set_failure_reason("libarchive: failed to create reader");
    return false;
  }

  // Do not cross mount points and do not archive chattr and xattr attributes.
  archive_read_disk_set_behavior(
      in_.get(), ARCHIVE_READDISK_NO_TRAVERSE_MOUNTS |
                     ARCHIVE_READDISK_NO_FFLAGS | ARCHIVE_READDISK_NO_XATTR);
  // Do not traverse symlinks.
  archive_read_disk_set_symlink_physical(in_.get());

  int ret = archive_read_disk_open(in_.get(), src_image_path_.value().c_str());
  if (ret != ARCHIVE_OK) {
    set_failure_reason("failed to open source directory as an archive");
    return false;
  }

  return true;
}

bool VmExportOperation::PrepareOutput() {
  out_ = ArchiveWriter(archive_write_new());
  if (!out_) {
    set_failure_reason("libarchive: failed to create writer");
    return false;
  }

  int ret;
  switch (out_fmt_) {
    case ArchiveFormat::ZIP:
      ret = archive_write_set_format_zip(out_.get());
      if (ret != ARCHIVE_OK) {
        set_failure_reason(base::StringPrintf(
            "libarchive: failed to initialize zip format: %s, %s",
            archive_error_string(out_.get()),
            strerror(archive_errno(out_.get()))));
        return false;
      }
      break;
    case ArchiveFormat::TAR_GZ:
      ret = archive_write_add_filter_gzip(out_.get());
      if (ret != ARCHIVE_OK) {
        set_failure_reason(base::StringPrintf(
            "libarchive: failed to initialize gzip filter: %s, %s",
            archive_error_string(out_.get()),
            strerror(archive_errno(out_.get()))));
        return false;
      }

      ret = archive_write_set_format_pax_restricted(out_.get());
      if (ret != ARCHIVE_OK) {
        set_failure_reason(base::StringPrintf(
            "libarchive: failed to initialize pax format: %s, %s",
            archive_error_string(out_.get()),
            strerror(archive_errno(out_.get()))));
        return false;
      }
      break;
  }

  ret = archive_write_open(out_.get(), reinterpret_cast<void*>(this),
                           OutputFileOpenCallback, OutputFileWriteCallback,
                           OutputFileCloseCallback);
  if (ret != ARCHIVE_OK) {
    set_failure_reason("failed to open output archive");
    return false;
  }

  return true;
}

// static
int VmExportOperation::OutputFileOpenCallback(archive* a, void* data) {
  // We expect that we are writing into a regular file, so no padding is needed.
  archive_write_set_bytes_in_last_block(a, 1);
  return ARCHIVE_OK;
}

// static
ssize_t VmExportOperation::OutputFileWriteCallback(archive* a,
                                                   void* data,
                                                   const void* buf,
                                                   size_t length) {
  VmExportOperation* op = reinterpret_cast<VmExportOperation*>(data);

  ssize_t bytes_written = HANDLE_EINTR(write(op->out_fd_.get(), buf, length));
  if (bytes_written <= 0) {
    archive_set_error(a, errno, "Write error");
    return -1;
  }

  op->sha256_->Update(buf, bytes_written);
  return bytes_written;
}

// static
int VmExportOperation::OutputFileCloseCallback(archive* a, void* data) {
  return ARCHIVE_OK;
}

void VmExportOperation::MarkFailed(const char* msg, struct archive* a) {
  if (a) {
    set_status(archive_errno(a) == ENOSPC ? DISK_STATUS_NOT_ENOUGH_SPACE
                                          : DISK_STATUS_FAILED);
    set_failure_reason(base::StringPrintf("%s: %s, %s", msg,
                                          archive_error_string(a),
                                          strerror(archive_errno(a))));
  } else {
    set_status(DISK_STATUS_FAILED);
    set_failure_reason(msg);
  }

  LOG(ERROR) << "Vm export failed: " << failure_reason();

  // Release resources.
  out_.reset();
  out_fd_.reset();
  out_digest_fd_.reset();
  in_.reset();
}

bool VmExportOperation::ExecuteIo(uint64_t io_limit) {
  do {
    if (!copying_data_) {
      struct archive_entry* entry;
      int ret = archive_read_next_header(in_.get(), &entry);
      if (ret == ARCHIVE_EOF) {
        // Successfully copied entire archive.
        return true;
      }

      if (ret < ARCHIVE_OK) {
        MarkFailed("failed to read header", in_.get());
        break;
      }

      // Signal our intent to descend into directory (noop if current entry
      // is not a directory).
      archive_read_disk_descend(in_.get());

      const char* c_path = archive_entry_pathname(entry);
      if (!c_path || c_path[0] == '\0') {
        MarkFailed("archive entry read from disk has empty file name", NULL);
        break;
      }

      base::FilePath path(c_path);
      if (image_is_directory_) {
        if (path == src_image_path_) {
          // Skip the image directory entry itself, as we will be storing
          // and restoring relative paths.
          continue;
        }

        // Strip the leading directory data as we want relative path,
        // and replace it with <vm_name>.pvm prefix.
        base::FilePath dest_path(vm_id().name() + ".pvm");
        if (!src_image_path_.AppendRelativePath(path, &dest_path)) {
          MarkFailed("failed to transform archive entry name", NULL);
          break;
        }
        archive_entry_set_pathname(entry, dest_path.value().c_str());
      } else {
        archive_entry_set_pathname(entry, path.BaseName().value().c_str());
      }

      ret = archive_write_header(out_.get(), entry);
      if (ret != ARCHIVE_OK) {
        MarkFailed("failed to write header", out_.get());
        break;
      }

      copying_data_ = archive_entry_size(entry) > 0;
    }

    if (copying_data_) {
      uint64_t bytes_read = CopyEntry(io_limit);
      io_limit -= std::min(bytes_read, io_limit);
      AccumulateProcessedSize(bytes_read);
    }

    if (!copying_data_) {
      int ret = archive_write_finish_entry(out_.get());
      if (ret != ARCHIVE_OK) {
        MarkFailed("failed to finish entry", out_.get());
        break;
      }
    }
  } while (status() == DISK_STATUS_IN_PROGRESS && io_limit > 0);

  // More copying is to be done (or there was a failure).
  return false;
}

uint64_t VmExportOperation::CopyEntry(uint64_t io_limit) {
  uint64_t bytes_read = 0;

  do {
    uint8_t buf[16384];
    int count = archive_read_data(in_.get(), buf, sizeof(buf));
    if (count == 0) {
      // No more data
      copying_data_ = false;
      break;
    }

    if (count < 0) {
      MarkFailed("failed to read data block", in_.get());
      break;
    }

    bytes_read += count;

    int ret = archive_write_data(out_.get(), buf, count);
    if (ret < ARCHIVE_OK) {
      MarkFailed("failed to write data block", out_.get());
      break;
    }
  } while (bytes_read < io_limit);

  return bytes_read;
}

void VmExportOperation::Finalize() {
  archive_read_close(in_.get());
  // Free the input archive.
  in_.reset();

  int ret = archive_write_close(out_.get());
  if (ret != ARCHIVE_OK) {
    MarkFailed("libarchive: failed to close writer", out_.get());
    return;
  }
  // Free the output archive structures.
  out_.reset();
  // Close the file descriptor.
  out_fd_.reset();

  // Calculate and store the image hash.
  if (out_digest_fd_.is_valid()) {
    std::vector<uint8_t> digest(sha256_->GetHashLength());
    sha256_->Finish(std::data(digest), digest.size());
    std::string str = base::StringPrintf(
        "%s\n", base::HexEncode(std::data(digest), digest.size()).c_str());
    bool written = base::WriteFileDescriptor(out_digest_fd_.get(), str);
    out_digest_fd_.reset();
    if (!written) {
      LOG(ERROR) << "Failed to write SHA256 digest of the exported image";
      set_status(DISK_STATUS_FAILED);
      return;
    }
  }

  set_status(DISK_STATUS_CREATED);
}

std::unique_ptr<PluginVmImportOperation> PluginVmImportOperation::Create(
    base::ScopedFD fd,
    const base::FilePath disk_path,
    uint64_t source_size,
    const VmId vm_id,
    scoped_refptr<dbus::Bus> bus,
    dbus::ObjectProxy* vmplugin_service_proxy) {
  auto op = base::WrapUnique(new PluginVmImportOperation(
      std::move(fd), source_size, std::move(disk_path), std::move(vm_id),
      std::move(bus), vmplugin_service_proxy));

  if (op->PrepareInput() && op->PrepareOutput()) {
    op->set_status(DISK_STATUS_IN_PROGRESS);
  }

  return op;
}

PluginVmImportOperation::PluginVmImportOperation(
    base::ScopedFD in_fd,
    uint64_t source_size,
    const base::FilePath disk_path,
    const VmId vm_id,
    scoped_refptr<dbus::Bus> bus,
    dbus::ObjectProxy* vmplugin_service_proxy)
    : DiskImageOperation(std::move(vm_id)),
      dest_image_path_(std::move(disk_path)),
      bus_(std::move(bus)),
      vmplugin_service_proxy_(vmplugin_service_proxy),
      in_fd_(std::move(in_fd)),
      copying_data_(false) {
  set_source_size(source_size);
}

PluginVmImportOperation::~PluginVmImportOperation() {
  // Ensure that the archive reader and writers are destroyed first, as these
  // can invoke callbacks that rely on data in this object.
  in_.reset();
  out_.reset();
}

bool PluginVmImportOperation::PrepareInput() {
  in_ = ArchiveReader(archive_read_new());
  if (!in_.get()) {
    set_failure_reason("libarchive: failed to create reader");
    return false;
  }

  int ret = archive_read_support_format_zip(in_.get());
  if (ret != ARCHIVE_OK) {
    set_failure_reason("libarchive: failed to initialize zip format");
    return false;
  }

  ret = archive_read_support_filter_all(in_.get());
  if (ret != ARCHIVE_OK) {
    set_failure_reason("libarchive: failed to initialize filter");
    return false;
  }

  ret = archive_read_open_fd(in_.get(), in_fd_.get(), 102400);
  if (ret != ARCHIVE_OK) {
    set_failure_reason("failed to open input archive");
    return false;
  }

  return true;
}

bool PluginVmImportOperation::PrepareOutput() {
  // We are not using CreateUniqueTempDirUnderPath() because we want
  // to be able to identify images that are being imported, and that
  // requires directory name to not be random.
  base::FilePath disk_path(dest_image_path_.AddExtension(".tmp"));
  if (base::PathExists(disk_path)) {
    set_failure_reason("VM with this name is already being imported");
    return false;
  }

  base::File::Error dir_error;
  if (!base::CreateDirectoryAndGetError(disk_path, &dir_error)) {
    set_failure_reason(std::string("failed to create output directory: ") +
                       base::File::ErrorToString(dir_error));
    return false;
  }

  CHECK(output_dir_.Set(disk_path));

  out_ = ArchiveWriter(archive_write_disk_new());
  if (!out_) {
    set_failure_reason("libarchive: failed to create writer");
    return false;
  }

  int ret = archive_write_disk_set_options(
      out_.get(), ARCHIVE_EXTRACT_SECURE_SYMLINKS |
                      ARCHIVE_EXTRACT_SECURE_NODOTDOT | ARCHIVE_EXTRACT_OWNER);
  if (ret != ARCHIVE_OK) {
    set_failure_reason("libarchive: failed to initialize filter");
    return false;
  }

  return true;
}

void PluginVmImportOperation::MarkFailed(const char* msg, struct archive* a) {
  if (a) {
    set_status(archive_errno(a) == ENOSPC ? DISK_STATUS_NOT_ENOUGH_SPACE
                                          : DISK_STATUS_FAILED);
    set_failure_reason(base::StringPrintf("%s: %s, %s", msg,
                                          archive_error_string(a),
                                          strerror(archive_errno(a))));
  } else {
    set_status(DISK_STATUS_FAILED);
    set_failure_reason(msg);
  }

  LOG(ERROR) << "PluginVm import failed: " << failure_reason();

  // Release resources.
  out_.reset();
  if (output_dir_.IsValid() && !output_dir_.Delete()) {
    LOG(WARNING) << "Failed to delete output directory on error";
  }

  in_.reset();
  in_fd_.reset();
}

bool PluginVmImportOperation::ExecuteIo(uint64_t io_limit) {
  do {
    if (!copying_data_) {
      struct archive_entry* entry;
      int ret = archive_read_next_header(in_.get(), &entry);
      if (ret == ARCHIVE_EOF) {
        // Successfully copied entire archive.
        return true;
      }

      if (ret < ARCHIVE_OK) {
        MarkFailed("failed to read header", in_.get());
        break;
      }

      const char* c_path = archive_entry_pathname(entry);
      if (!c_path || c_path[0] == '\0') {
        MarkFailed("archive entry has empty file name", NULL);
        break;
      }

      base::FilePath path(c_path);
      if (path.empty() || path.IsAbsolute() || path.ReferencesParent()) {
        MarkFailed(
            "archive entry has invalid/absolute/referencing parent file name",
            NULL);
        break;
      }

      // Drop the top level <directory>.pvm prefix, if it is present.
      std::vector<std::string> path_parts = path.GetComponents();
      DCHECK(!path_parts.empty());

      auto dest_path = output_dir_.GetPath();
      auto i = path_parts.begin();
      if (base::FilePath(*i).FinalExtension() == ".pvm")
        i++;
      for (; i != path_parts.end(); i++) {
        dest_path = dest_path.Append(*i);
      }

      archive_entry_set_pathname(entry, dest_path.value().c_str());

      archive_entry_set_uid(entry, getuid());
      archive_entry_set_gid(entry, kPluginVmGid);

      mode_t mode = archive_entry_filetype(entry);
      switch (mode) {
        case AE_IFREG:
          archive_entry_set_perm(entry, 0660);
          break;
        case AE_IFDIR:
          archive_entry_set_perm(entry, 0770);
          break;
      }

      ret = archive_write_header(out_.get(), entry);
      if (ret != ARCHIVE_OK) {
        MarkFailed("failed to write header", out_.get());
        break;
      }

      copying_data_ = archive_entry_size(entry) > 0;
    }

    if (copying_data_) {
      uint64_t bytes_read = CopyEntry(io_limit);
      io_limit -= std::min(bytes_read, io_limit);
      AccumulateProcessedSize(bytes_read);
    }

    if (!copying_data_) {
      int ret = archive_write_finish_entry(out_.get());
      if (ret != ARCHIVE_OK) {
        MarkFailed("failed to finish entry", out_.get());
        break;
      }
    }
  } while (status() == DISK_STATUS_IN_PROGRESS && io_limit > 0);

  // More copying is to be done (or there was a failure).
  return false;
}

// Note that this is extremely similar to VmExportOperation::CopyEntry()
// implementation. The difference is the disk writer supports
// archive_write_data_block() API that handles sparse files, whereas generic
// writer does not, so we have to use separate implementations.
uint64_t PluginVmImportOperation::CopyEntry(uint64_t io_limit) {
  uint64_t bytes_read_begin = archive_filter_bytes(in_.get(), -1);
  uint64_t bytes_read = 0;

  do {
    const void* buff;
    size_t size;
    la_int64_t offset;
    int ret = archive_read_data_block(in_.get(), &buff, &size, &offset);
    if (ret == ARCHIVE_EOF) {
      copying_data_ = false;
      break;
    }

    if (ret != ARCHIVE_OK) {
      MarkFailed("failed to read data block", in_.get());
      break;
    }

    bytes_read = archive_filter_bytes(in_.get(), -1) - bytes_read_begin;

    ret = archive_write_data_block(out_.get(), buff, size, offset);
    if (ret != ARCHIVE_OK) {
      MarkFailed("failed to write data block", out_.get());
      break;
    }
  } while (bytes_read < io_limit);

  return bytes_read;
}

void PluginVmImportOperation::Finalize() {
  archive_read_close(in_.get());
  // Free the input archive.
  in_.reset();
  // Close the file descriptor.
  in_fd_.reset();

  int ret = archive_write_close(out_.get());
  if (ret != ARCHIVE_OK) {
    MarkFailed("libarchive: failed to close writer", out_.get());
    return;
  }
  // Free the output archive structures.
  out_.reset();
  // Make sure resulting image is accessible by the dispatcher process.
  if (chown(output_dir_.GetPath().value().c_str(), -1, kPluginVmGid) < 0) {
    MarkFailed("failed to change group of the destination directory", NULL);
    return;
  }
  // We are setting setgid bit on the directory to make sure any new files
  // created by the plugin will be created with "pluginvm" group ownership.
  if (chmod(output_dir_.GetPath().value().c_str(), 02770) < 0) {
    MarkFailed("failed to change permissions of the destination directory",
               NULL);
    return;
  }
  // Drop the ".tmp" suffix from the directory so that we recognize
  // it as a valid Plugin VM image.
  if (!base::Move(output_dir_.GetPath(), dest_image_path_)) {
    MarkFailed("Unable to rename resulting image directory", NULL);
    return;
  }
  // Tell it not to try cleaning up as we are committed to using the
  // image.
  output_dir_.Take();

  if (!pvm::dispatcher::RegisterVm(bus_, vmplugin_service_proxy_, vm_id(),
                                   dest_image_path_)) {
    MarkFailed("Unable to register imported VM image", NULL);
    DeletePathRecursively(dest_image_path_);
    return;
  }

  set_status(DISK_STATUS_CREATED);
}

std::unique_ptr<VmResizeOperation> VmResizeOperation::Create(
    const VmId vm_id,
    StorageLocation location,
    const base::FilePath disk_path,
    uint64_t disk_size,
    StartResizeCallback start_resize_cb,
    ProcessResizeCallback process_resize_cb) {
  DiskImageStatus status = DiskImageStatus::DISK_STATUS_UNKNOWN;
  std::string failure_reason;
  std::move(start_resize_cb)
      .Run(vm_id.owner_id(), vm_id.name(), location, disk_size, &status,
           &failure_reason);

  auto op = base::WrapUnique(new VmResizeOperation(
      std::move(vm_id), std::move(location), std::move(disk_path),
      std::move(disk_size), std::move(process_resize_cb)));

  op->set_status(status);
  op->set_failure_reason(failure_reason);

  return op;
}

VmResizeOperation::VmResizeOperation(const VmId vm_id,
                                     StorageLocation location,
                                     const base::FilePath disk_path,
                                     uint64_t disk_size,
                                     ProcessResizeCallback process_resize_cb)
    : DiskImageOperation(std::move(vm_id)),
      process_resize_cb_(std::move(process_resize_cb)),
      location_(std::move(location)),
      disk_path_(std::move(disk_path)),
      target_size_(std::move(disk_size)) {}

bool VmResizeOperation::ExecuteIo(uint64_t io_limit) {
  DiskImageStatus status = DiskImageStatus::DISK_STATUS_UNKNOWN;
  std::string failure_reason;
  process_resize_cb_.Run(vm_id().owner_id(), vm_id().name(), location_,
                         target_size_, &status, &failure_reason);

  set_status(status);
  set_failure_reason(failure_reason);

  if (status != DISK_STATUS_IN_PROGRESS) {
    return true;
  }

  return false;
}

void VmResizeOperation::Finalize() {}

}  // namespace concierge
}  // namespace vm_tools
