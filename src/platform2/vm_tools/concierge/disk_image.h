// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_DISK_IMAGE_H_
#define VM_TOOLS_CONCIERGE_DISK_IMAGE_H_

#include <archive.h>

#include <memory>
#include <string>
#include <vector>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/files/scoped_temp_dir.h>
#include <crypto/secure_hash.h>
#include <dbus/exported_object.h>
#include <dbus/object_proxy.h>

#include <vm_concierge/concierge_service.pb.h>

#include "vm_tools/common/vm_id.h"

namespace vm_tools {
namespace concierge {

class Service;

class DiskImageOperation {
 public:
  virtual ~DiskImageOperation() = default;

  // Execute next chunk of the disk operation, handling up to |io_limit| bytes.
  void Run(uint64_t io_limit);

  // Report operation progress, in 0..100 range.
  int GetProgress() const;

  const std::string& uuid() const { return uuid_; }
  const VmId& vm_id() const { return vm_id_; }
  DiskImageStatus status() const { return status_; }
  const std::string& failure_reason() const { return failure_reason_; }
  int64_t processed_size() const { return processed_size_; }

 protected:
  explicit DiskImageOperation(const VmId vm_id);
  DiskImageOperation(const DiskImageOperation&) = delete;
  DiskImageOperation& operator=(const DiskImageOperation&) = delete;

  // Executes up to |io_limit| bytes of disk operation.
  virtual bool ExecuteIo(uint64_t io_limit) = 0;

  // Called after all IO is done to commit the result.
  virtual void Finalize() = 0;

  void AccumulateProcessedSize(uint64_t size) { processed_size_ += size; }

  void set_status(DiskImageStatus status) { status_ = status; }
  void set_failure_reason(const std::string& reason) {
    failure_reason_ = reason;
  }
  void set_source_size(uint64_t source_size) { source_size_ = source_size; }

 private:
  // UUID assigned to the operation.
  const std::string uuid_;

  // VM owner and name on which behalf the operation is executing.
  const VmId vm_id_;

  // Status of the operation.
  DiskImageStatus status_;

  // Failure reason, if any, to be communicated to the callers.
  std::string failure_reason_;

  // Size of the source of disk operation (bytes).
  uint64_t source_size_;

  // Number of bytes consumed from the source.
  uint64_t processed_size_;
};

class PluginVmCreateOperation : public DiskImageOperation {
 public:
  static std::unique_ptr<PluginVmCreateOperation> Create(
      base::ScopedFD in_fd,
      const base::FilePath& iso_dir,
      uint64_t source_size,
      const VmId vm_id,
      const std::vector<std::string> params);

 protected:
  bool ExecuteIo(uint64_t io_limit) override;
  void Finalize() override;

 private:
  PluginVmCreateOperation(base::ScopedFD in_fd,
                          uint64_t source_size,
                          const VmId vm_id_,
                          const std::vector<std::string> params);
  PluginVmCreateOperation(const PluginVmCreateOperation&) = delete;
  PluginVmCreateOperation& operator=(const PluginVmCreateOperation&) = delete;

  bool PrepareOutput(const base::FilePath& iso_dir);

  void MarkFailed(const char* msg, int error_code);

  // Parameters that need to be passed to the Plugin VM helper when
  // creating the VM.
  const std::vector<std::string> params_;

  // File descriptor from which to fetch the source image.
  base::ScopedFD in_fd_;

  // File descriptor to where the data from source image will
  // be written to.
  base::ScopedFD out_fd_;

  // Destination directory object.
  base::ScopedTempDir output_dir_;
};

struct ArchiveReadDeleter {
  void operator()(struct archive* in) { archive_read_free(in); }
};
using ArchiveReader = std::unique_ptr<struct archive, ArchiveReadDeleter>;

struct ArchiveWriteDeleter {
  void operator()(struct archive* out) { archive_write_free(out); }
};
using ArchiveWriter = std::unique_ptr<struct archive, ArchiveWriteDeleter>;

enum class ArchiveFormat {
  ZIP,
  TAR_GZ,
};

class VmExportOperation : public DiskImageOperation {
 public:
  static std::unique_ptr<VmExportOperation> Create(
      const VmId vm_id,
      const base::FilePath disk_path,
      base::ScopedFD out_fd,
      base::ScopedFD out_digest_fd,
      ArchiveFormat out_fmt);

  ~VmExportOperation() override;

 protected:
  bool ExecuteIo(uint64_t io_limit) override;
  void Finalize() override;

 private:
  static int OutputFileOpenCallback(archive* a, void* data);
  static ssize_t OutputFileWriteCallback(archive* a,
                                         void* data,
                                         const void* buf,
                                         size_t length);
  static int OutputFileCloseCallback(archive* a, void* data);

  VmExportOperation(const VmId vm_id,
                    const base::FilePath disk_path,
                    base::ScopedFD out_fd,
                    base::ScopedFD out_digest_fd,
                    ArchiveFormat out_fmt);
  VmExportOperation(const VmExportOperation&) = delete;
  VmExportOperation& operator=(const VmExportOperation&) = delete;

  bool PrepareInput();
  bool PrepareOutput();

  void MarkFailed(const char* msg, struct archive* a);

  // Copies up to |io_limit| bytes of one file of the image.
  // Returns number of bytes read.
  uint64_t CopyEntry(uint64_t io_limit);

  // Path to the directory containing source image.
  const base::FilePath src_image_path_;

  // File descriptor to write the compressed image to.
  base::ScopedFD out_fd_;

  // File descriptor to write the SHA256 digest of the compressed image to.
  base::ScopedFD out_digest_fd_;

  // We are in a middle of copying an archive entry. Copying of one archive
  // entry may span several Run() invocations, depending on the size of the
  // entry.
  bool copying_data_;

  // If true, disk image is a directory potentially containing multiple files.
  // If false, disk image is a single file.
  bool image_is_directory_;

  // Source directory "archive".
  ArchiveReader in_;

  // Output archive backed by the file descriptor.
  ArchiveWriter out_;

  // Output archive format.
  ArchiveFormat out_fmt_;

  // Hasher to generate digest of the produced image.
  std::unique_ptr<crypto::SecureHash> sha256_;
};

class PluginVmImportOperation : public DiskImageOperation {
 public:
  static std::unique_ptr<PluginVmImportOperation> Create(
      base::ScopedFD in_fd,
      const base::FilePath disk_path,
      uint64_t source_size,
      const VmId vm_id,
      scoped_refptr<dbus::Bus> bus,
      dbus::ObjectProxy* vmplugin_service_proxy);

  ~PluginVmImportOperation() override;

 protected:
  bool ExecuteIo(uint64_t io_limit) override;
  void Finalize() override;

 private:
  PluginVmImportOperation(base::ScopedFD in_fd,
                          uint64_t source_size,
                          const base::FilePath disk_path,
                          const VmId vm_id_,
                          scoped_refptr<dbus::Bus> bus,
                          dbus::ObjectProxy* vmplugin_service_proxy);
  PluginVmImportOperation(const PluginVmImportOperation&) = delete;
  PluginVmImportOperation& operator=(const PluginVmImportOperation&) = delete;

  bool PrepareInput();
  bool PrepareOutput();

  void MarkFailed(const char* msg, struct archive* a);

  // Copies up to |io_limit| bytes of one archive entry of the image.
  // Returns number of bytes read.
  uint64_t CopyEntry(uint64_t io_limit);

  // Path to the directory that will contain the imported image.
  const base::FilePath dest_image_path_;

  // Connection to the system bus.
  scoped_refptr<dbus::Bus> bus_;

  // Proxy to the dispatcher service.  Not owned.
  dbus::ObjectProxy* vmplugin_service_proxy_;

  // File descriptor from which to fetch the source image.
  base::ScopedFD in_fd_;

  // We are in a middle of copying an archive entry. Copying of one archive
  // entry may span several Run() invocations, depending on the size of the
  // entry.
  bool copying_data_;

  // Destination directory object.
  base::ScopedTempDir output_dir_;

  // Input compressed archive backed up by the file descriptor.
  ArchiveReader in_;

  // "Archive" representing output uncompressed directory.
  ArchiveWriter out_;
};

class VmResizeOperation : public DiskImageOperation {
 public:
  using StartResizeCallback =
      base::OnceCallback<void(const std::string& owner_id,
                              const std::string& vm_name,
                              StorageLocation location,
                              uint64_t target_size,
                              DiskImageStatus* status,
                              std::string* failure_reason)>;
  using ProcessResizeCallback =
      base::RepeatingCallback<void(const std::string& owner_id,
                                   const std::string& vm_name,
                                   StorageLocation location,
                                   uint64_t target_size,
                                   DiskImageStatus* status,
                                   std::string* failure_reason)>;

  static std::unique_ptr<VmResizeOperation> Create(
      const VmId vm_id,
      StorageLocation location,
      const base::FilePath disk_path,
      uint64_t disk_size,
      StartResizeCallback start_resize_cb,
      ProcessResizeCallback process_resize_cb);

 protected:
  bool ExecuteIo(uint64_t io_limit) override;
  void Finalize() override;

 private:
  VmResizeOperation(const VmId vm_id,
                    StorageLocation location,
                    const base::FilePath disk_path,
                    uint64_t size,
                    ProcessResizeCallback process_resize_cb);
  VmResizeOperation(const VmResizeOperation&) = delete;
  VmResizeOperation& operator=(const VmResizeOperation&) = delete;

  ProcessResizeCallback process_resize_cb_;

  StorageLocation location_;

  base::FilePath disk_path_;

  uint64_t target_size_;
};

}  // namespace concierge
}  // namespace vm_tools

#endif  // VM_TOOLS_CONCIERGE_DISK_IMAGE_H_
