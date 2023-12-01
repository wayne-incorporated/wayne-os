// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/data_migrator/migration_helper.h"

#include <algorithm>
#include <deque>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/message_loop/message_pump_type.h>
#include <base/strings/string_number_conversions.h>
#include <base/synchronization/condition_variable.h>
#include <base/system/sys_info.h>
#include <base/threading/thread.h>
#include <base/timer/elapsed_timer.h>

extern "C" {
#include <linux/fs.h>
}

namespace cryptohome::data_migrator {

namespace {

// The name of the file to be created to mark the start of the migration.
// NOTE: The file name contains 'crypto' for a historical reason, while this
// tool is used for for other types of migration (e.g., ARCVM /data migration).
constexpr char kMigrationStartedFileName[] = "crypto-migration.started";
// Expected maximum erasure block size on devices (4MB).
constexpr uint64_t kErasureBlockSize = 4 << 20;
// Free space required for migration overhead (FS metadata, duplicated
// in-progress directories, etc).  Must be smaller than kMinFreeSpace.
constexpr uint64_t kFreeSpaceBuffer = kErasureBlockSize;

// The maximum size of job list.
constexpr size_t kDefaultMaxJobListSize = 100000;

// TODO(dspaid): Determine performance impact so we can potentially increase
// frequency.
constexpr base::TimeDelta kStatusSignalInterval = base::Seconds(1);

// Sends the UMA stat for the start/end status of migration respectively in the
// constructor/destructor. By default the "generic error" end status is set, so
// to report other status, call an appropriate method to overwrite it.
class MigrationStartAndEndStatusReporter {
 public:
  MigrationStartAndEndStatusReporter(MigrationHelperDelegate* delegate,
                                     bool resumed,
                                     const base::AtomicFlag& is_cancelled)
      : delegate_(delegate),
        resumed_(resumed),
        is_cancelled_(is_cancelled),
        end_status_(resumed ? kResumedMigrationFailedGeneric
                            : kNewMigrationFailedGeneric) {
    delegate_->ReportStartStatus(resumed_ ? kMigrationResumed
                                          : kMigrationStarted);
  }
  MigrationStartAndEndStatusReporter(
      const MigrationStartAndEndStatusReporter&) = delete;
  MigrationStartAndEndStatusReporter& operator=(
      const MigrationStartAndEndStatusReporter&) = delete;

  ~MigrationStartAndEndStatusReporter() {
    if (is_cancelled_.IsSet()) {
      end_status_ =
          resumed_ ? kResumedMigrationCancelled : kNewMigrationCancelled;
    }
    delegate_->ReportEndStatus(end_status_);
  }

  void SetSuccess() {
    end_status_ = resumed_ ? kResumedMigrationFinished : kNewMigrationFinished;
  }

  void SetLowDiskSpaceFailure() {
    end_status_ = resumed_ ? kResumedMigrationFailedLowDiskSpace
                           : kNewMigrationFailedLowDiskSpace;
  }

  void SetFileErrorFailure(MigrationFailedOperationType operation,
                           base::File::Error error) {
    // Some notable special cases are given distinct enum values.
    if (operation == kMigrationFailedAtOpenSourceFile &&
        error == base::File::FILE_ERROR_IO) {
      end_status_ = resumed_ ? kResumedMigrationFailedFileErrorOpenEIO
                             : kNewMigrationFailedFileErrorOpenEIO;
    } else if (error == base::File::FILE_ERROR_NO_SPACE) {
      end_status_ =
          resumed_ ? kResumedMigrationFailedENOSPC : kNewMigrationFailedENOSPC;
    } else {
      end_status_ = resumed_ ? kResumedMigrationFailedFileError
                             : kNewMigrationFailedFileError;
    }
  }

 private:
  MigrationHelperDelegate* delegate_;
  const bool resumed_;
  const base::AtomicFlag& is_cancelled_;
  MigrationEndStatus end_status_;
};

}  // namespace

// {Source,Referrer}URL xattrs are from chrome downloads and are not used on
// ChromeOS.  They may be very large though, potentially preventing the
// migration of other attributes.
const char kSourceURLXattrName[] = "user.xdg.origin.url";
const char kReferrerURLXattrName[] = "user.xdg.referrer.url";

// Job represents a job to migrate a file or a symlink.
struct MigrationHelper::Job {
  Job() = default;
  ~Job() = default;
  base::FilePath child;
  base::stat_wrapper_t stat;
};

// WorkerPool manages jobs and job threads.
// All public methods must be called on the main thread unless otherwise
// specified.
class MigrationHelper::WorkerPool {
 public:
  explicit WorkerPool(MigrationHelper* migration_helper)
      : migration_helper_(migration_helper),
        job_thread_wakeup_condition_(&jobs_lock_),
        main_thread_wakeup_condition_(&jobs_lock_) {}
  WorkerPool(const WorkerPool&) = delete;
  WorkerPool& operator=(const WorkerPool&) = delete;

  ~WorkerPool() { Join(); }

  // Starts job threads.
  bool Start(size_t num_job_threads, size_t max_job_list_size) {
    job_threads_.resize(num_job_threads);
    job_thread_results_.resize(num_job_threads, false);
    max_job_list_size_ = max_job_list_size;

    for (size_t i = 0; i < job_threads_.size(); ++i) {
      job_threads_[i] = std::make_unique<base::Thread>(
          "MigrationHelper worker #" + base::NumberToString(i));
      base::Thread::Options options;
      options.message_pump_type = base::MessagePumpType::IO;
      if (!job_threads_[i]->StartWithOptions(std::move(options))) {
        LOG(ERROR) << "Failed to start a job thread.";
        return false;
      }
      job_threads_[i]->task_runner()->PostTask(
          FROM_HERE,
          base::BindOnce(&WorkerPool::ProcessJobs, base::Unretained(this),
                         &job_thread_results_[i]));
    }
    return true;
  }

  // Adds a job to the job list.
  bool PushJob(const Job& job) {
    base::AutoLock lock(jobs_lock_);
    while (jobs_.size() >= max_job_list_size_ && !should_abort_) {
      main_thread_wakeup_condition_.Wait();
    }
    if (should_abort_) {
      return false;
    }
    jobs_.push_back(job);
    // Let a job thread process the new job.
    job_thread_wakeup_condition_.Signal();
    return true;
  }

  // Waits for job threads to process all pushed jobs and returns true if there
  // was no error.
  bool Join() {
    {
      // Wake up all waiting job threads.
      base::AutoLock lock(jobs_lock_);
      no_more_new_jobs_ = true;
      job_thread_wakeup_condition_.Broadcast();
    }
    job_threads_.clear();  // Join threads.

    base::AutoLock lock(jobs_lock_);  // For should_abort_.
    return std::count(job_thread_results_.begin(), job_thread_results_.end(),
                      false) == 0 &&
           !should_abort_;
  }

  // Aborts job processing.
  // Can be called on any thread.
  void Abort() {
    base::AutoLock lock(jobs_lock_);
    no_more_new_jobs_ = true;
    should_abort_ = true;
    main_thread_wakeup_condition_.Signal();
    job_thread_wakeup_condition_.Broadcast();
  }

 private:
  // Processes jobs fed by the main thread.
  // Must be called on a job thread.
  void ProcessJobs(bool* result) {
    // Continue running on a job thread while the main thread feeds jobs.
    while (true) {
      Job job;
      if (!PopJob(&job)) {  // No more new jobs.
        *result = true;
        return;
      }
      if (!migration_helper_->ProcessJob(job)) {
        LOG(ERROR) << "Failed to migrate \"" << job.child.value() << "\"";
        Abort();
        *result = false;
        return;
      }
    }
  }

  // Pops a job from the job list. Returns false when the thread should stop.
  // Must be called on a job thread.
  bool PopJob(Job* job) {
    base::AutoLock lock(jobs_lock_);
    while (jobs_.empty()) {
      if (no_more_new_jobs_)
        return false;
      job_thread_wakeup_condition_.Wait();
    }
    if (should_abort_) {
      return false;
    }
    *job = jobs_.front();
    jobs_.pop_front();
    // Let the main thread feed new jobs.
    main_thread_wakeup_condition_.Signal();
    return true;
  }

  MigrationHelper* migration_helper_;
  std::vector<std::unique_ptr<base::Thread>> job_threads_;  // The job threads.
  // deque instead of vector to avoid vector<bool> specialization.
  std::deque<bool> job_thread_results_;
  size_t max_job_list_size_ = 0;

  std::deque<Job> jobs_;  // The FIFO job list.
  bool no_more_new_jobs_ = false;
  bool should_abort_ = false;
  // Lock for jobs_, no_more_new_jobs_, and should_abort_.
  base::Lock jobs_lock_;
  // Condition variables associated with jobs_lock_.
  base::ConditionVariable job_thread_wakeup_condition_;
  base::ConditionVariable main_thread_wakeup_condition_;
};

MigrationHelper::MigrationHelper(Platform* platform,
                                 MigrationHelperDelegate* delegate,
                                 const base::FilePath& from,
                                 const base::FilePath& to,
                                 const base::FilePath& status_files_dir,
                                 uint64_t max_chunk_size)
    : platform_(platform),
      delegate_(delegate),
      from_base_path_(from),
      to_base_path_(to),
      status_files_dir_(status_files_dir),
      max_chunk_size_(max_chunk_size),
      effective_chunk_size_(0),
      total_byte_count_(0),
      total_directory_byte_count_(0),
      n_files_(0),
      n_dirs_(0),
      n_symlinks_(0),
      migrated_byte_count_(0),
      failed_operation_type_(kMigrationFailedAtOtherOperation),
      failed_error_type_(base::File::FILE_OK),
      no_space_failure_free_space_bytes_(0),
      num_job_threads_(0),
      max_job_list_size_(kDefaultMaxJobListSize),
      worker_pool_(new WorkerPool(this)) {}

MigrationHelper::~MigrationHelper() {}

bool MigrationHelper::Migrate(const ProgressCallback& progress_callback) {
  base::ElapsedTimer timer;
  const bool resumed = IsMigrationStarted();
  MigrationStartAndEndStatusReporter status_reporter(delegate_, resumed,
                                                     is_cancelled_);

  if (progress_callback.is_null()) {
    LOG(ERROR) << "Invalid progress callback";
    return false;
  }
  progress_callback_ = progress_callback;
  ReportStatus();
  if (!from_base_path_.IsAbsolute() || !to_base_path_.IsAbsolute()) {
    LOG(ERROR) << "Migrate must be given absolute paths";
    return false;
  }

  if (!platform_->DirectoryExists(from_base_path_)) {
    LOG(ERROR) << "Directory does not exist: " << from_base_path_.value();
    return false;
  }

  if (!platform_->TouchFileDurable(
          status_files_dir_.Append(kMigrationStartedFileName))) {
    LOG(ERROR) << "Failed to create migration-started file";
    return false;
  }

  initial_dest_free_space_bytes_ =
      platform_->AmountOfFreeDiskSpace(to_base_path_);
  if (initial_dest_free_space_bytes_ < 0) {
    LOG(ERROR) << "Failed to determine free disk space on destination";
    return false;
  }
  const int64_t free_space_for_migrator_signed =
      delegate_->FreeSpaceForMigrator();
  if (free_space_for_migrator_signed < 0) {
    LOG(ERROR) << "Failed to determine free disk space for migrator";
    return false;
  }
  const uint64_t free_space_for_migrator =
      static_cast<uint64_t>(free_space_for_migrator_signed);
  const uint64_t kRequiredFreeSpaceForMainThread =
      kFreeSpaceBuffer + total_directory_byte_count_;
  // Calculate required space used by the number of job threads (or a minimum of
  // 1 thread of the number is dynamic)
  const uint64_t kRequiredFreeSpace =
      kRequiredFreeSpaceForMainThread +
      (num_job_threads_ == 0 ? 1 : num_job_threads_) * kErasureBlockSize;
  if (free_space_for_migrator < kRequiredFreeSpace) {
    LOG(ERROR) << "Not enough space to begin the migration";
    status_reporter.SetLowDiskSpaceFailure();
    return false;
  }
  const uint64_t kFreeSpaceForJobThreads =
      free_space_for_migrator - kRequiredFreeSpaceForMainThread;
  if (num_job_threads_ == 0) {
    // Limit the number of job threads based on the available free space.
    num_job_threads_ =
        std::min(static_cast<uint64_t>(base::SysInfo::NumberOfProcessors() * 2),
                 kFreeSpaceForJobThreads / kErasureBlockSize);
  }
  effective_chunk_size_ =
      std::min(max_chunk_size_, kFreeSpaceForJobThreads / num_job_threads_);
  if (effective_chunk_size_ > kErasureBlockSize)
    effective_chunk_size_ =
        effective_chunk_size_ - (effective_chunk_size_ % kErasureBlockSize);

  LOG(INFO) << "Free space for migrator: " << free_space_for_migrator;
  LOG(INFO) << "Total directory byte count: " << total_directory_byte_count_;
  LOG(INFO) << "Effective chunk size: " << effective_chunk_size_;
  LOG(INFO) << "Number of job threads: " << num_job_threads_;

  if (delegate_->ShouldReportProgress()) {
    // Calculate total bytes to migrate only if we need to report the progress.
    if (!CalculateDataToMigrate(from_base_path_)) {
      LOG(ERROR) << "Failed to calculate number of bytes to migrate";
      return false;
    }
    if (!resumed) {
      delegate_->ReportTotalSize(total_byte_count_ / 1024 / 1024,
                                 n_files_ + n_dirs_ + n_symlinks_);
    }
  }
  ReportStatus();
  base::stat_wrapper_t from_stat;
  if (!platform_->Stat(from_base_path_, &from_stat)) {
    PLOG(ERROR) << "Failed to stat from directory";
    RecordFileErrorWithCurrentErrno(kMigrationFailedAtStat, base::FilePath(),
                                    FailureLocationType::kSource);
    status_reporter.SetFileErrorFailure(failed_operation_type_,
                                        failed_error_type_);
    return false;
  }
  delegate_->ReportStartTime();
  LOG(INFO) << "Preparation took " << timer.Elapsed().InMilliseconds()
            << " ms.";
  // MigrateDir() recursively traverses the directory tree on the main thread,
  // while the job threads migrate files and symlinks.
  bool success =
      worker_pool_->Start(num_job_threads_, max_job_list_size_) &&
      MigrateDir(base::FilePath(base::FilePath::kCurrentDirectory), from_stat);
  // No matter if successful or not, always join the job threads.
  if (!worker_pool_->Join())
    success = false;
  if (!success) {
    LOG(ERROR) << "Migration Failed, aborting.";
    status_reporter.SetFileErrorFailure(failed_operation_type_,
                                        failed_error_type_);
    if (failed_error_type_ == base::File::FILE_ERROR_NO_SPACE) {
      delegate_->ReportFailedNoSpace(
          initial_dest_free_space_bytes_ / (1024 * 1024),
          no_space_failure_free_space_bytes_ / (1024 * 1024));
    }
    return false;
  }
  if (!resumed)
    delegate_->ReportEndTime();

  // One more progress update to say that we've hit 100%
  ReportStatus();
  status_reporter.SetSuccess();
  const int elapsed_ms = timer.Elapsed().InMilliseconds();
  const int speed_kb_per_s = elapsed_ms ? (total_byte_count_ / elapsed_ms) : 0;
  if (delegate_->ShouldReportProgress()) {
    LOG(INFO) << "Migrated " << total_byte_count_ << " bytes in " << elapsed_ms
              << " ms at " << speed_kb_per_s << " KB/s.";
  } else {
    LOG(INFO) << "Minimal migration took " << elapsed_ms << " ms.";
  }
  return true;
}

bool MigrationHelper::IsMigrationStarted() const {
  return platform_->FileExists(
      status_files_dir_.Append(kMigrationStartedFileName));
}

void MigrationHelper::Cancel() {
  worker_pool_->Abort();
  is_cancelled_.Set();
}

bool MigrationHelper::CalculateDataToMigrate(const base::FilePath& from) {
  total_byte_count_ = 0;
  total_directory_byte_count_ = 0;
  migrated_byte_count_ = 0;
  std::unique_ptr<FileEnumerator> enumerator(platform_->GetFileEnumerator(
      from, true /* recursive */,
      base::FileEnumerator::FILES | base::FileEnumerator::DIRECTORIES |
          base::FileEnumerator::SHOW_SYM_LINKS));
  for (base::FilePath entry = enumerator->Next(); !entry.empty();
       entry = enumerator->Next()) {
    if (is_cancelled_.IsSet()) {
      return false;
    }
    const FileEnumerator::FileInfo& info = enumerator->GetInfo();
    total_byte_count_ += info.GetSize();

    if (S_ISREG(info.stat().st_mode))
      ++n_files_;
    if (S_ISDIR(info.stat().st_mode)) {
      total_directory_byte_count_ += info.GetSize();
      ++n_dirs_;
    }
    if (S_ISLNK(info.stat().st_mode))
      ++n_symlinks_;
  }
  LOG(INFO) << "Number of files: " << n_files_;
  LOG(INFO) << "Number of directories: " << n_dirs_;
  LOG(INFO) << "Number of symlinks: " << n_symlinks_;
  return true;
}

void MigrationHelper::IncrementMigratedBytes(uint64_t bytes) {
  base::AutoLock lock(migrated_byte_count_lock_);
  migrated_byte_count_ += bytes;
  if (next_report_ < base::TimeTicks::Now())
    ReportStatus();
}

void MigrationHelper::ReportStatus() {
  if (!delegate_->ShouldReportProgress()) {
    return;
  }

  progress_callback_.Run(migrated_byte_count_, total_byte_count_);

  next_report_ = base::TimeTicks::Now() + kStatusSignalInterval;
}

bool MigrationHelper::MigrateDir(const base::FilePath& child,
                                 const base::stat_wrapper_t& stat) {
  if (is_cancelled_.IsSet()) {
    return false;
  }
  const base::FilePath from_dir = from_base_path_.Append(child);
  const base::FilePath to_dir = to_base_path_.Append(child);

  base::File::Error error;
  if (!platform_->CreateDirectoryAndGetError(to_dir, &error)) {
    LOG(ERROR) << "Failed to create directory " << to_dir.value();
    RecordFileError(kMigrationFailedAtMkdir, child, error,
                    FailureLocationType::kDest);
    return false;
  }
  if (!platform_->SyncDirectory(to_dir.DirName())) {
    RecordFileErrorWithCurrentErrno(kMigrationFailedAtSync, child,
                                    FailureLocationType::kDest);
    return false;
  }
  if (!CopyAttributes(child, stat))
    return false;

  // Dummy child count increment to protect this directory while reading.
  IncrementChildCount(child);
  std::unique_ptr<FileEnumerator> enumerator(platform_->GetFileEnumerator(
      from_dir, false /* is_recursive */,
      base::FileEnumerator::FILES | base::FileEnumerator::DIRECTORIES |
          base::FileEnumerator::SHOW_SYM_LINKS));

  for (base::FilePath entry = enumerator->Next(); !entry.empty();
       entry = enumerator->Next()) {
    const base::FilePath& new_child = child.Append(entry.BaseName());
    base::stat_wrapper_t entry_stat = enumerator->GetInfo().stat();
    if (!delegate_->ShouldMigrateFile(new_child) ||
        !delegate_->ConvertFileMetadata(&entry_stat)) {
      // Delete paths which should be skipped
      if (!platform_->DeletePathRecursively(entry)) {
        PLOG(ERROR) << "Failed to delete " << entry.value();
        RecordFileErrorWithCurrentErrno(kMigrationFailedAtDelete, new_child,
                                        FailureLocationType::kSource);
        return false;
      }
      continue;
    }

    IncrementChildCount(child);
    if (S_ISDIR(entry_stat.st_mode)) {
      // Directory.
      if (!MigrateDir(new_child, entry_stat))
        return false;
      IncrementMigratedBytes(entry_stat.st_size);
    } else {
      Job job;
      job.child = new_child;
      job.stat = entry_stat;
      if (!worker_pool_->PushJob(job))
        return false;
    }
  }
  enumerator.reset();
  // Decrement the placeholder child count.
  return DecrementChildCountAndDeleteIfNecessary(child);
}

bool MigrationHelper::MigrateLink(const base::FilePath& child,
                                  const base::stat_wrapper_t& stat) {
  const base::FilePath source = from_base_path_.Append(child);
  const base::FilePath new_path = to_base_path_.Append(child);
  base::FilePath target;
  if (!platform_->ReadLink(source, &target)) {
    RecordFileErrorWithCurrentErrno(kMigrationFailedAtReadLink, child,
                                    FailureLocationType::kSource);
    return false;
  }

  if (from_base_path_.IsParent(target)) {
    base::FilePath new_target = to_base_path_;
    from_base_path_.AppendRelativePath(target, &new_target);
    target = new_target;
  }
  // In the case that the link was already created by a previous migration
  // it should be removed to prevent errors recreating it below.
  if (!platform_->DeleteFile(new_path)) {
    PLOG(ERROR) << "Failed to delete existing symlink " << new_path.value();
    RecordFileErrorWithCurrentErrno(kMigrationFailedAtDelete, child,
                                    FailureLocationType::kDest);
    return false;
  }
  if (!platform_->CreateSymbolicLink(new_path, target)) {
    RecordFileErrorWithCurrentErrno(kMigrationFailedAtCreateLink, child,
                                    FailureLocationType::kDest);
    return false;
  }

  if (!CopyAttributes(child, stat))
    return false;
  // We don't need to modify the source file, so we can safely set times here
  // directly instead of storing them in xattrs first.
  if (!platform_->SetFileTimes(new_path, stat.st_atim, stat.st_mtim,
                               false /* follow_links */)) {
    PLOG(ERROR) << "Failed to set mtime for " << new_path.value();
    RecordFileErrorWithCurrentErrno(kMigrationFailedAtSetAttribute, child,
                                    FailureLocationType::kDest);
    return false;
  }
  // We can't explicitly f(data)sync symlinks, so we have to do a full FS sync.
  platform_->Sync();
  return true;
}

bool MigrationHelper::MigrateFile(const base::FilePath& child,
                                  const base::stat_wrapper_t& stat) {
  const base::FilePath& from_child = from_base_path_.Append(child);
  const base::FilePath& to_child = to_base_path_.Append(child);
  base::File from_file;
  platform_->InitializeFile(
      &from_file, from_child,
      base::File::FLAG_OPEN | base::File::FLAG_READ | base::File::FLAG_WRITE);
  if (!from_file.IsValid()) {
    if (from_file.error_details() == base::File::FILE_ERROR_IO &&
        delegate_->ShouldSkipFileOnIOErrors()) {
      LOG(WARNING) << "Found file that cannot be opened with EIO, skipping "
                   << from_child.value();
      RecordFileError(kMigrationFailedAtOpenSourceFileNonFatal, child,
                      from_file.error_details(), FailureLocationType::kSource);
      delegate_->RecordSkippedFile(child);
      return true;
    }
    PLOG(ERROR) << "Failed to open file " << from_child.value();
    RecordFileError(kMigrationFailedAtOpenSourceFile, child,
                    from_file.error_details(), FailureLocationType::kSource);
    return false;
  }

  base::File to_file;
  platform_->InitializeFile(
      &to_file, to_child,
      base::File::FLAG_OPEN_ALWAYS | base::File::FLAG_WRITE);
  if (!to_file.IsValid()) {
    PLOG(ERROR) << "Failed to open file " << to_child.value();
    RecordFileError(kMigrationFailedAtOpenDestinationFile, child,
                    to_file.error_details(), FailureLocationType::kDest);
    return false;
  }
  if (!platform_->SyncDirectory(to_child.DirName())) {
    RecordFileErrorWithCurrentErrno(kMigrationFailedAtSync, child,
                                    FailureLocationType::kDest);
    return false;
  }

  int64_t from_length = from_file.GetLength();
  int64_t to_length = to_file.GetLength();
  if (from_length < 0) {
    LOG(ERROR) << "Failed to get length of " << from_child.value();
    RecordFileErrorWithCurrentErrno(kMigrationFailedAtStat, child,
                                    FailureLocationType::kSource);
    return false;
  }
  if (to_length < 0) {
    LOG(ERROR) << "Failed to get length of " << to_child.value();
    RecordFileErrorWithCurrentErrno(kMigrationFailedAtStat, child,
                                    FailureLocationType::kDest);
    return false;
  }
  if (to_length < from_length) {
    // SetLength will call truncate, which on filesystems supporting sparse
    // files should not cause any actual disk space usage.  Instead only the
    // file's metadata is updated to reflect the new size.  Actual block
    // allocation will occur when attempting to write into space in the file
    // which is not yet allocated.
    if (!to_file.SetLength(from_length)) {
      PLOG(ERROR) << "Failed to set file length of " << to_child.value();
      RecordFileErrorWithCurrentErrno(kMigrationFailedAtTruncate, child,
                                      FailureLocationType::kDest);
      return false;
    }
  }

  if (!CopyAttributes(child, stat))
    return false;

  while (from_length > 0) {
    if (is_cancelled_.IsSet()) {
      return false;
    }
    size_t to_read = from_length % effective_chunk_size_;
    if (to_read == 0) {
      to_read = effective_chunk_size_;
    }
    off_t offset = from_length - to_read;
    if (to_file.Seek(base::File::FROM_BEGIN, offset) != offset) {
      LOG(ERROR) << "Failed to seek in " << to_child.value();
      RecordFileErrorWithCurrentErrno(kMigrationFailedAtSeek, child,
                                      FailureLocationType::kDest);
      return false;
    }
    // Sendfile is used here instead of a read to memory then write since it is
    // more efficient for transferring data from one file to another.  In
    // particular the data is passed directly from the read call to the write
    // in the kernel, never making a trip back out to user space.
    if (!platform_->SendFile(to_file.GetPlatformFile(),
                             from_file.GetPlatformFile(), offset, to_read)) {
      RecordFileErrorWithCurrentErrno(kMigrationFailedAtSendfile, child,
                                      FailureLocationType::kSourceOrDest);
      return false;
    }
    // For the last chunk, SyncFile will be called later so no need to flush
    // here. The same goes for SetLength as from_file will be deleted soon.
    if (offset > 0) {
      if (!to_file.Flush()) {
        PLOG(ERROR) << "Failed to flush " << to_child.value();
        RecordFileErrorWithCurrentErrno(kMigrationFailedAtSync, child,
                                        FailureLocationType::kDest);
        return false;
      }
      if (!from_file.SetLength(offset)) {
        PLOG(ERROR) << "Failed to truncate file " << from_child.value();
        RecordFileErrorWithCurrentErrno(kMigrationFailedAtTruncate, child,
                                        FailureLocationType::kSource);
        return false;
      }
    }
    from_length = offset;
    IncrementMigratedBytes(to_read);
  }

  from_file.Close();
  to_file.Close();
  if (!FixTimes(child))
    return false;
  if (!platform_->SyncFile(to_child)) {
    RecordFileErrorWithCurrentErrno(kMigrationFailedAtSync, child,
                                    FailureLocationType::kDest);
    return false;
  }
  if (!RemoveTimeXattrsIfPresent(child))
    return false;

  return true;
}

bool MigrationHelper::CopyAttributes(const base::FilePath& child,
                                     const base::stat_wrapper_t& stat) {
  const base::FilePath from = from_base_path_.Append(child);
  const base::FilePath to = to_base_path_.Append(child);

  if (!platform_->SetOwnership(to, stat.st_uid, stat.st_gid,
                               false /* follow_links */)) {
    RecordFileErrorWithCurrentErrno(kMigrationFailedAtSetAttribute, child,
                                    FailureLocationType::kDest);
    return false;
  }

  if (!CopyExtendedAttributes(child))
    return false;

  mode_t mode = stat.st_mode;

  // We don't need to modify the source file, so no special timestamp handling
  // needed.  Permissions and flags are also not supported on symlinks in linux.
  if (S_ISLNK(mode))
    return true;
  if (!platform_->SetPermissions(to, mode)) {
    RecordFileErrorWithCurrentErrno(kMigrationFailedAtSetAttribute, child,
                                    FailureLocationType::kDest);
    return false;
  }

  // Store mtime/atime to xattr if it's not done already. This should be after
  // copying the other xattrs since this might cause ENOSPC error, in which case
  // we proceed with the migration without copying mtime/atime.
  const auto& mtime = stat.st_mtim;
  const auto& atime = stat.st_atim;
  if (!SetExtendedAttributeIfNotPresent(child, delegate_->GetMtimeXattrName(),
                                        reinterpret_cast<const char*>(&mtime),
                                        sizeof(mtime))) {
    return false;
  }
  if (!SetExtendedAttributeIfNotPresent(child, delegate_->GetAtimeXattrName(),
                                        reinterpret_cast<const char*>(&atime),
                                        sizeof(atime))) {
    return false;
  }

  int flags;
  if (!platform_->GetExtFileAttributes(from, &flags)) {
    RecordFileErrorWithCurrentErrno(kMigrationFailedAtGetAttribute, child,
                                    FailureLocationType::kSource);
    return false;
  }
  /*
   * Exclude deprecated flags that was used by an older version of
   * e2fsprogs.
   * Setting older flags on newer kernel is prohibited and will fail with
   * EOPNOTSUPP.
   */
  if (!platform_->SetExtFileAttributes(to, flags & ~EXT4_EOFBLOCKS_FL)) {
    RecordFileErrorWithCurrentErrno(kMigrationFailedAtSetAttribute, child,
                                    FailureLocationType::kDest);
    return false;
  }

  if (delegate_->ShouldCopyQuotaProjectId()) {
    int project_id = 0;
    if (!platform_->GetQuotaProjectId(from, &project_id)) {
      return false;
    }
    if (!platform_->SetQuotaProjectId(to, project_id)) {
      return false;
    }
  }
  return true;
}

bool MigrationHelper::FixTimes(const base::FilePath& child) {
  const base::FilePath file = to_base_path_.Append(child);

  struct timespec mtime;
  if (!platform_->GetExtendedFileAttribute(file, delegate_->GetMtimeXattrName(),
                                           reinterpret_cast<char*>(&mtime),
                                           sizeof(mtime))) {
    if (errno == ENODATA) {
      // If the xattr does not exist, it means it could not be set due to the
      // ENOSPC error. In this case we proceed without copying mtime and atime.
      return true;
    }
    RecordFileErrorWithCurrentErrno(kMigrationFailedAtGetAttribute, child,
                                    FailureLocationType::kDest);
    return false;
  }
  struct timespec atime;
  if (!platform_->GetExtendedFileAttribute(file, delegate_->GetAtimeXattrName(),
                                           reinterpret_cast<char*>(&atime),
                                           sizeof(atime))) {
    if (errno == ENODATA) {
      // Same as mtime, proceed without copying mtime and atime.
      return true;
    }
    RecordFileErrorWithCurrentErrno(kMigrationFailedAtGetAttribute, child,
                                    FailureLocationType::kDest);
    return false;
  }

  if (!platform_->SetFileTimes(file, atime, mtime, true /* follow_links */)) {
    PLOG(ERROR) << "Failed to set mtime on " << file.value();
    RecordFileErrorWithCurrentErrno(kMigrationFailedAtSetAttribute, child,
                                    FailureLocationType::kDest);
    return false;
  }
  return true;
}

bool MigrationHelper::RemoveTimeXattrsIfPresent(const base::FilePath& child) {
  const base::FilePath file = to_base_path_.Append(child);

  if (!platform_->RemoveExtendedFileAttribute(file,
                                              delegate_->GetMtimeXattrName())) {
    if (errno != ENODATA) {
      PLOG(ERROR) << "Failed to remove mtime extended attribute from "
                  << file.value();
      RecordFileErrorWithCurrentErrno(kMigrationFailedAtRemoveAttribute, child,
                                      FailureLocationType::kDest);
      return false;
    }
  }

  if (!platform_->RemoveExtendedFileAttribute(file,
                                              delegate_->GetAtimeXattrName())) {
    if (errno != ENODATA) {
      PLOG(ERROR) << "Failed to remove atime extended attribute from "
                  << file.value();
      RecordFileErrorWithCurrentErrno(kMigrationFailedAtRemoveAttribute, child,
                                      FailureLocationType::kDest);
      return false;
    }
  }
  return true;
}

bool MigrationHelper::CopyExtendedAttributes(const base::FilePath& child) {
  const base::FilePath from = from_base_path_.Append(child);
  const base::FilePath to = to_base_path_.Append(child);

  std::vector<std::string> xattr_names;
  if (!platform_->ListExtendedFileAttributes(from, &xattr_names)) {
    RecordFileErrorWithCurrentErrno(kMigrationFailedAtGetAttribute, child,
                                    FailureLocationType::kSource);
    return false;
  }

  for (const std::string& name_from : xattr_names) {
    if (name_from == delegate_->GetMtimeXattrName() ||
        name_from == delegate_->GetAtimeXattrName() ||
        name_from == kSourceURLXattrName ||
        name_from == kReferrerURLXattrName) {
      continue;
    }
    std::string value;
    if (!platform_->GetExtendedFileAttributeAsString(from, name_from, &value)) {
      RecordFileErrorWithCurrentErrno(kMigrationFailedAtGetAttribute, child,
                                      FailureLocationType::kSource);
      return false;
    }
    const std::string name_to = delegate_->ConvertXattrName(name_from);
    if (!platform_->SetExtendedFileAttribute(to, name_to, value.data(),
                                             value.length())) {
      bool nospace_error = errno == ENOSPC;
      RecordFileErrorWithCurrentErrno(kMigrationFailedAtSetAttribute, child,
                                      FailureLocationType::kDest);
      if (nospace_error) {
        ReportTotalXattrSize(to, name_to.length() + 1 + value.length());
      }
      return false;
    }
  }

  return true;
}

bool MigrationHelper::SetExtendedAttributeIfNotPresent(
    const base::FilePath& child,
    const std::string& xattr,
    const char* value,
    ssize_t size) {
  base::FilePath file = to_base_path_.Append(child);
  // If the attribute already exists we assume it was set during a previous
  // migration attempt and use the existing one instead of writing a new one.
  if (platform_->HasExtendedFileAttribute(file, xattr)) {
    return true;
  }
  if (errno != ENODATA) {
    PLOG(ERROR) << "Failed to get extended attribute " << xattr << " for "
                << file.value();
    RecordFileErrorWithCurrentErrno(kMigrationFailedAtGetAttribute, child,
                                    FailureLocationType::kDest);
    return false;
  }
  if (!platform_->SetExtendedFileAttribute(file, xattr, value, size)) {
    // If it's the ENOSPC error, proceed without copying mtime/atime.
    if (errno != ENOSPC) {
      RecordFileErrorWithCurrentErrno(kMigrationFailedAtSetAttribute, child,
                                      FailureLocationType::kDest);
      return false;
    }
    ReportTotalXattrSize(file, xattr.length() + 1 + size);
  }
  return true;
}

void MigrationHelper::RecordFileError(MigrationFailedOperationType operation,
                                      const base::FilePath& child,
                                      base::File::Error error,
                                      FailureLocationType location_type) {
  // Report UMA stats here for each single error.
  delegate_->ReportFailure(error, operation, child, location_type);

  {  // Record the data for the final end-status report.
    base::AutoLock lock(failure_info_lock_);
    failed_operation_type_ = operation;
    failed_error_type_ = error;

    if (error == base::File::FILE_ERROR_NO_SPACE) {
      no_space_failure_free_space_bytes_ =
          platform_->AmountOfFreeDiskSpace(to_base_path_);
    }
  }
}

void MigrationHelper::RecordFileErrorWithCurrentErrno(
    MigrationFailedOperationType operation,
    const base::FilePath& child,
    FailureLocationType location_type) {
  RecordFileError(operation, child, base::File::OSErrorToFileError(errno),
                  location_type);
}

bool MigrationHelper::ProcessJob(const Job& job) {
  if (S_ISLNK(job.stat.st_mode)) {
    // Symlink
    if (!MigrateLink(job.child, job.stat))
      return false;
    IncrementMigratedBytes(job.stat.st_size);
  } else if (S_ISREG(job.stat.st_mode)) {
    // File
    if (!MigrateFile(job.child, job.stat))
      return false;
  } else {
    LOG(ERROR) << "Unknown file type: " << job.child.value();
  }
  if (!platform_->DeleteFile(from_base_path_.Append(job.child))) {
    LOG(ERROR) << "Failed to delete file " << job.child.value();
    RecordFileErrorWithCurrentErrno(kMigrationFailedAtDelete, job.child,
                                    FailureLocationType::kSource);
    return false;
  }
  // The file/symlink was removed.
  // Decrement the child count of the parent directory.
  return DecrementChildCountAndDeleteIfNecessary(job.child.DirName());
}

void MigrationHelper::IncrementChildCount(const base::FilePath& child) {
  base::AutoLock lock(child_counts_lock_);
  ++child_counts_[child];
}

bool MigrationHelper::DecrementChildCountAndDeleteIfNecessary(
    const base::FilePath& child) {
  {
    base::AutoLock lock(child_counts_lock_);
    auto it = child_counts_.find(child);
    --(it->second);
    if (it->second > 0)  // This directory is not empty yet.
      return true;
    child_counts_.erase(it);
  }
  // The last child was removed. Finish migrating this directory.
  const base::FilePath from_dir = from_base_path_.Append(child);
  const base::FilePath to_dir = to_base_path_.Append(child);
  if (!FixTimes(child)) {
    LOG(ERROR) << "Failed to fix times " << child.value();
    return false;
  }
  if (!platform_->SyncDirectory(to_dir)) {
    LOG(ERROR) << "Failed to sync " << child.value();
    RecordFileErrorWithCurrentErrno(kMigrationFailedAtSync, child,
                                    FailureLocationType::kDest);
    return false;
  }
  if (!RemoveTimeXattrsIfPresent(child))
    return false;

  // Don't delete the top directory.
  if (child.value() == base::FilePath::kCurrentDirectory)
    return true;

  if (!platform_->DeleteFile(from_dir)) {
    PLOG(ERROR) << "Failed to delete " << child.value();
    RecordFileErrorWithCurrentErrno(kMigrationFailedAtDelete, child,
                                    FailureLocationType::kSource);
    return false;
  }
  // Decrement the parent directory's child count.
  return DecrementChildCountAndDeleteIfNecessary(child.DirName());
}

void MigrationHelper::ReportTotalXattrSize(const base::FilePath& path,
                                           int failed_xattr_size) {
  std::vector<std::string> xattr_names;
  if (!platform_->ListExtendedFileAttributes(path, &xattr_names)) {
    LOG(ERROR) << "Error listing extended attributes for " << path.value();
    return;
  }
  int xattr_size = failed_xattr_size;
  for (const std::string& name : xattr_names) {
    xattr_size += name.length() + 1;  // Add one byte for null termination.
    std::string value;
    if (!platform_->GetExtendedFileAttributeAsString(path, name, &value)) {
      LOG(ERROR) << "Error getting value for extended attribute " << name
                 << " on " << path.value();
      return;
    }
    xattr_size += value.length();
  }
  delegate_->ReportFailedNoSpaceXattrSizeInBytes(xattr_size);
}

}  // namespace cryptohome::data_migrator
