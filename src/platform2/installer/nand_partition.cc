// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "installer/nand_partition.h"

#include <fcntl.h>
#include <linux/blkpg.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <base/files/scoped_file.h>
#include <base/logging.h>

namespace brillo {

namespace installer {

bool RemoveNandPartition(const base::FilePath& dev, int partno) {
  // We use /dev/mtd0 as the "master" device.
  if (partno <= 0) {
    LOG(INFO) << "Partition number " << partno << " is not greater than 0";
    return false;
  }

  base::ScopedFD fd(open(dev.value().c_str(), O_RDWR | O_CLOEXEC));
  if (!fd.is_valid()) {
    PLOG(ERROR) << "Cannot open " << dev;
    return false;
  }

  blkpg_partition part;
  memset(&part, 0, sizeof(part));
  part.pno = partno;

  blkpg_ioctl_arg arg;
  memset(&arg, 0, sizeof(arg));
  arg.op = BLKPG_DEL_PARTITION;
  arg.datalen = sizeof(part);
  arg.data = &part;

  int r = ioctl(fd.get(), BLKPG, &arg);
  if (r) {
    PLOG(ERROR) << "Cannot remove partition " << partno << " from " << dev;
  }
  return r == 0;
}

bool AddNandPartition(const base::FilePath& dev,
                      int partno,
                      uint64_t offset,
                      uint64_t length) {
  // We use /dev/mtd0 as the "master" device.
  if (partno <= 0) {
    LOG(INFO) << "Partition number " << partno << " is not greater than 0";
    return false;
  }

  base::ScopedFD fd(open(dev.value().c_str(), O_RDWR | O_CLOEXEC));
  if (!fd.is_valid()) {
    PLOG(ERROR) << "Cannot open " << dev;
    return false;
  }

  blkpg_partition part;
  memset(&part, 0, sizeof(part));
  part.pno = partno;
  part.start = offset;
  part.length = length;
  snprintf(part.devname, sizeof(part.devname), "mtd%d", partno);

  blkpg_ioctl_arg arg;
  memset(&arg, 0, sizeof(arg));
  arg.op = BLKPG_ADD_PARTITION;
  arg.datalen = sizeof(part);
  arg.data = &part;

  int r = ioctl(fd.get(), BLKPG, &arg);
  if (r) {
    PLOG(ERROR) << "Cannot add another partition to " << dev;
  }
  return r == 0;
}

}  // namespace installer

}  // namespace brillo
