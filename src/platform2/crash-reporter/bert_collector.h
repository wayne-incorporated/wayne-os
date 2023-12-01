// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// The BERT collector collects error reports from the Boot Error Record Table
// (as defined in the ACPI spec).
// These are exposed in /sys/firmware/acpi/tables (see path definitions in
// bert_collector.cc for details), and are useful for debugging firmware
// crashes.

#ifndef CRASH_REPORTER_BERT_COLLECTOR_H_
#define CRASH_REPORTER_BERT_COLLECTOR_H_

#include <base/files/file_path.h>

#include "crash-reporter/crash_collector.h"

#define ACPI_NAME_SIZE 4
#define ACPI_SIG_BERT "BERT"
#define ACPI_BERT_REGION_STRUCT_SIZE (5 * sizeof(uint32_t))

// BERT (Boot Error Record Table) as defined in ACPI spec, APEI chapter at
// http://www.uefi.org/sites/default/files/resources/ACPI%206_2_A_Sept29.pdf.
struct acpi_table_bert {
  char signature[ACPI_NAME_SIZE];
  uint32_t length;
  uint8_t revision;
  uint8_t checksum;
  char oem_id[6];
  char oem_table_id[8];
  uint32_t oem_revision;
  char asl_compiler_id[ACPI_NAME_SIZE];
  uint32_t asl_compiler_revision;
  uint32_t region_length;
  uint64_t address;
};

static_assert(sizeof(acpi_table_bert) == 48,
              "acpi_table_bert size is not correct");

// Firmware Error Bert dump collector.
class BERTCollector : public CrashCollector {
 public:
  BERTCollector();
  BERTCollector(const BERTCollector&) = delete;
  BERTCollector& operator=(const BERTCollector&) = delete;

  ~BERTCollector() override;

  // Collect Bert dump.
  bool Collect(bool use_saved_lsb);

 private:
  friend class BERTCollectorTest;

  base::FilePath acpitable_path_;
};

#endif  // CRASH_REPORTER_BERT_COLLECTOR_H_
