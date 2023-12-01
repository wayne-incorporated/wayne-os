// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>
#include <stdio.h>
#include <string>
#include <vector>

#include <cstddef>

#include <base/containers/span.h>
#include <base/strings/strcat.h>
#include <base/strings/stringprintf.h>

#include "libec/ec_command.h"
#include "libec/ec_panicinfo.h"

namespace ec {

namespace {
static std::string PrintPanicReg(int regnum, const uint32_t* regs, int index) {
  static const char* const regname[] = {
      "r0 ", "r1 ", "r2 ", "r3 ", "r4 ", "r5 ", "r6 ", "r7 ",
      "r8 ", "r9 ", "r10", "r11", "r12", "sp ", "lr ", "pc "};

  std::string ret;

  ret = base::StringPrintf("%s:", regname[regnum]);
  if (regs)
    base::StrAppend(&ret, {base::StringPrintf("%08x", regs[index])});
  else
    base::StrAppend(&ret, {base::StringPrintf("        ")});
  base::StrAppend(&ret, {(regnum & 3) == 3 ? "\n" : " "});
  return ret;
}

static std::string PanicShowExtraCm(const struct panic_data* pdata) {
  enum {
    CPU_NVIC_CFSR_BFARVALID = BIT(15),
    CPU_NVIC_CFSR_MFARVALID = BIT(7),
  };

  std::string ret;

  ret = base::StringPrintf("\n");
  if (pdata->cm.cfsr & CPU_NVIC_CFSR_BFARVALID)
    base::StrAppend(&ret, {base::StringPrintf("bfar=%08x, ", pdata->cm.bfar)});
  if (pdata->cm.cfsr & CPU_NVIC_CFSR_MFARVALID)
    base::StrAppend(&ret, {base::StringPrintf("mfar=%08x, ", pdata->cm.mfar)});
  base::StrAppend(
      &ret, {base::StringPrintf("cfsr=%08x, ", pdata->cm.cfsr),
             base::StringPrintf("shcsr=%08x, ", pdata->cm.shcsr),
             base::StringPrintf("hfsr=%08x, ", pdata->cm.hfsr),
             base::StringPrintf("dfsr=%08x, ", pdata->cm.dfsr),
             base::StringPrintf("ipsr=%08x",
                                pdata->cm.regs[CORTEX_PANIC_REGISTER_IPSR]),
             base::StringPrintf("\n")});
  return ret;
}

static std::string ParsePanicInfoCm(const struct panic_data* pdata) {
  const uint32_t* lregs = pdata->cm.regs;
  const uint32_t* sregs = nullptr;
  enum { ORIG_UNKNOWN = 0, ORIG_PROCESS, ORIG_HANDLER } origin = ORIG_UNKNOWN;
  int i;
  const char* panic_origins[3] = {"", "PROCESS", "HANDLER"};

  std::string ret;

  ret = base::StringPrintf(
      "Saved panic data:%s\n",
      (pdata->flags & PANIC_DATA_FLAG_OLD_HOSTCMD ? "" : " (NEW)"));

  if (pdata->struct_version == 2)
    origin = ((lregs[11] & 0xf) == 1 || (lregs[11] & 0xf) == 9) ? ORIG_HANDLER
                                                                : ORIG_PROCESS;

  /*
   * In pdata struct, 'regs', which is allocated before 'frame', has
   * one less elements in version 1. Therefore, if the data is from
   * version 1, shift 'sregs' by one element to align with 'frame' in
   * version 1.
   */
  if (pdata->flags & PANIC_DATA_FLAG_FRAME_VALID)
    sregs = pdata->cm.frame - (pdata->struct_version == 1 ? 1 : 0);

  base::StrAppend(&ret, {base::StringPrintf(
                            "=== %s EXCEPTION: %02x ====== xPSR: %08x ===\n",
                            panic_origins[origin], lregs[1] & 0xff,
                            sregs ? sregs[7] : -1)});
  for (i = 0; i < 4; ++i)
    base::StrAppend(&ret, {PrintPanicReg(i, sregs, i)});
  for (i = 4; i < 10; ++i)
    base::StrAppend(&ret, {PrintPanicReg(i, lregs, i - 1)});
  base::StrAppend(&ret,
                  {PrintPanicReg(10, lregs, 9), PrintPanicReg(11, lregs, 10),
                   PrintPanicReg(12, sregs, 4),
                   PrintPanicReg(13, lregs, origin == ORIG_HANDLER ? 2 : 0),
                   PrintPanicReg(14, sregs, 5), PrintPanicReg(15, sregs, 6),
                   PanicShowExtraCm(pdata)});
  return ret;
}

static std::string ParsePanicInfoNds32(const struct panic_data* pdata) {
  const uint32_t* regs = pdata->nds_n8.regs;
  uint32_t itype = pdata->nds_n8.itype;
  uint32_t ipc = pdata->nds_n8.ipc;
  uint32_t ipsw = pdata->nds_n8.ipsw;

  std::string ret;

  ret = base::StringPrintf(
      "Saved panic data:%s\n",
      (pdata->flags & PANIC_DATA_FLAG_OLD_HOSTCMD ? "" : " (NEW)"));

  base::StrAppend(
      &ret,
      {base::StringPrintf("=== EXCEP: ITYPE=%x ===\n", itype),
       base::StringPrintf("R0  %08x R1  %08x R2  %08x R3  %08x\n", regs[0],
                          regs[1], regs[2], regs[3]),
       base::StringPrintf("R4  %08x R5  %08x R6  %08x R7  %08x\n", regs[4],
                          regs[5], regs[6], regs[7]),
       base::StringPrintf("R8  %08x R9  %08x R10 %08x R15 %08x\n", regs[8],
                          regs[9], regs[10], regs[11]),
       base::StringPrintf("FP  %08x GP  %08x LP  %08x SP  %08x\n", regs[12],
                          regs[13], regs[14], regs[15]),
       base::StringPrintf("IPC %08x IPSW   %05x\n", ipc, ipsw),
       base::StringPrintf("SWID of ITYPE: %x\n", ((itype >> 16) & 0x7fff))});

  return ret;
}

static std::string ParsePanicInfoRv32i(const struct panic_data* pdata) {
  const uint32_t* regs;
  uint32_t mcause, mepc;

  regs = reinterpret_cast<const uint32_t*>(pdata->riscv.regs);
  mcause = pdata->riscv.mcause;
  mepc = pdata->riscv.mepc;

  std::string ret;

  ret = base::StringPrintf("=== EXCEPTION: MCAUSE=%x ===\n", mcause);
  base::StrAppend(&ret,
                  {base::StringPrintf("S11 %08x S10 %08x  S9 %08x  S8   %08x\n",
                                      regs[0], regs[1], regs[2], regs[3]),
                   base::StringPrintf("S7  %08x S6  %08x  S5 %08x  S4   %08x\n",
                                      regs[4], regs[5], regs[6], regs[7]),
                   base::StringPrintf("S3  %08x S2  %08x  S1 %08x  S0   %08x\n",
                                      regs[8], regs[9], regs[10], regs[11]),
                   base::StringPrintf("T6  %08x T5  %08x  T4 %08x  T3   %08x\n",
                                      regs[12], regs[13], regs[14], regs[15]),
                   base::StringPrintf("T2  %08x T1  %08x  T0 %08x  A7   %08x\n",
                                      regs[16], regs[17], regs[18], regs[19]),
                   base::StringPrintf("A6  %08x A5  %08x  A4 %08x  A3   %08x\n",
                                      regs[20], regs[21], regs[22], regs[23]),
                   base::StringPrintf("A2  %08x A1  %08x  A0 %08x  TP   %08x\n",
                                      regs[24], regs[25], regs[26], regs[27]),
                   base::StringPrintf("GP  %08x RA  %08x  SP %08x  MEPC %08x\n",
                                      regs[28], regs[29], regs[30], mepc)});

  return ret;
}

}  // namespace

base::expected<std::vector<uint8_t>, std::string> GetPanicInput(
    size_t max_size) {
  size_t size = 0;
  size_t read;
  std::vector<uint8_t> data(max_size);

  while (1) {
    read = fread(&data[size], 1, max_size - size, stdin);
    if (read < 0) {
      return base::unexpected("Cannot read panicinfo from stdin.");
    }
    if (read == 0)
      break;

    size += read;
    if (size >= max_size) {
      return base::unexpected("Too much panicinfo data in stdin.");
    }
  }

  data.resize(size);

  return data;
}

base::expected<std::string, std::string> ParsePanicInfo(
    base::span<const uint8_t> data) {
  size_t size = data.size();
  /* Size of the panic information "header". */
  const size_t header_size = 4;
  /* Size of the panic information "trailer" (struct_size and magic). */
  const size_t trailer_size =
      sizeof(struct panic_data) - offsetof(struct panic_data, struct_size);

  struct panic_data pdata = {0};
  size_t copy_size;
  std::string warning;

  if (size < (header_size + trailer_size)) {
    return base::unexpected(
        base::StringPrintf("ERROR: Panic data too short (%zd).\n", size));
  }

  if (size > sizeof(pdata)) {
    warning = base::StringPrintf("WARNING: Panic data too large (%zd > %zd)\n",
                                 size, sizeof(pdata));
    copy_size = sizeof(pdata);
  } else {
    copy_size = size;
  }
  /* Copy the data into pdata, as the struct size may have changed. */
  memcpy(&pdata, data.data(), copy_size);
  /* Then copy the trailer in position. */
  memcpy(reinterpret_cast<uint8_t*>(&pdata) +
             (sizeof(struct panic_data) - trailer_size),
         data.last(trailer_size).data(), trailer_size);

  /*
   * We only understand panic data with version in [1, 2]. Error on invalid
   * versions.
   */
  if (pdata.struct_version > 2 || pdata.struct_version == 0)
    return base::unexpected(
        warning +
        base::StringPrintf("ERROR: Unknown panic data version (%d).\n",
                           pdata.struct_version));

  if (pdata.reserved != 0)
    return base::unexpected(
        warning + base::StringPrintf("ERROR: Panic reserve is not 0 (%d).\n",
                                     pdata.reserved));

  /* Validate flag is within BIT(0) to BIT(6) inclusive. */
  if (pdata.flags >> 7)
    return base::unexpected(
        warning +
        base::StringPrintf("ERROR: Incorrect flag (%d).\n", pdata.flags));

  /*
   * Validate magic number. This is unlikely to happen but we should investigate
   * the mismatching in crash reports.
   */
  if (pdata.magic != PANIC_DATA_MAGIC)
    base::StrAppend(
        &warning, {base::StringPrintf("WARNING: Incorrect panic magic (%d).\n",
                                      pdata.magic)});

  /*
   * The size mismatching is unlikely to happen but we should investiage this
   * case in crash reports.
   */
  if (pdata.struct_size != size)
    base::StrAppend(
        &warning, {base::StringPrintf(
                      "WARNING: Panic struct size inconsistent (%u vs %zd).\n",
                      pdata.struct_size, size)});

  std::string ret;
  switch (pdata.arch) {
    case PANIC_ARCH_CORTEX_M:
      return base::ok(warning + ParsePanicInfoCm(&pdata));
    case PANIC_ARCH_NDS32_N8:
      return base::ok(warning + ParsePanicInfoNds32(&pdata));
    case PANIC_ARCH_RISCV_RV32I:
      return base::ok(warning + ParsePanicInfoRv32i(&pdata));
    default:
      return base::unexpected(
          warning + base::StringPrintf("ERROR: Unknown architecture (%d).\n",
                                       pdata.arch));
  }
}

}  // namespace ec
