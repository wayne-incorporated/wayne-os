// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "lorgnette/enums.h"

#include <vector>

#include <base/check.h>
#include <base/logging.h>
#include <base/strings/string_split.h>
#include <base/strings/stringprintf.h>
#include <re2/re2.h>

namespace {

// Index of the ScannerName within the ':' separated fields of an Airscan or
// IPP-USB device specification. e.g.
// "airscan:escl:ScannerName:http://127.0.0.2/eSCL"
constexpr size_t kScannerNameIndex = 2;

// Use const char* so that ManufacturerBackend is trivially-destructible.
struct ManufacturerBackend {
  const char* name_regex;
  DocumentScanSaneBackend airscan;
  DocumentScanSaneBackend ippusb;
};

constexpr ManufacturerBackend manufacturers[] = {
    {"brother", kAirscanBrother, kIppUsbBrother},
    {"canon", kAirscanCanon, kIppUsbCanon},
    {"epson", kAirscanEpson, kIppUsbEpson},
    {"kodak", kAirscanKodak, kIppUsbKodak},
    {"konica[- ]?minolta", kAirscanKonicaMinolta, kIppUsbKonicaMinolta},
    {"kyocera", kAirscanKyocera, kIppUsbKyocera},
    {"lexmark", kAirscanLexmark, kIppUsbLexmark},
    {"ricoh", kAirscanRicoh, kIppUsbRicoh},
    {"samsung", kAirscanSamsung, kIppUsbSamsung},
    {"xerox", kAirscanXerox, kIppUsbXerox},
    // Keep the HP cases last. It is possible that some other manufacturer
    // would use the abbreviation HP within their model name, so we only want
    // to match this if no other manufacturer matched.
    {"hp", kAirscanHp, kIppUsbHp},
    {"hewlett[- ]?packard", kAirscanHp, kIppUsbHp},
    {"DavieV", kTest, kTest},
};

DocumentScanSaneBackend GuessManufacturer(DocumentScanSaneBackend base_type,
                                          const std::string& scanner_name) {
  DCHECK(base_type == kAirscanOther || base_type == kIppUsbOther);

  for (const ManufacturerBackend& manufacturer : manufacturers) {
    // Use a case-insensitive match, and require matching at a word boundary
    // e.g if we're searching for "HP", we'll match "hp scanner" and "My HP
    // scanner" but not "RICOHPrinter".
    std::string regex =
        base::StringPrintf("(?i)\\b%s\\b", manufacturer.name_regex);
    if (RE2::PartialMatch(scanner_name, regex)) {
      if (base_type == kAirscanOther)
        return manufacturer.airscan;
      else if (base_type == kIppUsbOther)
        return manufacturer.ippusb;
    }
  }

  return base_type;
}

}  // namespace

DocumentScanSaneBackend BackendFromDeviceName(const std::string& device) {
  std::vector<std::string> components = base::SplitString(
      device, ":", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);

  const std::string& name = components[0];
  if (name == "abaton")
    return kAbaton;
  if (name == "agfafocus")
    return kAgfafocus;
  if (name == "airscan") {
    if (kScannerNameIndex < components.size())
      return GuessManufacturer(kAirscanOther, components[kScannerNameIndex]);
    else
      return kAirscanOther;
  }
  if (name == "apple")
    return kApple;
  if (name == "artec")
    return kArtec;
  if (name == "artec_eplus48u")
    return kArtecEplus48U;
  if (name == "as6e")
    return kAs6E;
  if (name == "avision")
    return kAvision;
  if (name == "bh")
    return kBh;
  if (name == "canon")
    return kCanon;
  if (name == "canon630u")
    return kCanon630U;
  if (name == "canon_dr")
    return kCanonDr;
  if (name == "canon_lide70")
    return kCanonLide70;
  if (name == "cardscan")
    return kCardscan;
  if (name == "coolscan")
    return kCoolscan;
  if (name == "coolscan2")
    return kCoolscan2;
  if (name == "coolscan3")
    return kCoolscan3;
  if (name == "dc210")
    return kDc210;
  if (name == "dc240")
    return kDc240;
  if (name == "dc25")
    return kDc25;
  if (name == "dell1600n_net")
    return kDell1600NNet;
  if (name == "dmc")
    return kDmc;
  if (name == "epjitsu")
    return kEpjitsu;
  if (name == "epson")
    return kEpson;
  if (name == "epson2")
    return kEpson2;
  if (name == "epsonds")
    return kEpsonDs;
  if (name == "escl")
    return kEscl;
  if (name == "fujitsu")
    return kFujitsu;
  if (name == "genesys")
    return kGenesys;
  if (name == "gt68xx")
    return kGt68Xx;
  if (name == "hp")
    return kHp;
  if (name == "hp3500")
    return kHp3500;
  if (name == "hp3900")
    return kHp3900;
  if (name == "hp4200")
    return kHp4200;
  if (name == "hp5400")
    return kHp5400;
  if (name == "hp5590")
    return kHp5590;
  if (name == "hpljm1005")
    return kHpljm1005;
  if (name == "hs2p")
    return kHs2P;
  if (name == "ibm")
    return kIbm;
  if (name == "ippusb") {
    if (kScannerNameIndex < components.size())
      return GuessManufacturer(kIppUsbOther, components[kScannerNameIndex]);
    else
      return kIppUsbOther;
  }
  if (name == "kodak")
    return kKodak;
  if (name == "kodakaio")
    return kKodakaio;
  if (name == "kvs1025")
    return kKvs1025;
  if (name == "kvs20xx")
    return kKvs20Xx;
  if (name == "kvs40xx")
    return kKvs40Xx;
  if (name == "leo")
    return kLeo;
  if (name == "lexmark")
    return kLexmark;
  if (name == "ma1509")
    return kMa1509;
  if (name == "magicolor")
    return kMagicolor;
  if (name == "matsushita")
    return kMatsushita;
  if (name == "microtek")
    return kMicrotek;
  if (name == "microtek2")
    return kMicrotek2;
  if (name == "mustek")
    return kMustek;
  if (name == "mustek_usb")
    return kMustekUsb;
  if (name == "mustek_usb2")
    return kMustekUsb2;
  if (name == "nec")
    return kNec;
  if (name == "net")
    return kNet;
  if (name == "niash")
    return kNiash;
  if (name == "p5")
    return kP5;
  if (name == "pie")
    return kPie;
  if (name == "pixma")
    return kPixma;
  if (name == "plustek")
    return kPlustek;
  if (name == "plustek_pp")
    return kPlustekPp;
  if (name == "qcam")
    return kQcam;
  if (name == "ricoh")
    return kRicoh;
  if (name == "ricoh2")
    return kRicoh2;
  if (name == "rts8891")
    return kRts8891;
  if (name == "s9036")
    return kS9036;
  if (name == "sceptre")
    return kSceptre;
  if (name == "sharp")
    return kSharp;
  if (name == "sm3600")
    return kSm3600;
  if (name == "sm3840")
    return kSm3840;
  if (name == "snapscan")
    return kSnapscan;
  if (name == "sp15c")
    return kSp15C;
  if (name == "st400")
    return kSt400;
  if (name == "stv680")
    return kStv680;
  if (name == "tamarack")
    return kTamarack;
  if (name == "teco1")
    return kTeco1;
  if (name == "teco2")
    return kTeco2;
  if (name == "teco3")
    return kTeco3;
  if (name == "test")
    return kTest;
  if (name == "u12")
    return kU12;
  if (name == "umax")
    return kUmax;
  if (name == "umax1220u")
    return kUmax1220U;
  if (name == "umax_pp")
    return kUmaxPp;
  if (name == "xerox_mfp")
    return kXeroxMfp;
  LOG(WARNING) << "Unknown sane backend " << name;
  return kOtherBackend;
}
