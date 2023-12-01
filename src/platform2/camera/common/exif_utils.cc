/*
 * Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "cros-camera/exif_utils.h"

#include <cstdlib>
#include <ctime>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/strings/string_split.h>

#include "cros-camera/common.h"

namespace std {

template <>
struct default_delete<ExifEntry> {
  inline void operator()(ExifEntry* entry) const { exif_entry_unref(entry); }
};

}  // namespace std

namespace cros {

const base::FilePath kCameraPropertyPath("/var/cache/camera/camera.prop");

#define SET_SHORT(ifd, tag, value)                \
  do {                                            \
    if (SetShort(ifd, tag, value, #tag) == false) \
      return false;                               \
  } while (0);

#define SET_LONG(ifd, tag, value)                \
  do {                                           \
    if (SetLong(ifd, tag, value, #tag) == false) \
      return false;                              \
  } while (0);

#define SET_RATIONAL(ifd, tag, numerator, denominator)                \
  do {                                                                \
    if (SetRational(ifd, tag, numerator, denominator, #tag) == false) \
      return false;                                                   \
  } while (0);

#define SET_SRATIONAL(ifd, tag, numerator, denominator)                \
  do {                                                                 \
    if (SetSRational(ifd, tag, numerator, denominator, #tag) == false) \
      return false;                                                    \
  } while (0);

#define SET_STRING(ifd, tag, format, buffer)                \
  do {                                                      \
    if (SetString(ifd, tag, format, buffer, #tag) == false) \
      return false;                                         \
  } while (0);

// This comes from the Exif Version 2.2 standard table 6.
const char gExifAsciiPrefix[] = {0x41, 0x53, 0x43, 0x49, 0x49, 0x0, 0x0, 0x0};

static void SetLatitudeOrLongitudeData(unsigned char* data, double num) {
  // Take the integer part of |num|.
  ExifLong degrees = static_cast<ExifLong>(num);
  ExifLong minutes = static_cast<ExifLong>(60 * (num - degrees));
  ExifLong microseconds =
      static_cast<ExifLong>(3600000000u * (num - degrees - minutes / 60.0));
  exif_set_rational(data, EXIF_BYTE_ORDER_INTEL, {degrees, 1});
  exif_set_rational(data + sizeof(ExifRational), EXIF_BYTE_ORDER_INTEL,
                    {minutes, 1});
  exif_set_rational(data + 2 * sizeof(ExifRational), EXIF_BYTE_ORDER_INTEL,
                    {microseconds, 1000000});
}

ExifUtils::ExifUtils()
    : exif_data_(nullptr), app1_buffer_(nullptr), app1_length_(0) {}

ExifUtils::~ExifUtils() {
  Reset();
}

bool ExifUtils::Initialize() {
  Reset();
  exif_data_ = exif_data_new();
  if (exif_data_ == nullptr) {
    LOGF(ERROR) << "Cannot allocate ExifData";
    return false;
  }
  // Set the image options.
  exif_data_set_option(exif_data_, EXIF_DATA_OPTION_FOLLOW_SPECIFICATION);
  exif_data_set_data_type(exif_data_, EXIF_DATA_TYPE_COMPRESSED);
  exif_data_set_byte_order(exif_data_, EXIF_BYTE_ORDER_INTEL);

  // Set exif version to 2.2.
  if (!SetExifVersion("0220")) {
    return false;
  }

  if (!ReadProperty()) {
    LOGF(WARNING) << "Cannot setup manufacturer and model";
  }
  return true;
}

bool ExifUtils::InitializeWithData(base::span<uint8_t> blob) {
  Reset();
  exif_data_ = exif_data_new_from_data(blob.data(), blob.size());
  if (exif_data_ == nullptr) {
    LOGF(ERROR) << "Cannot allocate ExifData from blob buffer";
    return false;
  }

  if (!ReadProperty()) {
    LOGF(WARNING) << "Cannot setup manufacturer and model";
  }
  return true;
}

bool ExifUtils::SetAperture(uint32_t numerator, uint32_t denominator) {
  SET_RATIONAL(EXIF_IFD_EXIF, EXIF_TAG_APERTURE_VALUE, numerator, denominator);
  return true;
}

bool ExifUtils::SetBrightness(int32_t numerator, int32_t denominator) {
  SET_SRATIONAL(EXIF_IFD_EXIF, EXIF_TAG_BRIGHTNESS_VALUE, numerator,
                denominator);
  return true;
}

bool ExifUtils::SetColorSpace(uint16_t color_space) {
  SET_SHORT(EXIF_IFD_EXIF, EXIF_TAG_COLOR_SPACE, color_space);
  return true;
}

bool ExifUtils::SetComponentsConfiguration(
    const std::string& components_configuration) {
  SET_STRING(EXIF_IFD_EXIF, EXIF_TAG_COMPONENTS_CONFIGURATION,
             EXIF_FORMAT_UNDEFINED, components_configuration);
  return true;
}

bool ExifUtils::SetCompression(uint16_t compression) {
  SET_SHORT(EXIF_IFD_0, EXIF_TAG_COMPRESSION, compression);
  return true;
}

bool ExifUtils::SetContrast(uint16_t contrast) {
  SET_SHORT(EXIF_IFD_EXIF, EXIF_TAG_CONTRAST, contrast);
  return true;
}

bool ExifUtils::SetDateTime(const struct tm& t) {
  // The length is 20 bytes including NULL for termination in Exif standard.
  char str[20];
  int result = snprintf(str, sizeof(str), "%04i:%02i:%02i %02i:%02i:%02i",
                        t.tm_year + 1900, t.tm_mon + 1, t.tm_mday, t.tm_hour,
                        t.tm_min, t.tm_sec);
  if (result != sizeof(str) - 1) {
    LOGF(WARNING) << "Input time is invalid";
    return false;
  }
  std::string buffer(str);
  SET_STRING(EXIF_IFD_0, EXIF_TAG_DATE_TIME, EXIF_FORMAT_ASCII, buffer);
  SET_STRING(EXIF_IFD_EXIF, EXIF_TAG_DATE_TIME_ORIGINAL, EXIF_FORMAT_ASCII,
             buffer);
  SET_STRING(EXIF_IFD_EXIF, EXIF_TAG_DATE_TIME_DIGITIZED, EXIF_FORMAT_ASCII,
             buffer);
  return true;
}

bool ExifUtils::SetDescription(const std::string& description) {
  SET_STRING(EXIF_IFD_0, EXIF_TAG_IMAGE_DESCRIPTION, EXIF_FORMAT_ASCII,
             description);
  return true;
}

bool ExifUtils::SetDigitalZoomRatio(uint32_t numerator, uint32_t denominator) {
  SET_RATIONAL(EXIF_IFD_EXIF, EXIF_TAG_DIGITAL_ZOOM_RATIO, numerator,
               denominator);
  return true;
}

bool ExifUtils::SetExposureBias(int32_t numerator, int32_t denominator) {
  SET_SRATIONAL(EXIF_IFD_EXIF, EXIF_TAG_EXPOSURE_BIAS_VALUE, numerator,
                denominator);
  return true;
}

bool ExifUtils::SetExposureMode(uint16_t exposure_mode) {
  SET_SHORT(EXIF_IFD_EXIF, EXIF_TAG_EXPOSURE_MODE, exposure_mode);
  return true;
}

bool ExifUtils::SetExposureProgram(uint16_t exposure_program) {
  SET_SHORT(EXIF_IFD_EXIF, EXIF_TAG_EXPOSURE_PROGRAM, exposure_program);
  return true;
}

bool ExifUtils::SetExposureTime(uint32_t numerator, uint32_t denominator) {
  SET_RATIONAL(EXIF_IFD_EXIF, EXIF_TAG_EXPOSURE_TIME, numerator, denominator);
  return true;
}

bool ExifUtils::SetFlash(uint16_t flash) {
  SET_SHORT(EXIF_IFD_EXIF, EXIF_TAG_FLASH, flash);
  return true;
}

bool ExifUtils::SetFNumber(uint32_t numerator, uint32_t denominator) {
  SET_RATIONAL(EXIF_IFD_EXIF, EXIF_TAG_FNUMBER, numerator, denominator);
  return true;
}

bool ExifUtils::SetFocalLength(uint32_t numerator, uint32_t denominator) {
  SET_RATIONAL(EXIF_IFD_EXIF, EXIF_TAG_FOCAL_LENGTH, numerator, denominator);
  return true;
}

bool ExifUtils::SetGainControl(uint16_t gain_control) {
  SET_SHORT(EXIF_IFD_EXIF, EXIF_TAG_GAIN_CONTROL, gain_control);
  return true;
}

bool ExifUtils::SetGpsAltitude(double altitude) {
  ExifTag refTag = static_cast<ExifTag>(EXIF_TAG_GPS_ALTITUDE_REF);
  std::unique_ptr<ExifEntry> refEntry =
      AddVariableLengthEntry(EXIF_IFD_GPS, refTag, EXIF_FORMAT_BYTE, 1, 1);
  if (!refEntry) {
    LOGF(ERROR) << "Adding GPSAltitudeRef exif entry failed";
    return false;
  }
  if (altitude >= 0) {
    *refEntry->data = 0;
  } else {
    *refEntry->data = 1;
    altitude *= -1;
  }

  ExifTag tag = static_cast<ExifTag>(EXIF_TAG_GPS_ALTITUDE);
  std::unique_ptr<ExifEntry> entry = AddVariableLengthEntry(
      EXIF_IFD_GPS, tag, EXIF_FORMAT_RATIONAL, 1, sizeof(ExifRational));
  if (!entry) {
    exif_content_remove_entry(exif_data_->ifd[EXIF_IFD_GPS], refEntry.get());
    LOGF(ERROR) << "Adding GPSAltitude exif entry failed";
    return false;
  }
  exif_set_rational(entry->data, EXIF_BYTE_ORDER_INTEL,
                    {static_cast<ExifLong>(altitude * 1000), 1000});

  return true;
}

bool ExifUtils::SetGpsLatitude(double latitude) {
  const ExifTag refTag = static_cast<ExifTag>(EXIF_TAG_GPS_LATITUDE_REF);
  std::unique_ptr<ExifEntry> refEntry =
      AddVariableLengthEntry(EXIF_IFD_GPS, refTag, EXIF_FORMAT_ASCII, 2, 2);
  if (!refEntry) {
    LOGF(ERROR) << "Adding GPSLatitudeRef exif entry failed";
    return false;
  }
  if (latitude >= 0) {
    memcpy(refEntry->data, "N", sizeof("N"));
  } else {
    memcpy(refEntry->data, "S", sizeof("S"));
    latitude *= -1;
  }

  const ExifTag tag = static_cast<ExifTag>(EXIF_TAG_GPS_LATITUDE);
  std::unique_ptr<ExifEntry> entry = AddVariableLengthEntry(
      EXIF_IFD_GPS, tag, EXIF_FORMAT_RATIONAL, 3, 3 * sizeof(ExifRational));
  if (!entry) {
    exif_content_remove_entry(exif_data_->ifd[EXIF_IFD_GPS], refEntry.get());
    LOGF(ERROR) << "Adding GPSLatitude exif entry failed";
    return false;
  }
  SetLatitudeOrLongitudeData(entry->data, latitude);

  return true;
}

bool ExifUtils::SetGpsLongitude(double longitude) {
  ExifTag refTag = static_cast<ExifTag>(EXIF_TAG_GPS_LONGITUDE_REF);
  std::unique_ptr<ExifEntry> refEntry =
      AddVariableLengthEntry(EXIF_IFD_GPS, refTag, EXIF_FORMAT_ASCII, 2, 2);
  if (!refEntry) {
    LOGF(ERROR) << "Adding GPSLongitudeRef exif entry failed";
    return false;
  }
  if (longitude >= 0) {
    memcpy(refEntry->data, "E", sizeof("E"));
  } else {
    memcpy(refEntry->data, "W", sizeof("W"));
    longitude *= -1;
  }

  ExifTag tag = static_cast<ExifTag>(EXIF_TAG_GPS_LONGITUDE);
  std::unique_ptr<ExifEntry> entry = AddVariableLengthEntry(
      EXIF_IFD_GPS, tag, EXIF_FORMAT_RATIONAL, 3, 3 * sizeof(ExifRational));
  if (!entry) {
    exif_content_remove_entry(exif_data_->ifd[EXIF_IFD_GPS], refEntry.get());
    LOGF(ERROR) << "Adding GPSLongitude exif entry failed";
    return false;
  }
  SetLatitudeOrLongitudeData(entry->data, longitude);

  return true;
}

bool ExifUtils::SetGpsProcessingMethod(const std::string& method) {
  std::string buffer =
      std::string(gExifAsciiPrefix, sizeof(gExifAsciiPrefix)) + method;
  SET_STRING(EXIF_IFD_GPS, static_cast<ExifTag>(EXIF_TAG_GPS_PROCESSING_METHOD),
             EXIF_FORMAT_UNDEFINED, buffer);
  return true;
}

bool ExifUtils::SetGpsTimestamp(const struct tm& t) {
  const ExifTag dateTag = static_cast<ExifTag>(EXIF_TAG_GPS_DATE_STAMP);
  const size_t kGpsDateStampSize = 11;
  std::unique_ptr<ExifEntry> entry =
      AddVariableLengthEntry(EXIF_IFD_GPS, dateTag, EXIF_FORMAT_ASCII,
                             kGpsDateStampSize, kGpsDateStampSize);
  if (!entry) {
    LOGF(ERROR) << "Adding GPSDateStamp exif entry failed";
    return false;
  }
  int result =
      snprintf(reinterpret_cast<char*>(entry->data), kGpsDateStampSize,
               "%04i:%02i:%02i", t.tm_year + 1900, t.tm_mon + 1, t.tm_mday);
  if (result != kGpsDateStampSize - 1) {
    LOGF(WARNING) << "Input time is invalid";
    return false;
  }

  const ExifTag timeTag = static_cast<ExifTag>(EXIF_TAG_GPS_TIME_STAMP);
  entry = AddVariableLengthEntry(EXIF_IFD_GPS, timeTag, EXIF_FORMAT_RATIONAL, 3,
                                 3 * sizeof(ExifRational));
  if (!entry) {
    LOGF(ERROR) << "Adding GPSTimeStamp exif entry failed";
    return false;
  }
  exif_set_rational(entry->data, EXIF_BYTE_ORDER_INTEL,
                    {static_cast<ExifLong>(t.tm_hour), 1});
  exif_set_rational(entry->data + sizeof(ExifRational), EXIF_BYTE_ORDER_INTEL,
                    {static_cast<ExifLong>(t.tm_min), 1});
  exif_set_rational(entry->data + 2 * sizeof(ExifRational),
                    EXIF_BYTE_ORDER_INTEL,
                    {static_cast<ExifLong>(t.tm_sec), 1});

  return true;
}

bool ExifUtils::SetImageLength(uint32_t length) {
  SET_SHORT(EXIF_IFD_0, EXIF_TAG_IMAGE_LENGTH, length);
  SET_LONG(EXIF_IFD_EXIF, EXIF_TAG_PIXEL_Y_DIMENSION, length);
  return true;
}

bool ExifUtils::SetImageWidth(uint32_t width) {
  SET_SHORT(EXIF_IFD_0, EXIF_TAG_IMAGE_WIDTH, width);
  SET_LONG(EXIF_IFD_EXIF, EXIF_TAG_PIXEL_X_DIMENSION, width);
  return true;
}

bool ExifUtils::SetIsoSpeedRating(uint16_t iso_speed_ratings) {
  SET_SHORT(EXIF_IFD_EXIF, EXIF_TAG_ISO_SPEED_RATINGS, iso_speed_ratings);
  return true;
}

bool ExifUtils::SetLightSource(uint16_t light_source) {
  SET_SHORT(EXIF_IFD_EXIF, EXIF_TAG_LIGHT_SOURCE, light_source);
  return true;
}

bool ExifUtils::SetMaxAperture(uint32_t numerator, uint32_t denominator) {
  SET_RATIONAL(EXIF_IFD_EXIF, EXIF_TAG_MAX_APERTURE_VALUE, numerator,
               denominator);
  return true;
}

bool ExifUtils::SetMeteringMode(uint16_t metering_mode) {
  SET_SHORT(EXIF_IFD_EXIF, EXIF_TAG_METERING_MODE, metering_mode);
  return true;
}

bool ExifUtils::SetOrientation(uint16_t orientation) {
  /*
   * Orientation value:
   *  1      2      3      4      5          6          7          8
   *
   *  888888 888888     88 88     8888888888 88                 88 8888888888
   *  88         88     88 88     88  88     88  88         88  88     88  88
   *  8888     8888   8888 8888   88         8888888888 8888888888         88
   *  88         88     88 88
   *  88         88 888888 888888
   */
  int value = 1;
  switch (orientation) {
    case 90:
      value = 6;
      break;
    case 180:
      value = 3;
      break;
    case 270:
      value = 8;
      break;
    default:
      break;
  }
  SET_SHORT(EXIF_IFD_0, EXIF_TAG_ORIENTATION, value);
  return true;
}

bool ExifUtils::SetResolutionUnit(uint16_t resolution_unit) {
  SET_SHORT(EXIF_IFD_EXIF, EXIF_TAG_RESOLUTION_UNIT, resolution_unit);
  return true;
}

bool ExifUtils::SetSaturation(uint16_t saturation) {
  SET_SHORT(EXIF_IFD_EXIF, EXIF_TAG_SATURATION, saturation);
  return true;
}

bool ExifUtils::SetSceneCaptureType(uint16_t type) {
  SET_SHORT(EXIF_IFD_EXIF, EXIF_TAG_SCENE_CAPTURE_TYPE, type);
  return true;
}

bool ExifUtils::SetSharpness(uint16_t sharpness) {
  SET_SHORT(EXIF_IFD_EXIF, EXIF_TAG_SHARPNESS, sharpness);
  return true;
}

bool ExifUtils::SetShutterSpeed(int32_t numerator, int32_t denominator) {
  SET_SRATIONAL(EXIF_IFD_EXIF, EXIF_TAG_SHUTTER_SPEED_VALUE, numerator,
                denominator);
  return true;
}

bool ExifUtils::SetSubjectDistance(uint32_t numerator, uint32_t denominator) {
  SET_RATIONAL(EXIF_IFD_EXIF, EXIF_TAG_SUBJECT_DISTANCE, numerator,
               denominator);
  return true;
}

bool ExifUtils::SetSubsecTime(const std::string& subsec_time) {
  SET_STRING(EXIF_IFD_EXIF, EXIF_TAG_SUB_SEC_TIME, EXIF_FORMAT_ASCII,
             subsec_time);
  SET_STRING(EXIF_IFD_EXIF, EXIF_TAG_SUB_SEC_TIME_ORIGINAL, EXIF_FORMAT_ASCII,
             subsec_time);
  SET_STRING(EXIF_IFD_EXIF, EXIF_TAG_SUB_SEC_TIME_DIGITIZED, EXIF_FORMAT_ASCII,
             subsec_time);
  return true;
}

bool ExifUtils::SetWhiteBalance(uint16_t white_balance) {
  SET_SHORT(EXIF_IFD_EXIF, EXIF_TAG_WHITE_BALANCE, white_balance);
  return true;
}

bool ExifUtils::SetXResolution(uint32_t numerator, uint32_t denominator) {
  SET_RATIONAL(EXIF_IFD_EXIF, EXIF_TAG_X_RESOLUTION, numerator, denominator);
  return true;
}

bool ExifUtils::SetYCbCrPositioning(uint16_t ycbcr_positioning) {
  SET_SHORT(EXIF_IFD_0, EXIF_TAG_YCBCR_POSITIONING, ycbcr_positioning);
  return true;
}

bool ExifUtils::SetYResolution(uint32_t numerator, uint32_t denominator) {
  SET_RATIONAL(EXIF_IFD_EXIF, EXIF_TAG_Y_RESOLUTION, numerator, denominator);
  return true;
}

bool ExifUtils::GenerateApp1(const void* thumbnail_buffer, uint32_t size) {
  DestroyApp1();
  exif_data_->data =
      const_cast<uint8_t*>(static_cast<const uint8_t*>(thumbnail_buffer));
  exif_data_->size = size;
  // Save the result into |app1_buffer_|.
  exif_data_save_data(exif_data_, &app1_buffer_, &app1_length_);
  if (!app1_length_) {
    LOGF(ERROR) << "Allocate memory for app1_buffer_ failed";
    return false;
  }
  /*
   * The JPEG segment size is 16 bits in spec. The size of APP1 segment should
   * be smaller than 65533 because there are two bytes for segment size field.
   */
  if (app1_length_ > 65533) {
    DestroyApp1();
    LOGF(ERROR) << "The size of APP1 segment is too large";
    return false;
  }
  return true;
}

const uint8_t* ExifUtils::GetApp1Buffer() {
  return app1_buffer_;
}

unsigned int ExifUtils::GetApp1Length() {
  return app1_length_;
}

bool ExifUtils::SetExifVersion(const std::string& exif_version) {
  SET_STRING(EXIF_IFD_EXIF, EXIF_TAG_EXIF_VERSION, EXIF_FORMAT_UNDEFINED,
             exif_version);
  return true;
}

bool ExifUtils::SetMake(const std::string& make) {
  SET_STRING(EXIF_IFD_0, EXIF_TAG_MAKE, EXIF_FORMAT_ASCII, make);
  return true;
}

bool ExifUtils::SetModel(const std::string& model) {
  SET_STRING(EXIF_IFD_0, EXIF_TAG_MODEL, EXIF_FORMAT_ASCII, model);
  return true;
}

bool ExifUtils::ReadProperty() {
  std::string content;
  // If camera.prop doesn't exist, leave Make and Model tags as empty.
  if (!base::PathExists(kCameraPropertyPath)) {
    return false;
  }

  if (!base::ReadFileToString(kCameraPropertyPath, &content)) {
    LOGF(ERROR) << "Read file failed: " << kCameraPropertyPath.value();
    return false;
  }

  std::vector<std::string> properties = base::SplitString(
      content, "\n", base::WhitespaceHandling::TRIM_WHITESPACE,
      base::SplitResult::SPLIT_WANT_NONEMPTY);
  const std::string kManufacturer = "ro.product.manufacturer";
  const std::string kModel = "ro.product.model";

  std::string camera_properties;
  for (const auto& property : properties) {
    VLOGF(1) << "property: " << property;
    std::vector<std::string> key_value = base::SplitString(
        property, "=", base::WhitespaceHandling::TRIM_WHITESPACE,
        base::SplitResult::SPLIT_WANT_ALL);

    if (!key_value[0].compare(0, kManufacturer.length(), kManufacturer)) {
      if (!SetMake(key_value[1])) {
        return false;
      }
    } else if (!key_value[0].compare(0, kModel.length(), kModel)) {
      if (!SetModel(key_value[1])) {
        return false;
      }
    }
  }
  return true;
}

void ExifUtils::Reset() {
  DestroyApp1();
  if (exif_data_) {
    /*
     * Since we decided to ignore the original APP1, we are sure that there is
     * no thumbnail allocated by libexif. |exif_data_->data| is actually
     * allocated by JpegCompressor. Sets |exif_data_->data| to nullptr to
     * prevent exif_data_unref() destroy it incorrectly.
     */
    exif_data_->data = nullptr;
    exif_data_->size = 0;
    exif_data_unref(exif_data_);
    exif_data_ = nullptr;
  }
}

std::unique_ptr<ExifEntry> ExifUtils::AddVariableLengthEntry(
    ExifIfd ifd,
    ExifTag tag,
    ExifFormat format,
    uint64_t components,
    unsigned int size) {
  // Remove old entry if exists.
  exif_content_remove_entry(exif_data_->ifd[ifd],
                            exif_content_get_entry(exif_data_->ifd[ifd], tag));
  ExifMem* mem = exif_mem_new_default();
  if (!mem) {
    LOGF(ERROR) << "Allocate memory for exif entry failed";
    return nullptr;
  }
  std::unique_ptr<ExifEntry> entry(exif_entry_new_mem(mem));
  if (!entry) {
    LOGF(ERROR) << "Allocate memory for exif entry failed";
    exif_mem_unref(mem);
    return nullptr;
  }
  void* tmpBuffer = exif_mem_alloc(mem, size);
  if (!tmpBuffer) {
    LOGF(ERROR) << "Allocate memory for exif entry failed";
    exif_mem_unref(mem);
    return nullptr;
  }

  entry->data = static_cast<unsigned char*>(tmpBuffer);
  entry->tag = tag;
  entry->format = format;
  entry->components = components;
  entry->size = size;

  exif_content_add_entry(exif_data_->ifd[ifd], entry.get());
  exif_mem_unref(mem);

  return entry;
}

std::unique_ptr<ExifEntry> ExifUtils::AddEntry(ExifIfd ifd, ExifTag tag) {
  std::unique_ptr<ExifEntry> entry(
      exif_content_get_entry(exif_data_->ifd[ifd], tag));
  if (entry) {
    // exif_content_get_entry() won't ref the entry, so we ref here.
    exif_entry_ref(entry.get());
    return entry;
  }
  entry.reset(exif_entry_new());
  if (!entry) {
    LOGF(ERROR) << "Allocate memory for exif entry failed";
    return nullptr;
  }
  entry->tag = tag;
  exif_content_add_entry(exif_data_->ifd[ifd], entry.get());
  exif_entry_initialize(entry.get(), tag);
  return entry;
}

bool ExifUtils::SetShort(ExifIfd ifd,
                         ExifTag tag,
                         uint16_t value,
                         const std::string& msg) {
  std::unique_ptr<ExifEntry> entry = AddEntry(ifd, tag);
  if (!entry) {
    LOGF(ERROR) << "Adding " << msg << " entry failed";
    return false;
  }
  exif_set_short(entry->data, EXIF_BYTE_ORDER_INTEL, value);
  return true;
}

bool ExifUtils::SetLong(ExifIfd ifd,
                        ExifTag tag,
                        uint32_t value,
                        const std::string& msg) {
  std::unique_ptr<ExifEntry> entry = AddEntry(ifd, tag);
  if (!entry) {
    LOGF(ERROR) << "Adding " << msg << " entry failed";
    return false;
  }
  exif_set_long(entry->data, EXIF_BYTE_ORDER_INTEL, value);
  return true;
}

bool ExifUtils::SetRational(ExifIfd ifd,
                            ExifTag tag,
                            uint32_t numerator,
                            uint32_t denominator,
                            const std::string& msg) {
  std::unique_ptr<ExifEntry> entry = AddEntry(ifd, tag);
  if (!entry) {
    LOGF(ERROR) << "Adding " << msg << " entry failed";
    return false;
  }
  exif_set_rational(entry->data, EXIF_BYTE_ORDER_INTEL,
                    {numerator, denominator});
  return true;
}

bool ExifUtils::SetSRational(ExifIfd ifd,
                             ExifTag tag,
                             int32_t numerator,
                             int32_t denominator,
                             const std::string& msg) {
  std::unique_ptr<ExifEntry> entry = AddEntry(ifd, tag);
  if (!entry) {
    LOGF(ERROR) << "Adding " << msg << " entry failed";
    return false;
  }
  exif_set_srational(entry->data, EXIF_BYTE_ORDER_INTEL,
                     {numerator, denominator});
  return true;
}

bool ExifUtils::SetString(ExifIfd ifd,
                          ExifTag tag,
                          ExifFormat format,
                          const std::string& buffer,
                          const std::string& msg) {
  size_t entry_size = buffer.length();
  // Since the exif format is undefined, NULL termination is not necessary.
  if (format == EXIF_FORMAT_ASCII) {
    entry_size++;
  }
  std::unique_ptr<ExifEntry> entry =
      AddVariableLengthEntry(ifd, tag, format, entry_size, entry_size);
  if (!entry) {
    LOGF(ERROR) << "Adding " << msg << " entry failed";
    return false;
  }
  memcpy(entry->data, buffer.c_str(), entry_size);
  return true;
}

void ExifUtils::DestroyApp1() {
  /*
   * Since there is no API to access ExifMem in ExifData->priv, we use free
   * here, which is the default free function in libexif. See
   * exif_data_save_data() for detail.
   */
  free(app1_buffer_);
  app1_buffer_ = nullptr;
  app1_length_ = 0;
}

}  // namespace cros
