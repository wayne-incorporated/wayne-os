// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
#include "camera3_test/camera3_exif_validator.h"

#include <algorithm>
#include <limits>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <jpeglib.h>

namespace camera3_test {

enum {
  ORIENTATION_UNDEFINED,
  ORIENTATION_NORMAL,
  ORIENTATION_FLIP_HORIZONTAL,
  ORIENTATION_ROTATE_180,
  ORIENTATION_FLIP_VERTICAL,
  ORIENTATION_TRANSPOSE,
  ORIENTATION_ROTATE_90,
  ORIENTATION_TRANSVERSE,
  ORIENTATION_ROTATE_270,
};

static int32_t GetJpegInfo(uint8_t* data,
                           size_t size,
                           ResolutionInfo* resolution,
                           ExifData** exif_data) {
#define JPEG_APP1 (JPEG_APP0 + 1)
  const unsigned int kMaxMarkerLength = 0xffff;
  struct jpeg_decompress_struct jpeg_info;
  struct jpeg_error_mgr jpeg_error;
  jpeg_info.err = jpeg_std_error(&jpeg_error);
  jpeg_create_decompress(&jpeg_info);
  jpeg_mem_src(&jpeg_info, data, size);
  jpeg_save_markers(&jpeg_info, JPEG_APP1, kMaxMarkerLength);
  if (jpeg_read_header(&jpeg_info, TRUE) != JPEG_HEADER_OK) {
    jpeg_destroy_decompress(&jpeg_info);
    return -EINVAL;
  }
  if (resolution) {
    *resolution = ResolutionInfo(jpeg_info.image_width, jpeg_info.image_height);
  }
  if (exif_data) {
    for (auto marker = jpeg_info.marker_list; marker != nullptr;
         marker = marker->next) {
      if (marker->marker == JPEG_APP1) {
        *exif_data = exif_data_new_from_data(marker->data, marker->data_length);
        break;
      }
    }
  }
  jpeg_destroy_decompress(&jpeg_info);
  return 0;
}

static int32_t GetExifOrientationInDegree(int32_t exif_orientation) {
  switch (exif_orientation) {
    case ORIENTATION_NORMAL:
      return 0;
    case ORIENTATION_ROTATE_90:
      return 90;
    case ORIENTATION_ROTATE_180:
      return 180;
    case ORIENTATION_ROTATE_270:
      return 270;
    default:
      ADD_FAILURE() << "It is impossible to get non 0, 90, 180, 270 degress "
                       "exif info based on the request orientation range";
      return 0;
  }
}

static int32_t GetExifTagInteger(const ExifData& exif_data,
                                 const ExifIfd& ifd,
                                 const ExifTag& tag,
                                 const ExifByteOrder& byte_order) {
  ExifEntry* entry = exif_data_get_entry((&exif_data), tag);
  if (!entry) {
    ADD_FAILURE() << "Failed to get EXIF tag "
                  << exif_tag_get_name_in_ifd(tag, ifd);
    return -EINVAL;
  }
  switch (entry->format) {
    case EXIF_FORMAT_SHORT:
      return exif_get_short(entry->data, byte_order);
    case EXIF_FORMAT_LONG:
      return exif_get_long(entry->data, byte_order);
    case EXIF_FORMAT_SLONG:
      return exif_get_slong(entry->data, byte_order);
    default:
      ADD_FAILURE() << "Invalid EXIF entry format " << entry->format;
      return -EINVAL;
  }
}

static const char* GetExifTagString(const ExifData& exif_data,
                                    const ExifIfd& ifd,
                                    const ExifTag& tag) {
  ExifEntry* entry = exif_data_get_entry((&exif_data), tag);
  if (!entry) {
    ADD_FAILURE() << "Failed to get EXIF tag "
                  << exif_tag_get_name_in_ifd(tag, ifd);
    return nullptr;
  }
  EXPECT_EQ(EXIF_FORMAT_ASCII, entry->format)
      << "Invalid EXIF entry string format " << entry->format;
  return reinterpret_cast<char*>(entry->data);
}

static float GetExifTagFloat(const ExifData& exif_data,
                             const ExifIfd& ifd,
                             const ExifTag& tag,
                             const ExifByteOrder& byte_order) {
  ExifEntry* entry = exif_data_get_entry((&exif_data), tag);
  if (!entry) {
    ADD_FAILURE() << "Failed to get EXIF tag "
                  << exif_tag_get_name_in_ifd(tag, ifd);
    return -EINVAL;
  }
  switch (entry->format) {
    case EXIF_FORMAT_RATIONAL: {
      ExifRational rational = exif_get_rational(entry->data, byte_order);
      return static_cast<float>(rational.numerator) /
             static_cast<float>(rational.denominator);
    }
    case EXIF_FORMAT_SRATIONAL: {
      ExifSRational srational = exif_get_srational(entry->data, byte_order);
      return static_cast<float>(srational.numerator) /
             static_cast<float>(srational.denominator);
    }
    default:
      ADD_FAILURE() << "Invalid EXIF entry format " << entry->format;
      return -EINVAL;
  }
}

Camera3ExifValidator::JpegExifInfo::JpegExifInfo(
    const cros::ScopedBufferHandle& buffer, size_t size)
    : buffer_handle(buffer),
      buffer_size(size),
      buffer_addr(nullptr),
      jpeg_resolution(ResolutionInfo(0, 0)),
      exif_data(nullptr) {
  // Get JPEG image address and size
  if (Camera3TestGralloc::GetInstance()->Lock(*buffer_handle, 0, 0, 0, size, 1,
                                              &buffer_addr) != 0 ||
      !buffer_addr) {
    ADD_FAILURE() << "Failed to map buffer";
  }
}

Camera3ExifValidator::JpegExifInfo::~JpegExifInfo() {
  if (exif_data) {
    exif_data_unref(exif_data);
  }
  Camera3TestGralloc::GetInstance()->Unlock(*buffer_handle);
}

bool Camera3ExifValidator::JpegExifInfo::Initialize() {
  if (!buffer_addr) {
    return false;
  }
  auto jpeg_blob = reinterpret_cast<camera3_jpeg_blob_t*>(
      static_cast<uint8_t*>(buffer_addr) + buffer_size -
      sizeof(camera3_jpeg_blob_t));
  if (static_cast<void*>(jpeg_blob) < buffer_addr ||
      jpeg_blob->jpeg_blob_id != CAMERA3_JPEG_BLOB_ID) {
    ADD_FAILURE() << "Invalid JPEG BLOB ID";
    return false;
  }
  if (GetJpegInfo(static_cast<uint8_t*>(buffer_addr), jpeg_blob->jpeg_size,
                  &jpeg_resolution, &exif_data) != 0) {
    ADD_FAILURE() << "No valid JPEG image found in the buffer";
    return false;
  }
  return true;
}

static ResolutionInfo GetMetadataThumbnailSize(
    const camera_metadata_t& metadata) {
  const size_t kNumOfElementsInSizeEntry = 2;
  enum { SIZE_ENTRY_WIDTH_INDEX, SIZE_ENTRY_HEIGHT_INDEX };
  camera_metadata_ro_entry_t entry;
  if (find_camera_metadata_ro_entry(&metadata, ANDROID_JPEG_THUMBNAIL_SIZE,
                                    &entry)) {
    ADD_FAILURE() << "Cannot find the metadata ANDROID_JPEG_THUMBNAIL_SIZE";
    return ResolutionInfo(-1, -1);
  }
  if (entry.count != kNumOfElementsInSizeEntry) {
    ADD_FAILURE()
        << "Invalid entry count of metadata ANDROID_JPEG_THUMBNAIL_SIZE ("
        << entry.count << ")";
    return ResolutionInfo(-1, -1);
  }
  return ResolutionInfo(entry.data.i32[SIZE_ENTRY_WIDTH_INDEX],
                        entry.data.i32[SIZE_ENTRY_HEIGHT_INDEX]);
}

static int64_t GetMetadataInteger(const camera_metadata_t& metadata,
                                  int32_t key) {
  camera_metadata_ro_entry_t entry;
  if (find_camera_metadata_ro_entry(&metadata, key, &entry)) {
    ADD_FAILURE() << "Cannot find the metadata "
                  << get_camera_metadata_tag_name(key);
    return -EINVAL;
  }
  switch (entry.type) {
    case TYPE_BYTE:
      return entry.data.u8[0];
    case TYPE_INT32:
      return entry.data.i32[0];
    case TYPE_INT64:
      return entry.data.i64[0];
    default:
      ADD_FAILURE() << "Unexpected metadata entry type " << entry.type;
      return -EINVAL;
  }
}

static float GetMetadataKeyValueFloat(const camera_metadata_t& metadata,
                                      int32_t key) {
  camera_metadata_ro_entry_t entry;
  if (find_camera_metadata_ro_entry(&metadata, key, &entry)) {
    ADD_FAILURE() << "Cannot find the metadata "
                  << get_camera_metadata_tag_name(key);
    return -EINVAL;
  }
  if (entry.type != TYPE_FLOAT) {
    ADD_FAILURE() << "Unexpected metadata entry type " << entry.type;
    return -EINVAL;
  }
  return entry.data.f[0];
}

void Camera3ExifValidator::ValidateExifKeys(
    const ResolutionInfo& jpeg_resolution,
    const ExifTestData& exif_test_data,
    const cros::ScopedBufferHandle& buffer,
    size_t buffer_size,
    const camera_metadata_t& metadata,
    const time_t& date_time) const {
  const int32_t kExifDateTimeStringLength = 19;
  const double kExifDateTimeErrorMarginSeconds = 60;
  const float kExifFocalLengthErrorMargin = 0.001f;
  const float kExifExposureTimeErrorMarginRation = 0.05f;
  const float kExifExposureTimeMinErrorMarginSeconds = 0.002f;
  const float kOneNanoSecond = 1e-9;
  const float kExifApertureErrorMargin = 0.001f;
  auto GetClosestValueInArray = [](std::vector<float> values, float target) {
    int min_idx = -1;
    float min_distance = std::numeric_limits<float>::max();
    for (size_t i = 0; i < values.size(); i++) {
      float distance = std::abs(values[i] - target);
      if (min_distance > distance) {
        min_distance = distance;
        min_idx = i;
      }
    }
    return (min_idx >= 0) ? values[min_idx]
                          : -std::numeric_limits<float>::max();
  };
  auto SwapWidthAndHeight = [](ResolutionInfo* resolution) {
    *resolution = ResolutionInfo(resolution->Height(), resolution->Width());
  };

  JpegExifInfo jpeg_exif_info(buffer, buffer_size);
  ASSERT_TRUE(jpeg_exif_info.Initialize());
  ExifByteOrder byte_order = exif_data_get_byte_order(jpeg_exif_info.exif_data);
  const ExifData& exif_data = *jpeg_exif_info.exif_data;
  int32_t exif_orientation = GetExifTagInteger(
      exif_data, EXIF_IFD_0, EXIF_TAG_ORIENTATION, byte_order);
  EXPECT_LE(ORIENTATION_UNDEFINED, exif_orientation)
      << "Invalid EXIF orientation value";
  EXPECT_GE(ORIENTATION_ROTATE_270, exif_orientation)
      << "Invalid EXIF orientation value";
  EXPECT_TRUE(exif_orientation == ORIENTATION_UNDEFINED ||
              exif_test_data.orientation ==
                  GetExifOrientationInDegree(exif_orientation))
      << "EXIF orientaiton should match requested orientation";

  if (exif_test_data.thumbnail_resolution == ResolutionInfo(0, 0)) {
    EXPECT_EQ(nullptr, exif_data.data)
        << "JPEG shouldn't have thumbnail when thumbnail size is (0, 0)";
  } else {
    EXPECT_NE(nullptr, exif_data.data) << "No thumbnail found in JPEG image";
    ResolutionInfo expected_thumbnail_resolution(
        exif_test_data.thumbnail_resolution);
    if (exif_test_data.orientation % 180 == 90 &&
        exif_orientation == ORIENTATION_UNDEFINED) {
      // Device physically rotated image+thumbnail data
      // Expect thumbnail size to be also rotated
      SwapWidthAndHeight(&expected_thumbnail_resolution);
    }
    EXPECT_EQ(expected_thumbnail_resolution, GetMetadataThumbnailSize(metadata))
        << "JPEG thumbnail size result and request should match";
    if (exif_data.data) {
      ResolutionInfo actual_thumbnail_resolution(0, 0);
      if (GetJpegInfo(exif_data.data, exif_data.size,
                      &actual_thumbnail_resolution, nullptr) != 0) {
        ADD_FAILURE() << "No valid thumbnail image found in the buffer";
      } else {
        EXPECT_EQ(expected_thumbnail_resolution, actual_thumbnail_resolution)
            << "EXIF thumbnail image size should match requested size";
      }
    }
  }
  EXPECT_EQ(exif_test_data.orientation,
            GetMetadataInteger(metadata, ANDROID_JPEG_ORIENTATION))
      << "JPEG orientation result and request should match";
  EXPECT_EQ(exif_test_data.jpeg_quality,
            GetMetadataInteger(metadata, ANDROID_JPEG_QUALITY))
      << "JPEG quality result and request should match";
  EXPECT_EQ(exif_test_data.thumbnail_quality,
            GetMetadataInteger(metadata, ANDROID_JPEG_THUMBNAIL_QUALITY))
      << "JPEG thumbnail quality result and request should match";
  // TAG_ORIENTATION.
  // Orientation and exif x/y dimensions need to be tested carefully, two cases:
  // 1. Device rotates the image buffer physically, then exif x/y dimensions
  // may not match the requested still capture size, we need swap them to check.
  // 2. Device uses the exif tag to record the image orientation, it doesn't
  // rotate the jpeg image buffer itself. In this case, the exif x/y dimensions
  // should always match the requested still capture size, and the exif
  // orientation should always match the requested orientation.
  ResolutionInfo expected_jpeg_size(jpeg_resolution);
  if (exif_test_data.orientation % 180 == 90 &&
      exif_orientation == ORIENTATION_UNDEFINED) {
    // Device captured image doesn't respect the requested orientation, which
    // means it rotates the image buffer physically. Then we should swap the
    // exif x/y dimensions accordingly to compare.
    SwapWidthAndHeight(&expected_jpeg_size);
  }
  EXPECT_EQ(
      expected_jpeg_size,
      ResolutionInfo(GetExifTagInteger(exif_data, EXIF_IFD_EXIF,
                                       EXIF_TAG_PIXEL_X_DIMENSION, byte_order),
                     GetExifTagInteger(exif_data, EXIF_IFD_EXIF,
                                       EXIF_TAG_PIXEL_Y_DIMENSION, byte_order)))
      << "EXIF JPEG pixel dimension should match requested size";
  EXPECT_EQ(expected_jpeg_size, jpeg_exif_info.jpeg_resolution)
      << "JPEG size result and request should match";

  // Validate date time between EXIF data and current time
  const char* exif_datetime_string =
      GetExifTagString(exif_data, EXIF_IFD_0, EXIF_TAG_DATE_TIME);
  if (exif_datetime_string) {
    EXPECT_EQ(kExifDateTimeStringLength, strlen(exif_datetime_string))
        << "EXIF dateTime is in wrong format";
    struct tm exif_tm = {};
    strptime(exif_datetime_string, "%Y:%m:%d %H:%M:%S", &exif_tm);
    time_t exif_time = mktime(&exif_tm);
    EXPECT_GT(kExifDateTimeErrorMarginSeconds, difftime(date_time, exif_time))
        << "Capture time deviates too much from the current time";
    const char* exif_datetime_digitized = GetExifTagString(
        exif_data, EXIF_IFD_EXIF, EXIF_TAG_DATE_TIME_DIGITIZED);
    if (exif_datetime_digitized) {
      EXPECT_EQ(kExifDateTimeStringLength, strlen(exif_datetime_digitized))
          << "EXIF digitizedTime is in wrong format";
      EXPECT_EQ(0, strncmp(exif_datetime_string, exif_datetime_digitized,
                           kExifDateTimeStringLength))
          << "EXIF dataTime should match digitizedTime";
    }
  }

  // Validate focal length between EXIF data and metadata
  std::vector<float> focal_lengths;
  if (cam_info_.GetAvailableFocalLengths(&focal_lengths) != 0 ||
      focal_lengths.empty()) {
    ADD_FAILURE() << "Failed to get available focal lengths";
  } else {
    float exif_focal_length = GetExifTagFloat(
        exif_data, EXIF_IFD_EXIF, EXIF_TAG_FOCAL_LENGTH, byte_order);
    EXPECT_GT(
        kExifFocalLengthErrorMargin,
        std::abs(GetClosestValueInArray(focal_lengths, exif_focal_length) -
                 exif_focal_length))
        << "EXIF focal length should be one of the available focal lengths";
    float result_focal_length =
        GetMetadataKeyValueFloat(metadata, ANDROID_LENS_FOCAL_LENGTH);
    EXPECT_LT(0.0f, result_focal_length)
        << "Result Focal length " << result_focal_length
        << " should be positive";
    EXPECT_NE(focal_lengths.end(),
              std::find(focal_lengths.begin(), focal_lengths.end(),
                        result_focal_length))
        << "Result Focal length should be one of the available focal lengths";
    EXPECT_GT(kExifFocalLengthErrorMargin,
              std::abs(result_focal_length - exif_focal_length))
        << "EXIF focal length should match capture result";
  }

  // Validate exposure time between EXIF data and metadata
  float exif_exposure_time = GetExifTagFloat(
      exif_data, EXIF_IFD_EXIF, EXIF_TAG_EXPOSURE_TIME, byte_order);
  if (exif_exposure_time > 0 &&
      cam_info_.IsKeyAvailable(ANDROID_SENSOR_EXPOSURE_TIME)) {
    float result_exposure_time = static_cast<float>(GetMetadataInteger(
                                     metadata, ANDROID_SENSOR_EXPOSURE_TIME)) *
                                 kOneNanoSecond;
    float tolerance =
        std::max(result_exposure_time * kExifExposureTimeErrorMarginRation,
                 kExifExposureTimeMinErrorMarginSeconds);
    EXPECT_GT(tolerance, std::abs(result_exposure_time - exif_exposure_time))
        << "Exif exposure time doesn't match";
  }

  // Validate aperture between EXIF data and metadata
  float exif_aperture =
      GetExifTagFloat(exif_data, EXIF_IFD_EXIF, EXIF_TAG_FNUMBER, byte_order);
  if (exif_aperture > 0 &&
      cam_info_.IsKeyAvailable(ANDROID_LENS_INFO_AVAILABLE_APERTURES)) {
    std::vector<float> apertures;
    if (cam_info_.GetAvailableApertures(&apertures) != 0 || apertures.empty()) {
      ADD_FAILURE() << "Failed to get available apertures";
    } else {
      float result_aperture =
          GetMetadataKeyValueFloat(metadata, ANDROID_LENS_APERTURE);
      EXPECT_GT(kExifApertureErrorMargin,
                std::abs(GetClosestValueInArray(apertures, exif_aperture) -
                         exif_aperture))
          << "Aperture value should be one of the available apertures";
      EXPECT_GT(kExifApertureErrorMargin,
                std::abs(result_aperture - exif_aperture))
          << "Exif aperture length should match capture result";
    }
  }

  // Verify EXIF TAG_FLASH is available
  GetExifTagInteger(exif_data, EXIF_IFD_EXIF, EXIF_TAG_FLASH, byte_order);
  // Verify EXIF TAG_WHITE_BALANCE is available
  GetExifTagInteger(exif_data, EXIF_IFD_EXIF, EXIF_TAG_WHITE_BALANCE,
                    byte_order);
  // TODO(hywu): For full devices, validate flash and AWB between EXIF and
  // metadata

  // Validate ISO between EXIF and metadata
  if (cam_info_.IsKeyAvailable(ANDROID_SENSOR_SENSITIVITY)) {
    int32_t iso = GetExifTagInteger(exif_data, EXIF_IFD_EXIF,
                                    EXIF_TAG_ISO_SPEED_RATINGS, byte_order);
    EXPECT_EQ(GetMetadataInteger(metadata, ANDROID_SENSOR_SENSITIVITY), iso)
        << "EXIF TAG_ISO is incorrect";
  }

  auto is_number = [&](const ExifIfd& ifd, const ExifTag& tag) {
    const char* c = GetExifTagString(exif_data, ifd, tag);
    const std::string s(c ? c : "");
    return !s.empty() && std::find_if(s.begin(), s.end(), [](char c) {
                           return !std::isdigit(c);
                         }) == s.end();
  };
  EXPECT_TRUE(is_number(EXIF_IFD_EXIF, EXIF_TAG_SUB_SEC_TIME));
  EXPECT_TRUE(is_number(EXIF_IFD_EXIF, EXIF_TAG_SUB_SEC_TIME_ORIGINAL));
  EXPECT_TRUE(is_number(EXIF_IFD_EXIF, EXIF_TAG_SUB_SEC_TIME_DIGITIZED));
}

int Camera3ExifValidator::getExifOrientation(
    const cros::ScopedBufferHandle& buffer, size_t buffer_size) {
  JpegExifInfo jpeg_exif_info(buffer, buffer_size);
  jpeg_exif_info.Initialize();
  ExifByteOrder byte_order = exif_data_get_byte_order(jpeg_exif_info.exif_data);
  const ExifData& exif_data = *jpeg_exif_info.exif_data;
  int32_t exif_orientation = GetExifTagInteger(
      exif_data, EXIF_IFD_0, EXIF_TAG_ORIENTATION, byte_order);
  return exif_orientation;
}

}  // namespace camera3_test
