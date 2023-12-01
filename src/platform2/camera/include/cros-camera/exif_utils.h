/*
 * Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_INCLUDE_CROS_CAMERA_EXIF_UTILS_H_
#define CAMERA_INCLUDE_CROS_CAMERA_EXIF_UTILS_H_

#include <cstddef>
#include <memory>
#include <string>
#include <utility>
#include <vector>

extern "C" {
#include <libexif/exif-data.h>
}

#include <base/containers/span.h>

#include "cros-camera/export.h"

namespace cros {

// ExifUtils can generate APP1 segment with tags which caller set. ExifUtils can
// also add a thumbnail in the APP1 segment if thumbnail size is specified.
// ExifUtils can be reused with different images by calling initialize().
//
// Example of using this class :
//  ExifUtils utils;
//  utils.initialize();
//  ...
//  // Call ExifUtils functions to set Exif tags.
//  ...
//  utils.GenerateApp1(thumbnail_buffer, thumbnail_size);
//  unsigned int app1Length = utils.GetApp1Length();
//  uint8_t* app1Buffer = new uint8_t[app1Length];
//  memcpy(app1Buffer, utils.GetApp1Buffer(), app1Length);
class CROS_CAMERA_EXPORT ExifUtils {
 public:
  ExifUtils();
  ~ExifUtils();

  // Initialize() can be called multiple times. The setting of Exif tags will be
  // cleared.
  bool Initialize();
  bool InitializeWithData(base::span<uint8_t> blob);

  // Sets the len aperture.
  // Returns false if memory allocation fails.
  bool SetAperture(uint32_t numerator, uint32_t denominator);

  // Sets the value of brightness.
  // Returns false if memory allocation fails.
  bool SetBrightness(int32_t numerator, int32_t denominator);

  // Sets the color space.
  // Returns false if memory allocation fails.
  bool SetColorSpace(uint16_t color_space);

  // Sets the information to compressed data.
  // Returns false if memory allocation fails.
  bool SetComponentsConfiguration(const std::string& components_configuration);

  // Sets the compression scheme used for the image data.
  // Returns false if memory allocation fails.
  bool SetCompression(uint16_t compression);

  // Sets image contrast.
  // Returns false if memory allocation fails.
  bool SetContrast(uint16_t contrast);

  // Sets the date and time of image last modified. It takes local time. The
  // name of the tag is DateTime in IFD0.
  // Returns false if memory allocation fails.
  bool SetDateTime(const struct tm& t);

  // Sets the image description.
  // Returns false if memory allocation fails.
  bool SetDescription(const std::string& description);

  // Sets the digital zoom ratio. If the numerator is 0, it means digital zoom
  // was not used.
  // Returns false if memory allocation fails.
  bool SetDigitalZoomRatio(uint32_t numerator, uint32_t denominator);

  // Sets the exposure bias.
  // Returns false if memory allocation fails.
  bool SetExposureBias(int32_t numerator, int32_t denominator);

  // Sets the exposure mode set when the image was shot.
  // Returns false if memory allocation fails.
  bool SetExposureMode(uint16_t exposure_mode);

  // Sets the program used by the camera to set exposure when the picture is
  // taken.
  // Returns false if memory allocation fails.
  bool SetExposureProgram(uint16_t exposure_program);

  // Sets the exposure time, given in seconds.
  // Returns false if memory allocation fails.
  bool SetExposureTime(uint32_t numerator, uint32_t denominator);

  // Sets the status of flash.
  // Returns false if memory allocation fails.
  bool SetFlash(uint16_t flash);

  // Sets the F number.
  // Returns false if memory allocation fails.
  bool SetFNumber(uint32_t numerator, uint32_t denominator);

  // Sets the focal length of lens used to take the image in millimeters.
  // Returns false if memory allocation fails.
  bool SetFocalLength(uint32_t numerator, uint32_t denominator);

  // Sets the degree of overall image gain adjustment.
  // Returns false if memory allocation fails.
  bool SetGainControl(uint16_t gain_control);

  // Sets the altitude in meters.
  // Returns false if memory allocation fails.
  bool SetGpsAltitude(double altitude);

  // Sets the latitude with degrees minutes seconds format.
  // Returns false if memory allocation fails.
  bool SetGpsLatitude(double latitude);

  // Sets the longitude with degrees minutes seconds format.
  // Returns false if memory allocation fails.
  bool SetGpsLongitude(double longitude);

  // Sets GPS processing method.
  // Returns false if memory allocation fails.
  bool SetGpsProcessingMethod(const std::string& method);

  // Sets GPS date stamp and time stamp (atomic clock). It takes UTC time.
  // Returns false if memory allocation fails.
  bool SetGpsTimestamp(const struct tm& t);

  // Sets the length (number of rows) of main image.
  // Returns false if memory allocation fails.
  bool SetImageLength(uint32_t length);

  // Sets the width (number of columes) of main image.
  // Returns false if memory allocation fails.
  bool SetImageWidth(uint32_t width);

  // Sets the ISO speed.
  // Returns false if memory allocation fails.
  bool SetIsoSpeedRating(uint16_t iso_speed_ratings);

  // Sets the kind of light source.
  // Returns false if memory allocation fails.
  bool SetLightSource(uint16_t light_source);

  // Sets the smallest F number of the lens.
  // Returns false if memory allocation fails.
  bool SetMaxAperture(uint32_t numerator, uint32_t denominator);

  // Sets the metering mode.
  // Returns false if memory allocation fails.
  bool SetMeteringMode(uint16_t metering_mode);

  // Sets image orientation.
  // Returns false if memory allocation fails.
  bool SetOrientation(uint16_t orientation);

  // Sets the unit for measuring XResolution and YResolution.
  // Returns false if memory allocation fails.
  bool SetResolutionUnit(uint16_t resolution_unit);

  // Sets image saturation.
  // Returns false if memory allocation fails.
  bool SetSaturation(uint16_t saturation);

  // Sets the type of scene that was shot.
  // Returns false if memory allocation fails.
  bool SetSceneCaptureType(uint16_t type);

  // Sets image sharpness.
  // Returns false if memory allocation fails.
  bool SetSharpness(uint16_t sharpness);

  // Sets the shutter speed.
  // Returns false if memory allocation fails.
  bool SetShutterSpeed(int32_t numerator, int32_t denominator);

  // Sets the distance to the subject, given in meters.
  // Returns false if memory allocation fails.
  bool SetSubjectDistance(uint32_t numerator, uint32_t denominator);

  // Sets the fractions of seconds for the <DateTime> tag.
  // Returns false if memory allocation fails.
  bool SetSubsecTime(const std::string& subsec_time);

  // Sets the white balance mode set when the image was shot.
  // Returns false if memory allocation fails.
  bool SetWhiteBalance(uint16_t white_balance);

  // Sets the number of pixels per resolution unit in the image width.
  // Returns false if memory allocation fails.
  bool SetXResolution(uint32_t numerator, uint32_t denominator);

  // Sets the position of chrominance components in relation to the luminance
  // component.
  // Returns false if memory allocation fails.
  bool SetYCbCrPositioning(uint16_t ycbcr_positioning);

  // Sets the number of pixels per resolution unit in the image length.
  // Returns false if memory allocation fails.
  bool SetYResolution(uint32_t numerator, uint32_t denominator);

  // Generates APP1 segment.
  // Returns false if generating APP1 segment fails.
  bool GenerateApp1(const void* thumbnail_buffer, uint32_t size);

  // Gets buffer of APP1 segment. This method must be called only after calling
  // GenerateAPP1().
  const uint8_t* GetApp1Buffer();

  // Gets length of APP1 segment. This method must be called only after calling
  // GenerateAPP1().
  unsigned int GetApp1Length();

 private:
  // Sets the version of this standard supported.
  // Returns false if memory allocation fails.
  bool SetExifVersion(const std::string& exif_version);

  // Sets the manufacturer of camera.
  // Returns false if memory allocation fails.
  bool SetMake(const std::string& make);

  // Sets the model number of camera.
  // Returns false if memory allocation fails.
  bool SetModel(const std::string& model);

  // Reads property to set manufacturer and model tag.
  bool ReadProperty();

  // Resets the pointers and memories.
  void Reset();

  // Adds a variable length tag to |exif_data_|. It will remove the original one
  // if the tag exists.
  // Returns the entry of the tag. The reference count of returned ExifEntry is
  // two.
  std::unique_ptr<ExifEntry> AddVariableLengthEntry(ExifIfd ifd,
                                                    ExifTag tag,
                                                    ExifFormat format,
                                                    uint64_t components,
                                                    unsigned int size);

  // Adds a entry of |tag| in |exif_data_|. It won't remove the original one if
  // the tag exists.
  // Returns the entry of the tag. It adds one reference count to returned
  // ExifEntry.
  std::unique_ptr<ExifEntry> AddEntry(ExifIfd ifd, ExifTag tag);

  // Helpe functions to add exif data with different types.
  bool SetShort(ExifIfd ifd,
                ExifTag tag,
                uint16_t value,
                const std::string& msg);
  bool SetLong(ExifIfd ifd,
               ExifTag tag,
               uint32_t value,
               const std::string& msg);
  bool SetRational(ExifIfd ifd,
                   ExifTag tag,
                   uint32_t numerator,
                   uint32_t denominator,
                   const std::string& msg);
  bool SetSRational(ExifIfd ifd,
                    ExifTag tag,
                    int32_t numerator,
                    int32_t denominator,
                    const std::string& msg);
  bool SetString(ExifIfd ifd,
                 ExifTag tag,
                 ExifFormat format,
                 const std::string& buffer,
                 const std::string& msg);

  // Destroys the buffer of APP1 segment if exists.
  void DestroyApp1();

  // The Exif data (APP1). Owned by this class.
  ExifData* exif_data_;
  // The raw data of APP1 segment. It's allocated by ExifMem in |exif_data_| but
  // owned by this class.
  uint8_t* app1_buffer_;
  // The length of |app1_buffer_|.
  unsigned int app1_length_;
};

}  // namespace cros

#endif  // CAMERA_INCLUDE_CROS_CAMERA_EXIF_UTILS_H_
