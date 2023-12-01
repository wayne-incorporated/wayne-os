/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_INCLUDE_CROS_CAMERA_COMMON_TYPES_H_
#define CAMERA_INCLUDE_CROS_CAMERA_COMMON_TYPES_H_

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>

#include <base/numerics/safe_conversions.h>
#include <base/strings/stringprintf.h>

namespace cros {

/**
 * Rect follows rectangular coordinate system for images. (0, 0) is the
 * top-left corner. It can be used to present the coordinates of active sensory
 * array and bounding box of detected faces.
 */
template <typename T>
struct Rect {
  T left;
  T top;
  T width;
  T height;

  Rect() : left(0), top(0), width(0), height(0) {}
  Rect(T l, T t, T w, T h) : left(l), top(t), width(w), height(h) {}
  T right() const {
    return left + width - (std::is_integral<T>::value ? 1 : 0);
  }
  T bottom() const {
    return top + height - (std::is_integral<T>::value ? 1 : 0);
  }
  bool is_valid() const { return width > 0 && height > 0; }
  bool operator==(const Rect& rhs) const {
    return left == rhs.left && top == rhs.top && width == rhs.width &&
           height == rhs.height;
  }
  template <typename U>
  Rect<U> AsRect() const {
    return Rect<U>(base::checked_cast<U>(left), base::checked_cast<U>(top),
                   base::checked_cast<U>(width), base::checked_cast<U>(height));
  }
  std::string ToString() const {
    std::stringstream ss;
    ss << left << "," << top << "+" << width << "x" << height;
    std::string str;
    ss >> str;
    return str;
  }
};

struct Size {
  uint32_t width;
  uint32_t height;

  Size() : width(0), height(0) {}
  Size(uint32_t w, uint32_t h) : width(w), height(h) {}
  uint32_t area() const { return width * height; }
  bool operator<(const Size& rhs) const {
    if (area() == rhs.area()) {
      return width < rhs.width;
    }
    return area() < rhs.area();
  }
  bool operator==(const Size& rhs) const {
    return width == rhs.width && height == rhs.height;
  }
  bool operator!=(const Size& rhs) const { return !(*this == rhs); }
  bool is_valid() const { return width > 0 && height > 0; }
  std::string ToString() const {
    return base::StringPrintf("%ux%u", width, height);
  }
  double aspect_ratio() const {
    return static_cast<double>(width) / static_cast<double>(height);
  }
};

template <typename T>
struct Range {
  T lower_bound = 0;
  T upper_bound = 0;

  Range() = default;
  Range(T l, T u) : lower_bound(l), upper_bound(u) {}
  bool is_valid() const { return lower_bound <= upper_bound; }
  T lower() const { return lower_bound; }
  T upper() const { return upper_bound; }
  T Clamp(T value) const { return std::clamp(value, lower_bound, upper_bound); }
  bool operator==(const Range& rhs) const {
    return lower_bound == rhs.lower_bound && upper_bound == rhs.upper_bound;
  }
};

template <typename T>
std::ostream& operator<<(std::ostream& stream, const Rect<T>& r) {
  return stream << "(" << r.left << "," << r.top << ")+" << r.width << "x"
                << r.height;
}

template <typename T>
std::ostream& operator<<(std::ostream& stream, const Range<T>& r) {
  return stream << "[" << r.lower_bound << ", " << r.upper_bound << "]";
}

}  // namespace cros

template <>
struct std::hash<cros::Size> {
  std::size_t operator()(cros::Size const& s) const noexcept {
    std::size_t h1 = std::hash<unsigned int>{}(s.width);
    std::size_t h2 = std::hash<unsigned int>{}(s.height);
    return h1 ^ (h2 << 1);
  }
};

#endif  // CAMERA_INCLUDE_CROS_CAMERA_COMMON_TYPES_H_
