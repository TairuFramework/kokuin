#pragma once

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <stdexcept>

namespace margelo::nitro::kokuin::crypto {

inline void wipeBytes(uint8_t* data, size_t size) noexcept {
  volatile uint8_t* bytes = data;
  while (size-- > 0) *bytes++ = 0;
}

class OwnedBytes {
 public:
  OwnedBytes(const uint8_t* data, size_t size) : size_(size), data_(new uint8_t[size]) {
    if (size != 0) std::memcpy(data_.get(), data, size);
  }
  OwnedBytes(const OwnedBytes&) = delete;
  OwnedBytes& operator=(const OwnedBytes&) = delete;
  OwnedBytes(OwnedBytes&& other) noexcept : size_(other.size_), data_(std::move(other.data_)) {
    other.size_ = 0;
  }
  OwnedBytes& operator=(OwnedBytes&&) = delete;
  ~OwnedBytes() { wipeBytes(data_.get(), size_); }
  const uint8_t* data() const { return data_.get(); }
  size_t size() const { return size_; }

 private:
  size_t size_;
  std::unique_ptr<uint8_t[]> data_;
};

inline size_t checkedInteger(double value, size_t maximum) {
  if (!std::isfinite(value) || value < 0 || std::floor(value) != value ||
      value > static_cast<double>(maximum)) {
    throw std::invalid_argument("Invalid crypto buffer descriptor");
  }
  return static_cast<size_t>(value);
}

inline OwnedBytes copyView(const uint8_t* data, size_t size, double offset, double length) {
  const auto start = checkedInteger(offset, size);
  const auto count = checkedInteger(length, size - start);
  if (data == nullptr && count != 0) throw std::invalid_argument("Unavailable input buffer");
  return OwnedBytes(count == 0 ? nullptr : data + start, count);
}

} // namespace margelo::nitro::kokuin::crypto
