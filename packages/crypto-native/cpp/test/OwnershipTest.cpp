#include "OwnedBytes.hpp"

#include <cassert>
#include <cstdlib>
#include <limits>
#include <new>

using namespace margelo::nitro::kokuin::crypto;

static const uint8_t* observed = nullptr;
static size_t observedSize = 0;
static size_t erasedAllocations = 0;

void* operator new[](size_t size) {
  if (auto ptr = std::malloc(size == 0 ? 1 : size)) return ptr;
  throw std::bad_alloc();
}

void operator delete[](void* ptr) noexcept {
  if (ptr != nullptr && ptr == observed) {
    const auto bytes = static_cast<const uint8_t*>(ptr);
    for (size_t i = 0; i < observedSize; i++) assert(bytes[i] == 0);
    erasedAllocations++;
    observed = nullptr;
  }
  std::free(ptr);
}

int main() {
  const uint8_t input[] = {99, 1, 2, 3, 99};
  {
    auto owned = copyView(input, 5, 1, 3);
    assert(owned.size() == 3 && owned.data()[0] == 1 && owned.data()[2] == 3);
    observed = owned.data();
    observedSize = owned.size();
    auto moved = std::move(owned);
    assert(moved.data() == observed);
  }
  assert(erasedAllocations == 1);
  try {
    auto owned = copyView(input, 5, 1, 3);
    observed = owned.data();
    observedSize = owned.size();
    throw std::runtime_error("dispatch failed");
  } catch (const std::runtime_error&) {}
  assert(erasedAllocations == 2);
  for (const auto invalid : {-1.0, 0.5, 6.0, std::numeric_limits<double>::infinity()}) {
    bool rejected = false;
    try { auto owned = copyView(input, 5, invalid, 1); }
    catch (const std::invalid_argument&) { rejected = true; }
    assert(rejected);
  }
  assert(copyView(nullptr, 0, 0, 0).size() == 0);
}
