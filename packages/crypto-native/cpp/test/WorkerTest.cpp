#include "CryptoWorker.hpp"
#include <cassert>
#include <cstdlib>
#include <future>
#include <new>

using namespace margelo::nitro::kokuin::crypto;

struct Observation { const uint8_t* data; size_t size; };
static std::vector<Observation> observations;
static size_t erased = 0;

void* operator new[](size_t size) {
  if (auto ptr = std::malloc(size == 0 ? 1 : size)) return ptr;
  throw std::bad_alloc();
}
void operator delete[](void* ptr) noexcept {
  for (auto& observation : observations) {
    if (ptr != nullptr && ptr == observation.data) {
      auto bytes = static_cast<const uint8_t*>(ptr);
      for (size_t i = 0; i < observation.size; i++) assert(bytes[i] == 0);
      observation.data = nullptr;
      erased++;
    }
  }
  std::free(ptr);
}

OwnedRequest signingRequest(size_t seedSize) {
  const uint8_t seed[32] = {42};
  OwnedRequest request{1, 1, 0, OwnedBytes(seed, seedSize), OwnedBytes(nullptr, 0), OwnedBytes(nullptr, 0)};
  observations.push_back({request.key.data(), request.key.size()});
  return request;
}

int main() {
  auto async = [](auto work) { return std::async(std::launch::async, std::move(work)); };
  {
    std::vector<OwnedRequest> requests;
    requests.push_back(signingRequest(32));
    auto pending = dispatchCryptoRequests(std::move(requests), async);
    bool succeeded = false;
    try {
      auto outputs = pending.get();
      succeeded = outputs.size() == 1 && outputs[0]->buffer.len == 64;
      assert(erased == 1);
    } catch (...) {}
    assert(succeeded);
  }
  {
    std::vector<OwnedRequest> requests;
    requests.push_back(signingRequest(32));
    requests.push_back(signingRequest(31));
    auto pending = dispatchCryptoRequests(std::move(requests), async);
    bool rejected = false;
    try { auto outputs = pending.get(); } catch (const std::runtime_error&) { rejected = true; }
    assert(rejected && erased == 3);
  }
  {
    std::vector<OwnedRequest> requests;
    requests.push_back(signingRequest(32));
    requests.push_back(signingRequest(32));
    auto failDispatch = [](auto) -> std::future<CryptoOutputs> { throw std::runtime_error("dispatch failed"); };
    bool rejected = false;
    try { auto pending = dispatchCryptoRequests(std::move(requests), failDispatch); }
    catch (const std::runtime_error&) { rejected = true; }
    assert(rejected && erased == 5);
  }
  {
    std::vector<OwnedRequest> requests;
    requests.push_back(signingRequest(32));
    bool rejected = false;
    try { auto outputs = dispatchCryptoRequests(std::move(requests), [](auto work) { return work(); }); }
    catch (const std::runtime_error&) { rejected = true; }
    assert(rejected && erased == 6);
  }
}
