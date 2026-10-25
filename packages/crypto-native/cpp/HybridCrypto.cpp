#include "HybridCrypto.hpp"
#include "OwnedBytes.hpp"
#include "generated/kokuin_crypto.h"

#include <thread>

namespace margelo::nitro::kokuin::crypto {
namespace {

OwnedBytes snapshot(const ByteView& view) {
  if (!view.buffer) throw std::invalid_argument("Missing input buffer");
  return copyView(view.buffer->data(), view.buffer->size(), view.offset, view.length);
}

struct OwnedRequest {
  uint32_t operation;
  uint32_t algorithm;
  uint32_t outputLength;
  OwnedBytes key;
  OwnedBytes message;
  OwnedBytes signature;

  explicit OwnedRequest(const CryptoRequest& input)
      : operation(checkedInteger(input.operation, UINT32_MAX)),
        algorithm(checkedInteger(input.algorithm, UINT32_MAX)),
        outputLength(checkedInteger(input.outputLength, UINT32_MAX)),
        key(snapshot(input.key)), message(snapshot(input.message)), signature(snapshot(input.signature)) {}
};

struct RustOutput {
  CryptoBuffer buffer{nullptr, 0};
  ~RustOutput() { kokuin_crypto_free(buffer); }
};

CryptoSlice slice(const OwnedBytes& bytes) { return {bytes.data(), bytes.size()}; }

} // namespace

double HybridCrypto::getAbiVersion() { return kokuin_crypto_abi_version(); }

std::shared_ptr<Promise<std::vector<std::shared_ptr<ArrayBuffer>>>>
HybridCrypto::execute(const std::vector<CryptoRequest>& requests) {
  auto owned = std::make_shared<std::vector<OwnedRequest>>();
  owned->reserve(requests.size());
  // No JS-backed reference crosses the dispatch boundary, even on native-owned inputs.
  for (const auto& request : requests) owned->emplace_back(request);
  const auto caller = std::this_thread::get_id();
  return Promise<std::vector<std::shared_ptr<ArrayBuffer>>>::async([owned, caller]() {
    auto snapshots = std::move(*owned);
    if (std::this_thread::get_id() == caller) throw std::runtime_error("Crypto worker ran on caller thread");
    std::vector<std::shared_ptr<ArrayBuffer>> results;
    results.reserve(snapshots.size());
    for (const auto& request : snapshots) {
      auto output = std::make_shared<RustOutput>();
      const auto status = kokuin_crypto_execute(
          request.operation, request.algorithm, slice(request.key), slice(request.message),
          slice(request.signature), request.outputLength, &output->buffer);
      if (status != 0) throw std::runtime_error("Native crypto request failed: " + std::to_string(status));
      results.push_back(ArrayBuffer::wrap(output->buffer.data, output->buffer.len, [output]() {}));
    }
    // Erase seed-bearing snapshots before settling the Promise.
    snapshots.clear();
    return results;
  });
}

} // namespace margelo::nitro::kokuin::crypto
