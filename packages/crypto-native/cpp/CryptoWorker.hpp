#pragma once

#include "OwnedBytes.hpp"
#include "generated/kokuin_crypto.h"
#include <thread>
#include <vector>

namespace margelo::nitro::kokuin::crypto {

struct OwnedRequest {
  uint32_t operation;
  uint32_t algorithm;
  uint32_t outputLength;
  OwnedBytes key;
  OwnedBytes message;
  OwnedBytes signature;
};

struct RustOutput {
  CryptoBuffer buffer{nullptr, 0};
  ~RustOutput() { kokuin_crypto_free(buffer); }
};

using CryptoOutputs = std::vector<std::shared_ptr<RustOutput>>;

template <typename Dispatch>
auto dispatchCryptoRequests(std::vector<OwnedRequest> requests, Dispatch dispatch) {
  auto owned = std::make_shared<std::vector<OwnedRequest>>(std::move(requests));
  const auto caller = std::this_thread::get_id();
  return dispatch([owned, caller]() -> CryptoOutputs {
    auto snapshots = std::move(*owned);
    if (std::this_thread::get_id() == caller) throw std::runtime_error("Crypto worker ran on caller thread");
    CryptoOutputs results;
    results.reserve(snapshots.size());
    for (const auto& request : snapshots) {
      auto output = std::make_shared<RustOutput>();
      const auto status = kokuin_crypto_execute(
          request.operation, request.algorithm, {request.key.data(), request.key.size()},
          {request.message.data(), request.message.size()},
          {request.signature.data(), request.signature.size()}, request.outputLength, &output->buffer);
      if (status != 0) throw std::runtime_error("Native crypto request failed: " + std::to_string(status));
      results.push_back(std::move(output));
    }
    // Local snapshots are erased on success and on exceptions, before the dispatcher settles.
    return results;
  });
}

} // namespace margelo::nitro::kokuin::crypto
