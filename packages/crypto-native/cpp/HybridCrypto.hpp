#pragma once

#include "HybridCryptoSpec.hpp"

namespace margelo::nitro::kokuin::crypto {

class HybridCrypto final : public HybridCryptoSpec {
 public:
  HybridCrypto() : HybridObject(TAG) {}
  double getAbiVersion() override;
  std::shared_ptr<Promise<std::vector<std::shared_ptr<ArrayBuffer>>>>
  execute(const std::vector<CryptoRequest>& requests) override;
};

} // namespace margelo::nitro::kokuin::crypto
