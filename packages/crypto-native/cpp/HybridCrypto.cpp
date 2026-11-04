#include "HybridCrypto.hpp"
#include "CryptoWorker.hpp"

namespace margelo::nitro::kokuin::crypto {
namespace {

OwnedBytes snapshot(const ByteView& view) {
  if (!view.buffer) throw std::invalid_argument("Missing input buffer");
  return copyView(view.buffer->data(), view.buffer->size(), view.offset, view.length);
}

} // namespace

double HybridCrypto::getAbiVersion() { return kokuin_crypto_abi_version(); }

std::shared_ptr<Promise<std::vector<std::shared_ptr<ArrayBuffer>>>>
HybridCrypto::execute(const std::vector<CryptoRequest>& requests) {
  std::vector<OwnedRequest> owned;
  owned.reserve(requests.size());
  // No JS-backed reference crosses the dispatch boundary, even on native-owned inputs.
  for (const auto& request : requests) {
    owned.push_back(OwnedRequest{
        static_cast<uint32_t>(checkedInteger(request.operation, UINT32_MAX)),
        static_cast<uint32_t>(checkedInteger(request.algorithm, UINT32_MAX)),
        static_cast<uint32_t>(checkedInteger(request.outputLength, UINT32_MAX)),
        snapshot(request.key), snapshot(request.message), snapshot(request.signature)});
  }
  return dispatchCryptoRequests(std::move(owned), [](auto work) {
    return Promise<std::vector<std::shared_ptr<ArrayBuffer>>>::async([work = std::move(work)]() {
      auto outputs = work();
      std::vector<std::shared_ptr<ArrayBuffer>> results;
      results.reserve(outputs.size());
      for (const auto& output : outputs) {
        results.push_back(ArrayBuffer::wrap(output->buffer.data, output->buffer.len, [output]() {}));
      }
      return results;
    });
  });
}

} // namespace margelo::nitro::kokuin::crypto
