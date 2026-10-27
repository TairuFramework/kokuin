// A=B+T or R=B+T, with T the order-four point encoded as 32 zero bytes.
// S=1+SHA512(R||A||message) mod L satisfies the cofactored equation, but violates our subgroup rule.
export const mixedOrderVectors = [
  {
    name: 'mixed-order public key',
    message: '6b6f6b75696e207374726963742073756267726f7570',
    publicKey: '5252cc0a7f208133b620acbd4537eba2a4123bf0a8c2e4f980c3b31bb69765ea',
    signature:
      '5866666666666666666666666666666666666666666666666666666666666666e40b5648f51a424e5f78c79ee627dc7b037e5599acbe1982974fd875780ac50d',
  },
  {
    name: 'mixed-order signature point',
    message: '6b6f6b75696e207374726963742073756267726f7570',
    publicKey: '5866666666666666666666666666666666666666666666666666666666666666',
    signature:
      '5252cc0a7f208133b620acbd4537eba2a4123bf0a8c2e4f980c3b31bb69765ea107269cbc9715cb07137d25ed92e5af805b1a2668b19fef789f2487a3c2eee02',
  },
]
