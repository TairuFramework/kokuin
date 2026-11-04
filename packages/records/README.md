# @kokuin/records

## Named params migration

| Export | Named params type | Fields |
| --- | --- | --- |
| `new RecordClaimError` | `RecordClaimErrorParams` | `message` |
| `new RecordOpSigningError` | `RecordOpSigningErrorParams` | `message` |
| `signRecordOp` | `SignRecordOpParams` | `identity, claim, opKind, options?` |
| `verifyRecordOp` | `VerifyRecordOpParams` | `opJWT, opKind, methods?, options?` |
| `verifySignedRecord` | `VerifySignedRecordParams` | `record, opKind, methods?, options?` |
| `recordDecisionDigest` | `RecordDecisionDigestParams` | `record, opKind, methods?, options?` |
| `compareRecordOps` | `CompareRecordOpsParams` | `incoming, stored, policy, onEqual?` |
| `new RecordTypeGraphError` | `RecordTypeGraphErrorParams` | `message` |
| `new RecordContentRefusalError` | `RecordContentRefusalErrorParams` | `message` |
| `new RecordRangeError` | `RecordRangeErrorParams` | `message, options?` |
| `splitRange` | `SplitRangeParams` | `leaves, rangeBounds, leafThreshold, cryptoOptions?` |
| `advanceRecordPull` | `AdvanceRecordPullParams` | `state, local, response, options?` |

These signature and typing changes preserve cryptographic results, error causes, ordering and storage behaviour.
