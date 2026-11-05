# @kokuin/records

## Named params migration

| Export | Named params type | Fields |
| --- | --- | --- |
| `new RecordClaimError` | `RecordClaimErrorParams` | `message` |
| `new RecordOpSigningError` | `RecordOpSigningErrorParams` | `message` |
| `signRecordOp` | `SignRecordOpParams` | `identity, claim, opKind, crypto?` |
| `verifyRecordOp` | `VerifyRecordOpParams` | `opJWT, opKind, methods?, crypto?` |
| `verifySignedRecord` | `VerifySignedRecordParams` | `record, opKind, methods?, crypto?` |
| `recordDecisionDigest` | `RecordDecisionDigestParams` | `record, opKind, methods?, crypto?` |
| `compareRecordOps` | `CompareRecordOpsParams` | `incoming, stored, policy, onEqual?` |
| `new RecordTypeGraphError` | `RecordTypeGraphErrorParams` | `message` |
| `new RecordContentRefusalError` | `RecordContentRefusalErrorParams` | `message` |
| `new RecordRangeError` | `RecordRangeErrorParams` | `message, options?` |
| `splitRange` | `SplitRangeParams` | `leaves, rangeBounds, leafThreshold, crypto?` |
| `advanceRecordPull` | `AdvanceRecordPullParams` | `state, local, response, crypto?` |

These signature and typing changes preserve cryptographic results, error causes, ordering and storage behaviour.

Additional APIs use the same flat params convention.

| Export | Named params type | Previous positional form |
| --- | --- | --- |
| `parseBoundedHLC` | `ParseBoundedHLCParams` | `parseBoundedHLC(hlc: string, nowMS: number, maxDriftMS: number)` |
| `recordDecisionFromVerifiedCopies` | `RecordDecisionFromVerifiedCopiesParams` | `recordDecisionFromVerifiedCopies(key: RecordKey, entries: ReadonlyArray<VerifiedRecordCopy>, stampSource: 'hlc' \| 'version')` |
| `createRecordVerifier` | `CreateRecordVerifierParams` | `createRecordVerifier(params: CreateRecordVerifierParams)` |
| `fingerprintRange` | `FingerprintRangeParams` | `fingerprintRange(params: FingerprintRangeParams)` |
| `rangeContains` | `RangeContainsParams` | `rangeContains(bounds: RangeBounds, key: RecordKey)` |
| `rangeLeaf` | `RangeLeafParams` | `rangeLeaf(params: RangeLeafParams)` |
| `summarizeRange` | `SummarizeRangeParams` | `summarizeRange(params: SummarizeRangeParams)` |
| `nextRequesterSteps` | `NextRequesterStepsParams` | `nextRequesterSteps(params: NextRequesterStepsParams)` |
| `recordClaimDigest` | `RecordClaimDigestParams` | `recordClaimDigest(params: RecordClaimDigestParams)` |
| `recordPayloadDigest` | `RecordPayloadDigestParams` | `recordPayloadDigest(params: RecordPayloadDigestParams)` |
| `recordPayloadMatches` | `RecordPayloadMatchesParams` | `recordPayloadMatches(params: RecordPayloadMatchesParams)` |
| `recordSignerKey` | `RecordSignerKeyParams` | `recordSignerKey(issuer: string, opJWT: string)` |
| `getRecordDecisions` | `GetRecordDecisionsParams` | `getRecordDecisions(store: RecordStoreAdapter, keys: ReadonlyArray<RecordKey>)` |
| `filterVisibleRecords` | `FilterVisibleRecordsParams` | `filterVisibleRecords(records: ReadonlyArray<SignedRecord>, types: ReadonlyMap<string, RecordTypeDefinition>, ctx: VisibilityContext)` |
| `verifyHolderProof` | `VerifyHolderProofParams` | `verifyHolderProof(proof: SignedRecord, ctx: VisibilityContext)` |
| `visibleTo` | `VisibleToParams` | `visibleTo(record: SignedRecord, rules: ReadonlyArray<VisibilityRule>, ctx: VisibilityContext)` |

Method and callback contracts follow the same convention.

| API | Named params type | Previous form |
| --- | --- | --- |
| `ApplyRecordChunkParams.verifyCapability` | `ApplyRecordChunkParamsVerifyCapabilityParams` | `verifyCapability(tokens, owner, issuer)` |
| `RecordAuthorizeContext.verifyCapability` | `RecordAuthorizeContextVerifyCapabilityParams` | `verifyCapability(tokens, owner, issuer)` |
| `RecordTypeDefinition.authorize` | `RecordTypeDefinitionAuthorizeParams` | `authorize(op, ctx)` |
| `RecordTypeDefinition.precheck` | `RecordTypeDefinitionPrecheckParams` | `precheck(op, record)` |
| `RecordTypeDefinition.visibleTo` | `RecordTypeDefinitionVisibleToParams` | `visibleTo(record, ctx)` |
| `RecordTypeDefinition.dependencies` | `RecordTypeDefinitionDependenciesParams` | `dependencies(record, op)` |
| `RecordTypeDefinition.onEqual` | `RecordTypeDefinitionOnEqualParams` | `onEqual(incoming, stored)` |
| `RecordTypeDefinition.afterApply` | `RecordTypeDefinitionAfterApplyParams` | `afterApply(record, store)` |
| `RecordTypeDefinition.afterAuthorize` | `RecordTypeDefinitionAfterAuthorizeParams` | `afterAuthorize(record, store)` |
| `RecordTypeDefinition.lockKeys` | `RecordTypeDefinitionLockKeysParams` | `lockKeys(incoming, stored)` |
| `VisibilityContext.authorizeProof` | `VisibilityContextAuthorizeProofParams` | `authorizeProof(record, stored)` |
| `VisibilityContext.currentKeyVersion` | `VisibilityContextCurrentKeyVersionParams` | `currentKeyVersion(owner, keyID)` |
| `VisibilityContext.isGroupMember` | `VisibilityContextIsGroupMemberParams` | `isGroupMember(groupID, did)` |
| `CompareRecordOpsParams.onEqual` | `CompareRecordOpsParamsOnEqualParams` | `onEqual(incoming, stored)` |
| `RecordStoreAdapter.listByGroup` | `RecordStoreAdapterListByGroupParams` | `listByGroup(type, groupID)` |
| `RecordStoreAdapter.pruneCopy` | `RecordStoreAdapterPruneCopyParams` | `pruneCopy(key, signerDID)` |

Existing params objects also flatten their options fields:

| Existing params type | Updated params type | Field migration |
| --- | --- | --- |
| `RecordDecisionDigestParams` | `RecordDecisionDigestParams` | `Nested options fields → top-level fields` |
| `SignRecordOpParams` | `SignRecordOpParams` | `Nested options fields → top-level fields` |
| `VerifyRecordOpParams` | `VerifyRecordOpParams` | `Nested options fields → top-level fields` |
| `VerifySignedRecordParams` | `VerifySignedRecordParams` | `Nested options fields → top-level fields` |
| `AdvanceRecordPullParams` | `AdvanceRecordPullParams` | `Nested options fields → top-level fields` |
| `IsDependencyUnsatisfiedParams` | `IsDependencyUnsatisfiedParams` | `Nested options fields → top-level fields` |
| `IsDependencyUnsatisfiedByParams` | `IsDependencyUnsatisfiedByParams` | `Nested options fields → top-level fields` |
