import {
  createKeyAgreementIdentityForDID,
  createSigningIdentityForDID,
  type DIDString,
  type FullIdentity,
  type SigningIdentity,
  type SignTokenOptions,
} from '@kokuin/token'
import { ed25519 } from '@noble/curves/ed25519.js'

import { agreementPath, authorityPath, deriveKeyPair } from './derivation.js'
import { didFromInception, type InceptionEvent, type SignedEvent } from './events.js'
import type { KeyState } from './fold.js'
import { encodeKey } from './keys.js'
import { type ControllerLog, isControllerLog, MALFORMED_LOG } from './log.js'
import { currentState } from './state.js'

const CONTEXT = 'Controller identity'

/**
 * The DID the log claims to be, read from its inception before any fold runs — the fold needs the DID
 * to check the inception against, so it cannot be the thing that produces it.
 */
function didFromLog(log: ControllerLog): DIDString {
  if (!isControllerLog(log)) {
    throw new Error(`${CONTEXT}: ${MALFORMED_LOG}`)
  }
  if (log.chain.length === 0) {
    throw new Error(`${CONTEXT}: empty log`)
  }
  const first = log.chain[0] as SignedEvent<InceptionEvent>
  if (first.event.t !== 'icp') {
    throw new Error(`${CONTEXT}: first event must be an inception`)
  }
  return didFromInception(first.event)
}

/**
 * Stamp `kid` on every token this identity signs, naming the key that produced the signature. The
 * identity derives exactly one key pair, so `kid` is a fact about the signature, not an input: a
 * caller-supplied one is only ever checked, never honoured — dropping a mismatched one silently would
 * mint a token whose header names a key that did not sign it. Both spellings are checked:
 * `options.kid` and `options.header.kid`.
 */
function withKid(identity: SigningIdentity, kid: string): SigningIdentity {
  return {
    ...identity,
    async signToken<Payload extends Record<string, unknown> = Record<string, unknown>>(
      payload: Payload,
      options: SignTokenOptions = {},
    ) {
      for (const supplied of [options.kid, options.header?.kid]) {
        if (supplied != null && supplied !== kid) {
          throw new Error(
            `${CONTEXT}: cannot sign under kid ${String(supplied)}, this identity holds ${kid}`,
          )
        }
      }
      return identity.signToken(payload, { ...options, header: { ...options.header, kid } })
    },
  }
}

/**
 * Bind a private key the caller holds to the DID, having checked the folded state publishes its
 * public half. Shared by all four entry points, so the membership rule and `kid` binding are written
 * once. Membership, not `keys[0]`: a set may publish several keys and the one in hand need not be
 * first (co-signers' keys belong to other holders); what must hold is that the resolver can answer
 * with this key. A key outside the set signs unverifiable tokens, so fail loudly at construction.
 */
function identityForKey({
  privateKey,
  publicKey,
  did,
  state,
  mismatch,
}: {
  privateKey: Uint8Array
  publicKey: Uint8Array
  did: DIDString
  state: KeyState
  mismatch: string
}): SigningIdentity {
  if (state.keys.length === 0) {
    // Defensive, unreachable through the fold today (`verifySignatures` rejects an empty key set, and
    // the chain holds only key-establishing events). Kept so a future event type that can empty the
    // set fails here rather than deriving a key for a controller that publishes none. `resolver.ts`
    // holds it too.
    throw new Error(`Controller ${did} has no signing key`)
  }

  const key = encodeKey(publicKey, 'EdDSA')
  if (!state.keys.includes(key)) {
    throw new Error(`${CONTEXT}: ${mismatch} of ${did}`)
  }

  // The resolver picks by `kid` and defaults to `keys[0]`, so a token whose key is not first is
  // unverifiable unless the header names the key that signed it.
  return withKid(createSigningIdentityForDID(did, privateKey), `#${key}`)
}

/**
 * Derive the signing key the folded state establishes and bind it to the DID. Shared by the sync and
 * async seed entry points, which differ only in how they reach the state.
 */
function identityForState({
  seed,
  profile,
  did,
  state,
}: {
  seed: Uint8Array
  profile: number
  did: DIDString
  state: KeyState
}): FullIdentity {
  const authority = deriveKeyPair(seed, authorityPath(profile, state.keyGen, state.keySeq), 'EdDSA')
  const signing = identityForKey({
    privateKey: authority.privateKey,
    publicKey: authority.publicKey,
    did,
    state,
    mismatch: 'derived key is not one of the current authority keys',
  })
  // The agreement key sits at the same (keyGen, keySeq) as the authority key — both icp and rot
  // derive them at matching indices — so one position locates both. Verified against the folded
  // set, failing closed like the authority membership check.
  const agreement = deriveKeyPair(
    seed,
    agreementPath(profile, state.keyGen, state.keySeq),
    'X25519',
  )
  const encoded = encodeKey(agreement.publicKey, 'X25519')
  if (!state.agreement.includes(encoded)) {
    throw new Error(
      `${CONTEXT}: derived agreement key is not one of the current agreement keys of ${did}`,
    )
  }
  return { ...signing, ...createKeyAgreementIdentityForDID(did, agreement.privateKey) }
}

export type CreateControllerIdentityParams = {
  seed: Uint8Array
  profile: number
  log: ControllerLog
}

/**
 * A signing identity for a `did:kokuin:` profile, whose `iss` is the profile DID.
 *
 * Takes the log and folds its chain here, so the signing key is always the one that log's current
 * state establishes, never one the caller named. Its epoch events are not folded: they never change a
 * root key (see `currentState`). The log is the caller's freshness contract: an identity
 * built from a stale or truncated log signs with a retired key, minting tokens a current verifier
 * rejects. Rebuild from a re-read log after a rotation rather than holding one across it.
 *
 * The key is derived at `keyGen`/`keySeq`, the derivation index the fold names for the current keys
 * — on a chain of key-establishing events the same number as `seq`, but the question asked is where
 * the key lives, not where the event sits. Every token carries `kid: #<the key that signed it>`, so
 * there is no `kid` parameter — one naming any other key is a request it could not honour, and is
 * rejected on mismatch rather than dropped.
 *
 * Synchronous, and stays so: kubun's apply path depends on it.
 *
 * @throws when the log does not fold, or when the derived key is not one of the profile's current
 * authority keys (a wrong `seed` or `profile` for this log).
 */
export function createControllerIdentity({
  seed,
  profile,
  log,
}: CreateControllerIdentityParams): FullIdentity {
  const did = didFromLog(log)
  return identityForState({ seed, profile, did, state: currentState(did, log, CONTEXT) })
}

export type CreateControllerIdentityWithKeyParams = {
  privateKey: Uint8Array
  log: ControllerLog
}

/**
 * A signing identity for a `did:kokuin:` profile, from the current authority private key rather than
 * the profile seed.
 *
 * The seed form above needs the root seed to derive the key, but the custody tiers say the daily path
 * must not touch it: the root seed lives on a Ledger or cold mnemonic, and a device never receives the
 * profile sub-seed (a sub-seed holder can derive the *next* key and therefore rotate, voiding
 * pre-rotation).
 *
 * What the key in hand can do is exactly the intended granularity: it signs as the profile and cannot
 * rotate, since a rotate must reveal the key the log committed in `n` and only the seed derives that.
 * Losing it costs a rotate-then-deny, not the identity. Takes the raw private key (no identity type
 * here signs raw bytes; a `KeyStore` entry hands back exactly this); the public half is derived from
 * it, so a caller cannot present one key and sign with another.
 *
 * @throws when the log does not fold, or when the key's public half is not one of the profile's
 * current authority keys — a stale log, or a key the profile has rotated away.
 */
export function createControllerIdentityWithKey({
  privateKey,
  log,
}: CreateControllerIdentityWithKeyParams): SigningIdentity {
  const did = didFromLog(log)
  return identityForKey({
    privateKey,
    publicKey: ed25519.getPublicKey(privateKey),
    did,
    state: currentState(did, log, CONTEXT),
    mismatch: 'the supplied key is not one of the current authority keys',
  })
}
