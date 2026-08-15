import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import { authorityPath, deriveKeyPair, recoveryPath } from '../src/derivation.js'
import {
  createInception,
  createReset,
  createRotate,
  didFromInception,
  encodeKey,
  type RotateEvent,
  type SignedEvent,
  signEvent,
  verifyReset,
} from '../src/events.js'
import { foldLog } from '../src/fold.js'

const ownerSeed = new Uint8Array(32).fill(1)
const newRootSeed = new Uint8Array(32).fill(77)

function recoveryKeyOf(seed: Uint8Array) {
  return deriveKeyPair(seed, recoveryPath(0), 'EdDSA')
}

/** Re-sign a rotate body after mutating it, with the key the rotate reveals. */
function resign(
  event: RotateEvent,
  seed: Uint8Array,
  keyGen: number,
  keySeq: number,
): SignedEvent<RotateEvent> {
  const key = deriveKeyPair(seed, authorityPath(0, keyGen, keySeq), 'EdDSA')
  return { event, sigs: signEvent(event, [key.privateKey]) }
}

// CLOSED by removing the field. `RotateEvent.r` was written, digested into the event, and read by
// nothing: `verifyReset` checked `inception.r` regardless, so the commitment could never move while
// `KeyState.recovery` cheerfully reported that it had. The alternative — a recovery co-signature on
// a rotate that changes `r` — was rejected because it costs the property the whole recovery design
// rests on: a reset anchors to the inception so a root holding only its seed can author one with no
// log knowledge at all, and a movable commitment means the root must read the log to learn which
// key to sign with. `recoveryPath(profile)` carries no index for the same reason.
//
// A rotate carrying `r` is now *refused* rather than ignored, so the field cannot come back as wire
// data nothing reads. Constructions below are byte-for-byte what they were — `r` is no longer in
// the type, so writing one needs a cast, which is the point. The assertions changed.
type RotateWithRecovery = RotateEvent & { r: string }

describe('ATTACK: `RotateEvent.r` — the documented recovery-commitment update', () => {
  test('ROW 1 (closed): a rotate carrying `r` is refused, not accepted-and-ignored', () => {
    const icp = createInception(ownerSeed, 0)
    const did = didFromInception(icp.event)
    const rot = createRotate(ownerSeed, 0, did, icp.event)

    const newRecovery = recoveryKeyOf(newRootSeed)

    // Mutate exactly one field: `r`. Everything else is the generator's own rotate. Re-signed with
    // the same revealed authority key the generator used — no recovery signature is added.
    const mutated: RotateWithRecovery = {
      ...rot.event,
      r: digestOf(encodeKey(newRecovery.publicKey, 'EdDSA')),
    }
    const forgedRot = resign(mutated, ownerSeed, 0, 1)

    const folded = foldLog(did, [icp, forgedRot])
    expect(folded).toEqual({ ok: false, reason: 'invalid rotate', index: 1 })

    // ROW 1 control: the same rotate with `r` left alone, re-signed by the same key at the same
    // position — so the rejection above is the `r` member and nothing about the re-signing.
    const control = resign({ ...rot.event }, ownerSeed, 0, 1)
    const controlFold = foldLog(did, [icp, control])
    expect(controlFold.ok).toBe(true)
    if (!controlFold.ok) return
    // And the folded recovery is the inception's, which is exactly what `verifyReset` enforces.
    // The state and the verifier no longer tell different stories.
    expect(controlFold.states[1].recovery).toBe(icp.event.r)
  })

  test('ROW 2 (unchanged): a foreign recovery key cannot author a reset — now for one reason', () => {
    const icp = createInception(ownerSeed, 0)
    const did = didFromInception(icp.event)
    const rot = createRotate(ownerSeed, 0, did, icp.event)
    const newRecovery = recoveryKeyOf(newRootSeed)
    const mutated: RotateWithRecovery = {
      ...rot.event,
      r: digestOf(encodeKey(newRecovery.publicKey, 'EdDSA')),
    }
    const forgedRot = resign(mutated, ownerSeed, 0, 1)

    // A reset authored by the key the log's *current* commitment names.
    const newRootReset = createReset(newRootSeed, 0, 1)
    // It has to anchor to THIS did's inception, so rebuild the body against it.
    const body: RotateEvent = { ...newRootReset.event, i: did, p: digestOf(icp.event) }
    const signedByNewRoot: SignedEvent<RotateEvent> = {
      event: body,
      sigs: signEvent(body, [newRecovery.privateKey]),
      recoveryKey: encodeKey(newRecovery.publicKey, 'EdDSA'),
    }
    expect(verifyReset(signedByNewRoot, icp.event)).toBe(false)
    const r = foldLog(did, [icp, forgedRot, signedByNewRoot])
    expect(r.ok).toBe(false)

    // ROW 2 control: the *committed* recovery key authors the same shape of reset against the same
    // inception and it verifies — so the refusal above is the key and not the hand-built body.
    const rootReset = createReset(ownerSeed, 0, 1)
    expect(verifyReset(rootReset, icp.event)).toBe(true)
  })

  test('ROW 3 (closed): the original recovery key authors a reset, and nothing claims otherwise', () => {
    const icp = createInception(ownerSeed, 0)
    const did = didFromInception(icp.event)
    const rot = createRotate(ownerSeed, 0, did, icp.event)
    const newRecovery = recoveryKeyOf(newRootSeed)
    const mutated: RotateWithRecovery = {
      ...rot.event,
      r: digestOf(encodeKey(newRecovery.publicKey, 'EdDSA')),
    }
    const forgedRot = resign(mutated, ownerSeed, 0, 1)

    // The key the owner believes they retired.
    const oldReset = createReset(ownerSeed, 0, 1)
    const r = foldLog(did, [icp, forgedRot, oldReset])
    // The r-carrying rotate no longer folds at all, so the log stops there.
    expect(r).toEqual({ ok: false, reason: 'invalid rotate', index: 1 })

    // ROW 3 control: the same reset by the same key over a log whose rotate carries no `r`. The
    // original recovery key still authors a reset — that is the property, and it is now the only
    // story the state tells, since `KeyState.recovery` is the inception's commitment throughout.
    const plainRot = createRotate(ownerSeed, 0, did, icp.event)
    const control = foldLog(did, [icp, plainRot, oldReset])
    expect(control.ok).toBe(true)
    if (!control.ok) return
    expect(control.states[2].gen).toBe(1)
    expect(control.states.every((state) => state.recovery === icp.event.r)).toBe(true)
  })
})
