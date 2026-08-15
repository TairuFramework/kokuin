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

describe('ATTACK: `RotateEvent.r` — the documented recovery-commitment update', () => {
  test('ROW 1: a rotate may replace `r` with NO recovery co-signature and the fold accepts it', () => {
    const icp = createInception(ownerSeed, 0)
    const did = didFromInception(icp.event)
    const rot = createRotate(ownerSeed, 0, did, icp.event)

    const oldRecovery = recoveryKeyOf(ownerSeed)
    const newRecovery = recoveryKeyOf(newRootSeed)
    console.log(
      'inception r === digest(old recovery key):',
      icp.event.r === digestOf(encodeKey(oldRecovery.publicKey, 'EdDSA')),
    )

    // Mutate exactly one field: `r`. Everything else is the generator's own rotate. Re-signed with
    // the same revealed authority key the generator used — no recovery signature is added.
    const mutated: RotateEvent = {
      ...rot.event,
      r: digestOf(encodeKey(newRecovery.publicKey, 'EdDSA')),
    }
    const forgedRot = resign(mutated, ownerSeed, 0, 1)
    console.log('rotate carries exactly one signature:', forgedRot.sigs.length)

    const folded = foldLog(did, [icp, forgedRot])
    console.log('log with r-replacing rotate folds:', folded.ok, folded.ok ? '' : folded.reason)
    expect(folded.ok).toBe(true)
    if (!folded.ok) return
    console.log(
      'state.recovery after the rotate === the NEW commitment:',
      folded.states[1].recovery === mutated.r,
    )
    console.log(
      'state.recovery !== the inception commitment:',
      folded.states[1].recovery !== icp.event.r,
    )
    expect(folded.states[1].recovery).toBe(mutated.r)

    // ROW 1 control: the same rotate with `r` left alone also folds, so nothing incidental about
    // the re-signing explains the acceptance.
    const control = resign({ ...rot.event }, ownerSeed, 0, 1)
    console.log('CONTROL (r untouched) folds:', foldLog(did, [icp, control]).ok)
    expect(foldLog(did, [icp, control]).ok).toBe(true)
  })

  test('ROW 2: the updated commitment is INERT — the new recovery key cannot author a reset', () => {
    const icp = createInception(ownerSeed, 0)
    const did = didFromInception(icp.event)
    const rot = createRotate(ownerSeed, 0, did, icp.event)
    const newRecovery = recoveryKeyOf(newRootSeed)
    const mutated: RotateEvent = {
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
    console.log('verifyReset(new-root reset, inception):', verifyReset(signedByNewRoot, icp.event))
    const r = foldLog(did, [icp, forgedRot, signedByNewRoot])
    console.log('fold of [icp, rot(r=new), reset-by-new-root]:', r.ok, r.ok ? '' : r.reason)
    expect(r.ok).toBe(false)
  })

  test('ROW 3: the ORIGINAL (supposedly replaced) recovery key still authors a valid reset', () => {
    const icp = createInception(ownerSeed, 0)
    const did = didFromInception(icp.event)
    const rot = createRotate(ownerSeed, 0, did, icp.event)
    const newRecovery = recoveryKeyOf(newRootSeed)
    const mutated: RotateEvent = {
      ...rot.event,
      r: digestOf(encodeKey(newRecovery.publicKey, 'EdDSA')),
    }
    const forgedRot = resign(mutated, ownerSeed, 0, 1)

    // The key the owner believes they retired.
    const oldReset = createReset(ownerSeed, 0, 1)
    const r = foldLog(did, [icp, forgedRot, oldReset])
    console.log('fold of [icp, rot(r=new), reset-by-OLD-root]:', r.ok, r.ok ? '' : r.reason)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    console.log("generation after the old key's reset:", r.states[2].gen)
    console.log(
      'state.recovery at head (never consulted):',
      r.states[2].recovery === icp.event.r ? 'back to inception r' : 'other',
    )
    expect(r.states[2].gen).toBe(1)
  })
})
