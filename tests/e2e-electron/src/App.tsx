import { type SignedPayload, type Token, verifyToken } from '@kokuin/token'
import { useState } from 'react'

type Data = {
  test: string
}

function useSignedDID(): [string | null, (keyID: string) => void] {
  const [did, setDID] = useState<string | null>(null)

  const sign = (keyID: string) => {
    window.kokuin
      .sign({ test: 'OK' }, keyID)
      .then((signedToken) => verifyToken<Data>(signedToken))
      .then((token) => {
        setDID((token.payload as SignedPayload).iss)
      })
  }

  return [did, sign]
}

export default function App() {
  const [signedToken, setSignedToken] = useState<string | null>(null)
  const [verifiedToken, setVerifiedToken] = useState<Token<Data> | null>(null)
  const [alphaDID, signAlpha] = useSignedDID()
  const [betaDID, signBeta] = useSignedDID()

  return (
    <>
      {verifiedToken != null ? (
        <p>Verified token: {verifiedToken.payload.test}</p>
      ) : signedToken != null ? (
        <button
          type="button"
          onClick={() => {
            verifyToken<Data>(signedToken).then(setVerifiedToken)
          }}>
          Verify token
        </button>
      ) : (
        <button
          type="button"
          onClick={() => {
            window.kokuin.sign({ test: 'OK' }).then(setSignedToken)
          }}>
          Sign token
        </button>
      )}
      <button type="button" onClick={() => signAlpha('alpha')}>
        Sign alpha
      </button>
      {alphaDID != null ? <p data-testid="alpha-did">Alpha DID: {alphaDID}</p> : null}
      <button type="button" onClick={() => signBeta('beta')}>
        Sign beta
      </button>
      {betaDID != null ? <p data-testid="beta-did">Beta DID: {betaDID}</p> : null}
    </>
  )
}
