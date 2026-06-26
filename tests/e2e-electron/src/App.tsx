import { type Token, verifyToken } from '@kokuin/token'
import { useState } from 'react'

type Data = {
  test: string
}

export default function App() {
  const [signedToken, setSignedToken] = useState<string | null>(null)
  const [verifiedToken, setVerifiedToken] = useState<Token<Data> | null>(null)

  if (verifiedToken != null) {
    return <p>Verified token: {verifiedToken.payload.test}</p>
  }
  if (signedToken != null) {
    return (
      <button
        type="button"
        onClick={() => {
          verifyToken<Data>(signedToken).then(setVerifiedToken)
        }}>
        Verify token
      </button>
    )
  }
  return (
    <button
      type="button"
      onClick={() => {
        window.kokuin.sign({ test: 'OK' }).then(setSignedToken)
      }}>
      Sign token
    </button>
  )
}
