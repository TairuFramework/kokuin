import { ExpoKeyStore } from '@kokuin/expo'
import type { FullIdentity, SignedToken, Token } from '@kokuin/token'
import { verifyToken } from '@kokuin/token'
import { useEffect, useState } from 'react'
import { Button, Text } from 'react-native'

type Data = {
  test: string
}

export default function SignVerify() {
  const [identity, setIdentity] = useState<FullIdentity | null>(null)
  const [signedToken, setSignedToken] = useState<SignedToken<Data> | null>(null)
  const [verifiedToken, setVerifiedToken] = useState<Token<Data> | null>(null)

  useEffect(() => {
    ExpoKeyStore.open().provideIdentity('test').then(setIdentity)
  }, [])

  if (verifiedToken) {
    return <Text>Verified token: {verifiedToken.payload.test}</Text>
  }
  if (signedToken) {
    return (
      <Button
        title="Verify token"
        onPress={() => {
          verifyToken(signedToken).then(setVerifiedToken)
        }}
      />
    )
  }
  if (identity) {
    return (
      <Button
        title="Sign token"
        onPress={() => {
          identity.signToken({ test: 'OK' }).then(setSignedToken)
        }}
      />
    )
  }
  return null
}
