import { provideSigningIdentity } from '@kokuin/browser'
import { type Token, verifyToken } from '@kokuin/token'
import { useEffect, useState } from 'react'
import { Button, StyleSheet, Text, View } from 'react-native'

const identityPromise = provideSigningIdentity('test')
const durableIdentityPromise = provideSigningIdentity('durable')
const alphaIdentityPromise = provideSigningIdentity('alpha')
const betaIdentityPromise = provideSigningIdentity('beta')

type Data = {
  test: string
}

export default function App() {
  const [signedToken, setSignedToken] = useState<Token<Data> | null>(null)
  const [verifiedToken, setVerifiedToken] = useState<Token<Data> | null>(null)
  const [durableDID, setDurableDID] = useState<string | null>(null)
  const [alphaDID, setAlphaDID] = useState<string | null>(null)
  const [betaDID, setBetaDID] = useState<string | null>(null)

  useEffect(() => {
    durableIdentityPromise.then((identity) => setDurableDID(identity.id))
    alphaIdentityPromise.then((identity) => setAlphaDID(identity.id))
    betaIdentityPromise.then((identity) => setBetaDID(identity.id))
  }, [])

  let button = null
  if (signedToken == null) {
    button = (
      <Button
        title="Sign token"
        onPress={() => {
          identityPromise
            .then((identity) => identity.signToken({ test: 'OK' }))
            .then(setSignedToken)
        }}
      />
    )
  } else if (verifiedToken == null) {
    button = (
      <Button
        title="Verify token"
        onPress={() => {
          verifyToken(signedToken).then(setVerifiedToken)
        }}
      />
    )
  }
  return (
    <View style={styles.container}>
      {button}
      {verifiedToken ? <Text>Verified token: {verifiedToken.payload.test}</Text> : null}
      {durableDID ? <Text testID="durable-did">{durableDID}</Text> : null}
      {alphaDID ? <Text testID="alpha-did">{alphaDID}</Text> : null}
      {betaDID ? <Text testID="beta-did">{betaDID}</Text> : null}
    </View>
  )
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'center',
    padding: 10,
  },
})
