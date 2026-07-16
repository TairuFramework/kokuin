import { ExpoKeyStore } from '@kokuin/expo'
import { useEffect, useState } from 'react'
import { Text } from 'react-native'

export default function TwoIdentities() {
  const [alpha, setAlpha] = useState<string | null>(null)
  const [beta, setBeta] = useState<string | null>(null)

  useEffect(() => {
    const store = ExpoKeyStore.open()
    store.provideIdentity('alpha').then((identity) => setAlpha(identity.id))
    store.provideIdentity('beta').then((identity) => setBeta(identity.id))
  }, [])

  return (
    <>
      {alpha ? <Text>Alpha DID: {alpha}</Text> : null}
      {beta ? <Text>Beta DID: {beta}</Text> : null}
    </>
  )
}
