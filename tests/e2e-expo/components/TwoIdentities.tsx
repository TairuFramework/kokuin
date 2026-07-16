import { ExpoKeyStore } from '@kokuin/expo'
import { useState } from 'react'
import { Text } from 'react-native'

export default function TwoIdentities() {
  const [alpha] = useState(() => ExpoKeyStore.open().provideIdentitySync('alpha'))
  const [beta] = useState(() => ExpoKeyStore.open().provideIdentitySync('beta'))

  return (
    <>
      <Text>Alpha DID: {alpha.id}</Text>
      <Text>Beta DID: {beta.id}</Text>
    </>
  )
}
