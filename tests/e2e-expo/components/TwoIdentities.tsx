import { provideFullIdentity } from '@kokuin/expo'
import { useState } from 'react'
import { Text } from 'react-native'

export default function TwoIdentities() {
  const [alpha] = useState(() => provideFullIdentity('alpha'))
  const [beta] = useState(() => provideFullIdentity('beta'))

  return (
    <>
      <Text>Alpha DID: {alpha.id}</Text>
      <Text>Beta DID: {beta.id}</Text>
    </>
  )
}
