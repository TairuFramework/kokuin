import { nobleCrypto } from '@kokuin/crypto'
import { cryptoConformance } from '@kokuin/crypto-conformance'
import { createNativeCrypto } from '@kokuin/crypto-native'
import { useEffect, useState } from 'react'
import { Text, View } from 'react-native'

export default function App() {
  const [result, setResult] = useState('Crypto conformance: running')
  useEffect(() => {
    async function run() {
      for (const provider of [nobleCrypto, createNativeCrypto()]) {
        for (const entry of cryptoConformance(provider)) await entry.run()
      }
    }
    void run().then(
      () => setResult('Crypto conformance: OK'),
      (error: unknown) => setResult(`Crypto conformance: FAILED ${String(error)}`),
    )
  }, [])
  return (
    <View style={{ padding: 32, paddingTop: 100 }}>
      <Text>{result}</Text>
    </View>
  )
}
