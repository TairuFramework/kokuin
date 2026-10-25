import { createSpikeCrypto } from '@kokuin/crypto-native'
import { useRef, useState } from 'react'
import { Button, Platform, Share, Switch, Text, TextInput, View } from 'react-native'

import { runBenchmarkMatrix } from '../crypto/benchmark'
import { checkSpikeCrypto } from '../crypto/checks'
import { type BenchmarkSample, evaluateGate } from '../crypto/gate'

export default function CryptoBenchmark() {
  const [status, setStatus] = useState('Crypto checks: ready')
  const [device, setDevice] = useState('')
  const [physical, setPhysical] = useState(false)
  const [revision, setRevision] = useState('')
  const [running, setRunning] = useState(false)
  const samples = useRef<Array<BenchmarkSample>>([])
  const abort = useRef<AbortController | null>(null)

  async function check() {
    setRunning(true)
    try {
      await checkSpikeCrypto(createSpikeCrypto())
      setStatus('Crypto checks: OK')
    } catch (error) {
      setStatus(`Crypto checks: FAIL ${String(error)}`)
    } finally {
      setRunning(false)
    }
  }

  async function benchmark() {
    if (Platform.OS !== 'ios' && Platform.OS !== 'android') return
    const controller = new AbortController()
    abort.current = controller
    samples.current = []
    setRunning(true)
    try {
      const native = createSpikeCrypto()
      await checkSpikeCrypto(native)
      await runBenchmarkMatrix({
        native,
        signal: controller.signal,
        metadata: {
          platform: Platform.OS,
          device,
          physical,
          revision,
          release: !__DEV__,
          hermes: 'HermesInternal' in globalThis,
        },
        async onSample(sample, completed, total) {
          samples.current.push(sample)
          setStatus(`Benchmark ${completed}/${total}`)
        },
      })
      setStatus(`Benchmark gate: ${evaluateGate(samples.current).status}`)
    } catch (error) {
      setStatus(`Benchmark stopped: ${String(error)}`)
    } finally {
      setRunning(false)
    }
  }

  async function exportSamples() {
    await Share.share({
      message: JSON.stringify({ samples: samples.current, gate: evaluateGate(samples.current) }),
    })
  }

  return (
    <View style={{ gap: 8, padding: 12 }}>
      <Text>{status}</Text>
      <Button
        title="Run crypto checks"
        disabled={running}
        onPress={() => {
          void check()
        }}
      />
      <TextInput
        accessibilityLabel="Benchmark device model and OS"
        placeholder="Device model and OS"
        value={device}
        onChangeText={setDevice}
      />
      <TextInput
        accessibilityLabel="Benchmark source revision"
        placeholder="Exact source commit SHA"
        value={revision}
        onChangeText={setRevision}
      />
      <Text>Physical phone (leave off for simulators and emulators)</Text>
      <Switch
        accessibilityLabel="Physical benchmark phone"
        value={physical}
        onValueChange={setPhysical}
      />
      <Text>
        Release Hermes builds only. The complete matrix can take hours. Export partial results
        before leaving the app.
      </Text>
      <Button
        title="Run benchmark matrix"
        disabled={running || __DEV__ || !device.trim() || !revision.trim()}
        onPress={() => {
          void benchmark()
        }}
      />
      <Button title="Stop benchmark" disabled={!running} onPress={() => abort.current?.abort()} />
      <Button
        title="Export benchmark samples"
        disabled={running}
        onPress={() => {
          void exportSamples()
        }}
      />
    </View>
  )
}
