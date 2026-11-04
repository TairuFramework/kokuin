import { StatusBar } from 'expo-status-bar'
import { ScrollView, StyleSheet } from 'react-native'

import CryptoBenchmark from './components/CryptoBenchmark'
import SignVerify from './components/SignVerify'
import TwoIdentities from './components/TwoIdentities'

export default function App() {
  return (
    <ScrollView contentContainerStyle={styles.container}>
      <StatusBar style="auto" />
      <SignVerify />
      <TwoIdentities />
      <CryptoBenchmark />
    </ScrollView>
  )
}

const styles = StyleSheet.create({
  container: {
    flexGrow: 1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'center',
    padding: 10,
  },
})
