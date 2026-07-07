import { StatusBar } from 'expo-status-bar'
import { StyleSheet, View } from 'react-native'

import SignVerify from './components/SignVerify'
import TwoIdentities from './components/TwoIdentities'

export default function App() {
  return (
    <View style={styles.container}>
      <StatusBar style="auto" />
      <SignVerify />
      <TwoIdentities />
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
