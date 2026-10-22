import { AppRegistry, type RootTag } from 'react-native'

import App from './App'

AppRegistry.registerComponent('App', () => App)

const root = document.getElementById('root')
if (root == null) throw new Error('Missing #root element')

// Typed against react-native, whose RootTag is opaque; Vite aliases it to
// react-native-web at runtime, which takes the DOM element.
AppRegistry.runApplication('App', {
  initialProps: {},
  rootTag: root as unknown as RootTag,
})
