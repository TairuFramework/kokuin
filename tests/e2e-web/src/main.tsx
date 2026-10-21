import { AppRegistry } from 'react-native'

import App from './App'

AppRegistry.registerComponent('App', () => App)

const rootTag = document.getElementById('root')
if (rootTag == null) throw new Error('Missing #root element')

AppRegistry.runApplication('App', { rootTag })
