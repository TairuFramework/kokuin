import { execFileSync } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { artifactsCurrent } from './crypto-artifacts.mjs'

export function ensureCryptoNative(root, build) {
  for (const platform of ['ios', 'android']) {
    if (artifactsCurrent(root, platform)) continue
    build(platform)
    if (!artifactsCurrent(root, platform)) {
      throw new Error(`${platform} crypto binaries are still stale after a rebuild`)
    }
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
  ensureCryptoNative(root, (platform) => {
    console.log(`Rebuilding ${platform} crypto binaries`)
    execFileSync(process.execPath, [join(root, 'scripts/build-crypto-native.mjs'), platform], {
      cwd: root,
      stdio: 'inherit',
    })
  })
}
