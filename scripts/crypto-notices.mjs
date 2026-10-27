import { execFileSync } from 'node:child_process'
import { readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

export function collectNotices(packages) {
  return packages
    .map((entry) => {
      const directory = entry.licenseDirectory ?? dirname(entry.manifest_path)
      const files = readdirSync(directory, { withFileTypes: true })
        .filter((file) => file.isFile() && /^(licen[cs]e|copying|notice)/i.test(file.name))
        .map((file) => file.name)
        .sort()
      if (files.length === 0) throw new Error(`Missing dependency licence files: ${entry.name}`)
      const texts = files.map((name) => `${name}\n${readFileSync(join(directory, name), 'utf8')}`)
      return `${entry.name} ${entry.version}\nLicence: ${entry.license}\n\n${texts.join('\n\n')}`
    })
    .join('\n\n------------------------------------------------------------\n\n')
}

export function generateNotices(root) {
  const metadata = JSON.parse(
    execFileSync(
      'pnpm',
      ['exec', 'cargo', 'metadata', '--format-version', '1', '--locked', '--offline'],
      {
        cwd: root,
        encoding: 'utf8',
        maxBuffer: 8 * 1024 * 1024,
      },
    ),
  )
  const nodes = new Map(metadata.resolve.nodes.map((node) => [node.id, node]))
  const visited = new Set()
  function visit(id) {
    if (visited.has(id)) return
    visited.add(id)
    for (const dependency of nodes.get(id).deps) {
      if (dependency.dep_kinds.some((kind) => kind.kind === null)) visit(dependency.pkg)
    }
  }
  visit(metadata.packages.find((entry) => entry.name === 'kokuin-crypto-ffi').id)
  const packages = metadata.packages
    .filter((entry) => entry.source && visited.has(entry.id))
    .sort((left, right) => left.name.localeCompare(right.name))
  const nitroDirectory = join(root, 'node_modules/react-native-nitro-modules')
  const nitro = JSON.parse(readFileSync(join(nitroDirectory, 'package.json'), 'utf8'))
  packages.push({
    ...nitro,
    licenseDirectory: join(root, 'packages/crypto-native/third-party', `nitro-${nitro.version}`),
  })
  const content = `Third-party licences for Kokuin native crypto\n\n${collectNotices(packages)}\n`
  writeFileSync(join(root, 'packages/crypto-native/prebuilt/THIRD_PARTY_LICENSES.txt'), content)
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  generateNotices(resolve(dirname(fileURLToPath(import.meta.url)), '..'))
}
