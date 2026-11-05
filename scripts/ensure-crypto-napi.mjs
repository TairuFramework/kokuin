// Puts the attested binaries of this exact commit into their platform packages before a release.
// They cannot be built on one machine, so CI builds them. Publishing without them would ship empty
// packages, so any missing or unverifiable binary stops the release.
import { execFileSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const WORKFLOW = 'crypto-napi-prebuilds.yml'
const REPOSITORY = 'TairuFramework/kokuin'

export function platformTargets(root) {
  return readdirSync(join(root, 'packages'))
    .filter((name) => name.startsWith('crypto-napi-'))
    .map((name) => name.slice('crypto-napi-'.length))
    .sort()
}

function isPublished(run, name, version) {
  try {
    return run('npm', ['view', `${name}@${version}`, 'version']).trim() === version
  } catch {
    return false
  }
}

export function ensureCryptoNapi(root, run) {
  const targets = platformTargets(root)
  const allPublished = targets.every((target) => {
    const directory = join(root, 'packages', `crypto-napi-${target}`)
    const { name, version } = JSON.parse(readFileSync(join(directory, 'package.json'), 'utf8'))
    return isPublished(run, name, version)
  })
  if (allPublished) return false

  const commit = run('git', ['rev-parse', 'HEAD']).trim()
  const [latest] = JSON.parse(
    run('gh', [
      'run',
      'list',
      '--repo',
      REPOSITORY,
      '--workflow',
      WORKFLOW,
      '--commit',
      commit,
      '--status',
      'success',
      '--limit',
      '1',
      '--json',
      'databaseId',
    ]),
  )
  if (latest == null) {
    throw new Error(
      `No successful ${WORKFLOW} run for ${commit}. Run: gh workflow run ${WORKFLOW} --ref main`,
    )
  }
  for (const target of targets) {
    const directory = join(root, 'packages', `crypto-napi-${target}`)
    const binary = join(directory, `kokuin-crypto-napi.${target}.node`)
    run('gh', [
      'run',
      'download',
      String(latest.databaseId),
      '--repo',
      REPOSITORY,
      '--name',
      `crypto-napi-${target}`,
      '--dir',
      directory,
    ])
    if (!existsSync(binary)) throw new Error(`The artifact did not contain ${binary}`)
    run('gh', ['attestation', 'verify', binary, '--repo', REPOSITORY])
  }
  return true
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
  const fetched = ensureCryptoNapi(root, (command, args) => {
    return execFileSync(command, args, { cwd: root, encoding: 'utf8' })
  })
  console.log(
    fetched ? 'Fetched and verified crypto-napi binaries' : 'crypto-napi binaries are published',
  )
}
