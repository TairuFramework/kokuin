// Puts the attested binaries of this exact commit into their platform packages before a release.
// They cannot be built on one machine, so CI builds them. `napi artifacts` then fails unless every
// configured target has its binary, so a missing one stops the release before anything publishes.
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const WORKFLOW = 'crypto-napi-prebuilds.yml'
const REPOSITORY = 'TairuFramework/kokuin'

export function platformTargets(root) {
  return readdirSync(join(root, 'packages/crypto-napi/npm')).sort()
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
    const manifest = join(root, 'packages/crypto-napi/npm', target, 'package.json')
    const { name, version } = JSON.parse(readFileSync(manifest, 'utf8'))
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
  const downloads = mkdtempSync(join(tmpdir(), 'crypto-napi-artifacts-'))
  try {
    for (const target of targets) {
      const binary = join(downloads, `kokuin-crypto-napi.${target}.node`)
      run('gh', [
        'run',
        'download',
        String(latest.databaseId),
        '--repo',
        REPOSITORY,
        '--name',
        `crypto-napi-${target}`,
        '--dir',
        downloads,
      ])
      run('gh', ['attestation', 'verify', binary, '--repo', REPOSITORY])
    }
    run('pnpm', [
      '--filter',
      '@kokuin/crypto-napi',
      'exec',
      'napi',
      'artifacts',
      '--output-dir',
      downloads,
      '--npm-dir',
      'npm',
    ])
  } finally {
    rmSync(downloads, { recursive: true, force: true })
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
