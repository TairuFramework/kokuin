// Runs from a platform package's prepublishOnly, so every publish path gets the attested binary of
// this exact commit. They cannot be built on one machine, so CI builds them. Any failure stops the
// publish: npm versions cannot be replaced afterwards.
import { execFileSync } from 'node:child_process'
import { copyFileSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const WORKFLOW = 'crypto-napi-prebuilds.yml'
const REPOSITORY = 'TairuFramework/kokuin'

export function ensureCryptoNapi(directory, run) {
  const { main } = JSON.parse(readFileSync(join(directory, 'package.json'), 'utf8'))
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
      `No successful ${WORKFLOW} run for ${commit}. Wait for it, or run: gh workflow run ${WORKFLOW} --ref main`,
    )
  }
  const downloads = mkdtempSync(join(tmpdir(), 'crypto-napi-artifact-'))
  try {
    const binary = join(downloads, main)
    run('gh', [
      'run',
      'download',
      String(latest.databaseId),
      '--repo',
      REPOSITORY,
      '--name',
      `crypto-napi-${basename(directory)}`,
      '--dir',
      downloads,
    ])
    run('gh', ['attestation', 'verify', binary, '--repo', REPOSITORY])
    // Overwrites: a binary left by an earlier release is not this commit's.
    copyFileSync(binary, join(directory, main))
  } finally {
    rmSync(downloads, { recursive: true, force: true })
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const directory = process.cwd()
  ensureCryptoNapi(directory, (command, args) => {
    return execFileSync(command, args, { cwd: directory, encoding: 'utf8' })
  })
}
