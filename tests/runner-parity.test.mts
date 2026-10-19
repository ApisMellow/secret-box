// bin/keychain-env against tests/env-cases.ts, with `security` stubbed out:
// a copy of the runner whose SECURITY points at a script that answers -g as a
// printable password and -w with the item it was asked for. No Keychain is
// touched. Run: node --experimental-strip-types tests/runner-parity.test.mts
import { spawnSync } from 'node:child_process'
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { envPointers } from '../hooks/keychain.js'
import { ENV_CASES, type Found } from './env-cases.ts'

const here = dirname(fileURLToPath(import.meta.url))
const dir = mkdtempSync(join(tmpdir(), 'runner-parity-'))
try {
  const stub = join(dir, 'security')
  writeFileSync(
    stub,
    [
      '#!/bin/sh',
      's= a= mode=',
      'while [ $# -gt 0 ]; do',
      '  case $1 in -s) s=$2; shift 2 ;; -a) a=$2; shift 2 ;; -g) mode=g; shift ;; -w) mode=w; shift ;; *) shift ;; esac',
      'done',
      `if [ "$mode" = g ]; then echo 'password: "stub"' >&2; else printf 'stub|%s|%s\\n' "$s" "$a"; fi`,
    ].join('\n') + '\n',
  )
  chmodSync(stub, 0o755)
  const runner = readFileSync(join(here, '../bin/keychain-env'), 'utf8')
  if (!runner.includes('\nSECURITY=/usr/bin/security\n')) throw new Error('the runner no longer sets SECURITY=/usr/bin/security')
  const copy = join(dir, 'keychain-env')
  writeFileSync(copy, runner.replace('\nSECURITY=/usr/bin/security\n', `\nSECURITY=${stub}\n`))
  chmodSync(copy, 0o755)

  const key = (f: Found[]) => JSON.stringify(f.map(([n, s, a]) => [n, s, a ?? '']).sort())
  let failed = 0
  for (const c of ENV_CASES) {
    const file = join(dir, 'case.env')
    writeFileSync(file, c.text)
    // The runner as a user runs it: a UTF-8 locale it must not parse by
    const r = spawnSync('/bin/bash', [copy, '--env-file', file, '--', '/usr/bin/env'], { env: { PATH: '/usr/bin:/bin', LANG: 'en_US.UTF-8', LC_ALL: 'en_US.UTF-8' }, encoding: 'utf8' })
    const bash: Found[] = r.stdout
      .split('\n')
      .filter((l) => l.includes('=stub|'))
      .map((l) => {
        const [name, rest] = [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]
        const [, service, account] = rest.split('|')
        return [name, service!, account || undefined] as Found
      })
    const js: Found[] = envPointers(c.text).map(([name, p]: [string, { service: string; account?: string }]) => [name, p.service, p.account])
    // The caller's locale reaches the command as it was
    const lcAll = r.stdout.split('\n').find((l) => l.startsWith('LC_ALL='))
    const ok = key(bash) === key(c.pointers) && key(js) === key(c.pointers) && (r.status !== 0 || lcAll === 'LC_ALL=en_US.UTF-8')
    if (!ok) failed++
    console.log(`${ok ? 'ok  ' : 'FAIL'} ${c.name}: bash ${key(bash)} js ${key(js)}${r.status ? ` (runner exit ${r.status})` : ''}`)
  }
  console.log(failed ? `${failed} of ${ENV_CASES.length} differ` : `ok  ${ENV_CASES.length} cases, bash and js agree`)
  if (failed) process.exitCode = 1
} finally {
  rmSync(dir, { recursive: true, force: true })
}
