import { expect, test } from 'claude-code/testing'

import { dumpedItems, envPointers, envValue, keychainReads, looksLikeKey, parsePointer, pointerTo, SECURITY } from '../hooks/keychain'
import { ENV_CASES } from './env-cases'
import { call, CWD, dumpOf, hex, hexOf, LIST, mac, MIGRATE, registered, securityCalls, TAG, USE, wOutput, type Item, type Opts } from './fake-mac'

const NAMES_ONLY = "Returns key names only and never fetches or returns any key's value."
// A Stripe-shaped fake key the detector hides on sight, built at run time
const STRIPE = 'sk_' + 'live_' + 'A1b2C3d4E5f6G7h8J9k0L1m2'
const U = 'unknown'
const reads = (command: string) => keychainReads(command, { USER: 'tester', HOME: '/Users/tester' }).map((r: any) => (r.unknown ? U : r))

// ------------------------------------------------------------ pointer syntax

const POINTERS: [string, unknown][] = [
  ['keychain:openai', { service: 'openai' }],
  ['keychain:openai?account=work', { service: 'openai', account: 'work' }],
  ['keychain:myapp/STRIPE_SECRET_KEY', { service: 'myapp/STRIPE_SECRET_KEY' }],
  ['keychain:my%20app/KEY?account=ops%40acme', { service: 'my app/KEY', account: 'ops@acme' }],
  ['keychain:a%3Fb%23c%25d%26e', { service: 'a?b#c%d&e' }],
  ['keychain:', undefined],
  ['keychain:a b', undefined],
  ['keychain:a?account=', undefined],
  ['keychain:a?acct=b', undefined],
  ['keychain:a?account=b&x=y', undefined],
  ['keychain:a%0Ab', undefined],
  ['keychain:a%7F', undefined],
  ['keychain:caf%C3%A9', undefined],
  ['keychain:a%zz', undefined],
  ['keychain:a"b', undefined],
  ['Keychain:a', undefined],
  [STRIPE, undefined],
]
for (const [text, pointer] of POINTERS) {
  test(`parsePointer: ${JSON.stringify(text)}`, async () => {
    expect(parsePointer(text)).toEqual(pointer)
  })
}

test('pointerTo writes a pointer parsePointer reads back, and refuses what a pointer cannot carry', async () => {
  for (const [service, account] of [['openai', ''], ['myapp/KEY', 'work'], ['my app?#%&"\'', 'a b@c'], ['x', '']]) {
    expect(parsePointer(pointerTo(service!, account!)!)).toEqual({ service, ...(account ? { account } : {}) })
  }
  expect(pointerTo('café', '')).toBeUndefined()
  expect(pointerTo('ok', 'tab\there')).toBeUndefined()
})

const VALUES: [string, string][] = [
  ['keychain:x', 'keychain:x'],
  ['"keychain:x"', 'keychain:x'],
  ["'keychain:x'", 'keychain:x'],
  ['keychain:x # a note', 'keychain:x'],
  ['"keychain:x" # a note', 'keychain:x'],
  ['"a # b"', 'a # b'],
  ['a#b', 'a#b'],
  ['  spaced  ', 'spaced'],
  ['', ''],
]
for (const [raw, value] of VALUES) {
  test(`envValue: ${JSON.stringify(raw)}`, async () => {
    expect(envValue(raw)).toBe(value)
  })
}

test('envPointers finds pointers under export, quotes, comments and CRLF, and nothing else', async () => {
  const text = [
    '# OPENAI_API_KEY=keychain:commented',
    'export OPENAI_API_KEY=keychain:openai?account=work\r',
    'DB_PASSWORD="keychain:myapp/DB_PASSWORD" # db',
    'PORT=3000',
    `STRIPE_SECRET_KEY=${STRIPE}`,
    'BROKEN=keychain:has space',
  ].join('\n')
  expect(envPointers(text)).toEqual([
    ['OPENAI_API_KEY', { service: 'openai', account: 'work' }],
    ['DB_PASSWORD', { service: 'myapp/DB_PASSWORD' }],
  ])
})

// -------------------------------------------------------- pointers stay readable

test('pointers in a .env file read back as written, while a plaintext key is hidden', async ($, on) => {
  const text = `OPENAI_API_KEY=keychain:openai?account=work\nDB_PASSWORD="keychain:myapp/DB_PASSWORD"\nSTRIPE_SECRET_KEY=${STRIPE}\nPORT=3000\n`
  mac(on, { files: { '.env': text }, output: text })
  const r = String((await call($, { tool: 'Read', file_path: `${CWD}/.env` })).result)
  expect(r).toContain('OPENAI_API_KEY=keychain:openai?account=work')
  expect(r).toContain('DB_PASSWORD="keychain:myapp/DB_PASSWORD"')
  expect(r).not.toContain(STRIPE)
  expect(r).toContain('PORT=3000')
  // Learning that .env did not make the pointer text a secret either
  const later = String((await call($, { tool: 'Bash', command: 'grep -r keychain: src' })).result)
  expect(later).toContain('OPENAI_API_KEY=keychain:openai?account=work')
  expect(later).toContain('DB_PASSWORD="keychain:myapp/DB_PASSWORD"')
  expect(later).not.toContain(STRIPE)
})

// --------------------------------------------------------------------- nudge

const plaintextEnv = { '.env': `STRIPE_SECRET_KEY=${STRIPE}\nPORT=3000\n` }
const pointerEnv = { '.env': 'OPENAI_API_KEY=keychain:openai\n' }

async function prompts($: any, on: any, opts: Opts, count: number) {
  const contexts: string[][] = []
  // The test's own hooks go in before it first calls $
  on('prompt.submit', (_$: unknown, e: { text: string; context?: string[] }) => {
    contexts.push([...(e.context ?? [])])
    return { text: e.text }
  })
  await registered($, on, opts)
  for (let i = 0; i < count; i++) await $.prompt.submit({ text: `prompt ${i}`, wait: false, origin: { kind: 'composer' } })
  return contexts
}

test('a session that starts beside .env files gets the nudge with its first prompt, and only then', async ($, on) => {
  const [first, second] = await prompts($, on, { files: plaintextEnv }, 2)
  expect(first!.join('\n')).toContain('secret-box is installed')
  expect(first!.join('\n')).toContain('NAME=keychain:SERVICE?account=ACCOUNT')
  expect(first!.join('\n')).toContain('/bin/keychain-env -- COMMAND')
  expect(first!.join('\n')).toContain('secret-box:secrets')
  // The .env holds a plaintext key, so migration is offered
  expect(first!.join('\n')).toContain('.env holds plaintext keys')
  expect(second).toEqual([])
})

test('a .env of pointers gets the nudge without the migration offer', async ($, on) => {
  const [first] = await prompts($, on, { files: pointerEnv }, 1)
  expect(first!.join('\n')).toContain('secret-box is installed')
  expect(first!.join('\n')).not.toContain('migrate_env_to_keychain')
})

test('no .env and no key: no nudge', async ($, on) => {
  const [first] = await prompts($, on, {}, 1)
  expect(first).toEqual([])
  const r = await call($, { tool: 'Bash', command: 'ls' })
  expect(r.context).toBeUndefined()
})

test('the first tool call that touches a .env file carries the nudge, once', async ($, on) => {
  mac(on, { output: 'PORT=3000' })
  const first = await call($, { tool: 'Read', file_path: `${CWD}/.env.local` })
  expect((first.context ?? []).join('\n')).toContain('secret-box is installed')
  const second = await call($, { tool: 'Read', file_path: `${CWD}/.env.local` })
  expect(second.context).toBeUndefined()
})

test('the first result with a key hidden from it carries the nudge', async ($, on) => {
  mac(on, { output: `config: ${STRIPE}` })
  const r = await call($, { tool: 'Bash', command: 'cat config.yml' })
  expect(String(r.result)).not.toContain(STRIPE)
  expect((r.context ?? []).join('\n')).toContain('secret-box is installed')
})

test('off macOS there is no nudge', async ($, on) => {
  mac(on, { platform: 'Linux', output: `config: ${STRIPE}` })
  expect((await call($, { tool: 'Read', file_path: `${CWD}/.env` })).context).toBeUndefined()
})

// ------------------------------------------------------- use_secret precedence

const items = (): Item[] => [
  { s: 'OPENAI_API_KEY', value: hex(1) },
  { s: 'openai', a: 'work', value: hex(2) },
  { s: 'openai', a: 'home', value: hex(3) },
]
async function restoredValue($: any, opts: Opts, input: Record<string, unknown>) {
  const r = String((await call($, { tool: USE, ...input })).result)
  const tag = r.match(TAG)
  if (!tag) return r
  await call($, { tool: 'Write', file_path: `${CWD}/k.txt`, content: tag[0] })
  return String(opts.seen!.at(-1)!.content)
}

test('use_secret: a .env variable whose value is a pointer names the item, ahead of a service of the same name', async ($, on) => {
  const opts: Opts = { items: items(), files: { '.env': 'OPENAI_API_KEY=keychain:openai?account=work\n' }, seen: [], argvs: [] }
  mac(on, opts)
  const answer = await call($, { tool: USE, service: 'OPENAI_API_KEY' })
  expect(String(answer.result)).toContain('through the OPENAI_API_KEY pointer in .env')
  expect((answer.context ?? []).join('\n')).toContain('/bin/keychain-env -- COMMAND')
  expect(securityCalls(opts.argvs!).at(-1)).toEqual([SECURITY, 'find-generic-password', '-s', 'openai', '-a', 'work', '-g'])
  expect(await restoredValue($, opts, { service: 'OPENAI_API_KEY' })).toBe(hex(2))
})

test('use_secret: with an account given, the name is always a service', async ($, on) => {
  const opts: Opts = { items: [...items(), { s: 'OPENAI_API_KEY', a: 'ci', value: hex(4) }], files: { '.env': 'OPENAI_API_KEY=keychain:openai?account=work\n' }, seen: [] }
  mac(on, opts)
  expect(await restoredValue($, opts, { service: 'OPENAI_API_KEY', account: 'ci' })).toBe(hex(4))
})

test('use_secret: a name no .env file holds is a service', async ($, on) => {
  const opts: Opts = { items: items(), files: { '.env': 'OTHER=keychain:openai?account=home\n' }, seen: [] }
  mac(on, opts)
  expect(await restoredValue($, opts, { service: 'OPENAI_API_KEY' })).toBe(hex(1))
})

test('use_secret: .env files that point one name at different items are not guessed between', async ($, on) => {
  mac(on, { items: items(), files: { '.env': 'OPENAI_API_KEY=keychain:openai?account=work\n', '.env.local': 'OPENAI_API_KEY=keychain:openai?account=home\n' } })
  const r = String((await call($, { tool: USE, service: 'OPENAI_API_KEY' })).result)
  expect(r).toContain('points to different Keychain items in .env, .env.local')
  expect(r).not.toMatch(TAG)
})

test('use_secret: .env files that agree are fine', async ($, on) => {
  const opts: Opts = { items: items(), files: { '.env': 'OPENAI_API_KEY=keychain:openai?account=home\n', '.env.local': "OPENAI_API_KEY='keychain:openai?account=home'\n" }, seen: [] }
  mac(on, opts)
  expect(await restoredValue($, opts, { service: 'OPENAI_API_KEY' })).toBe(hex(3))
})

// ----------------------------------------------------------- the runner

const RUNNER_READS: [string, string, unknown[]][] = [
  ['by name', 'keychain-env -- npm start', [{ envFiles: ['.env'] }]],
  ['by path, with --env-file', '/opt/secret-box/bin/keychain-env --env-file .env.local -- node app.js', [{ envFiles: ['.env.local'] }]],
  ['two env files, = and ~', 'keychain-env --env-file=.env.prod --env-file ~/.env.shared -- x', [{ envFiles: ['.env.prod', '/Users/tester/.env.shared'] }]],
  ['and the command it runs reads the Keychain', 'keychain-env -- security find-generic-password -s svc -w', [{ envFiles: ['.env'] }, { kind: 'generic', criteria: [['-s', 'svc']], keychains: [] }]],
  ['inside a keyword and a pipe', 'if true; then keychain-env -- node a.js | tee log; fi', [{ envFiles: ['.env'] }]],
  ['after cd', 'cd app && keychain-env -- npm start', [U]],
  ['run by bash', 'bash keychain-env -- npm start', [U]],
  ['run by sudo', 'sudo /opt/bin/keychain-env -- npm start', [U]],
  ['without --', 'keychain-env npm start', [U]],
  ['an --env-file only the shell knows', 'keychain-env --env-file "$F" -- x', [U]],
  ['named in quotes', 'echo "keychain-env -- x"', [U]],
  ['looked at, not run', 'cat bin/keychain-env', []],
  ['made executable', 'chmod +x /opt/secret-box/bin/keychain-env', []],
]
for (const [name, command, expected] of RUNNER_READS) {
  test(`keychainReads, the runner: ${name}`, async () => {
    expect(reads(command)).toEqual(expected)
  })
}

const env2 = { '.env': 'OPENAI_API_KEY=keychain:openai?account=work\nPORT=3000\nDB_PASSWORD="keychain:myapp/DB_PASSWORD"\n' }
const runnerItems = (): Item[] => [
  { s: 'openai', a: 'work', value: hex(5) },
  { s: 'myapp/DB_PASSWORD', a: 'tester', value: hex(6) },
]

test('the runner: every pointer it will resolve is loaded before it runs, so what the app prints comes back hidden', async ($, on) => {
  const opts: Opts = { items: runnerItems(), files: env2, argvs: [], log: [], output: `db=${hex(6)} key=${hex(5)}\n` }
  mac(on, opts)
  const r = String((await call($, { tool: 'Bash', command: '/opt/secret-box/bin/keychain-env -- node app.js' })).result)
  expect(r).not.toContain(hex(5))
  expect(r).not.toContain(hex(6))
  expect(securityCalls(opts.argvs!)).toEqual([
    [SECURITY, 'find-generic-password', '-s', 'openai', '-a', 'work', '-g'],
    [SECURITY, 'find-generic-password', '-s', 'myapp/DB_PASSWORD', '-g'],
  ])
  expect(opts.log!.at(-1)).toBe('tool Bash')
})

test('the runner: --env-file names the only file it reads', async ($, on) => {
  const opts: Opts = { items: runnerItems(), files: { ...env2, '.env.ci': 'DB_PASSWORD=keychain:myapp/DB_PASSWORD\n' }, argvs: [] }
  mac(on, opts)
  await call($, { tool: 'Bash', command: 'keychain-env --env-file .env.ci -- node app.js' })
  expect(securityCalls(opts.argvs!)).toEqual([[SECURITY, 'find-generic-password', '-s', 'myapp/DB_PASSWORD', '-g']])
})

test('the runner: with no .env there is nothing to load, and the command runs', async ($, on) => {
  const opts: Opts = { argvs: [] }
  mac(on, opts)
  expect(await call($, { tool: 'Bash', command: 'keychain-env -- node app.js' })).toMatchObject({ result: 'ran' })
  expect(securityCalls(opts.argvs!)).toEqual([])
})

for (const [name, command, opts] of [
  ['after cd', 'cd app && keychain-env -- npm start', {}],
  ['a pointer to a locked keychain', 'keychain-env -- npm start', { files: env2, fail: { exitCode: 36, stdout: '', stderr: 'locked' } }],
  ['a value too short to hide', 'keychain-env -- npm start', { files: { '.env': 'PIN=keychain:pin\n' }, items: [{ s: 'pin', value: 'ab12' }] }],
] as [string, string, Opts][]) {
  test(`the runner, refuseUnmaskable on: ${name} is refused`, { options: { refuseUnmaskable: true } }, async ($, on) => {
    mac(on, { ...opts })
    expect(String((await call($, { tool: 'Bash', command })).deny)).toContain("can't be hidden")
  })
  test(`the runner, refuseUnmaskable off: ${name} runs`, async ($, on) => {
    mac(on, { ...opts })
    expect((await call($, { tool: 'Bash', command })).deny).toBeUndefined()
  })
}

// ------------------------------------------------------------- commit guard

const pointersOnly = 'OPENAI_API_KEY=keychain:openai?account=work\nPORT=3000\nDB_PASSWORD=\n'
// The item those pointers name, so the guard finds it in the Keychain
const held = (): Item[] => [{ s: 'openai', a: 'work', value: hex(30) }]
const GUARD: [string, Opts, string, boolean][] = [
  ['git add of a .env of pointers', { files: { '.env': pointersOnly }, items: held() }, 'git add .env', false],
  ['git add of a .env with a plaintext key', { files: { '.env': `${pointersOnly}STRIPE_SECRET_KEY=${STRIPE}\n` } }, 'git add .env', true],
  ['git add of pointers beside a password in a URL', { files: { '.env': `${pointersOnly}DATABASE_URL=postgres://app:Tr0ub4dor-3-horse@db.internal:5432/app\n` } }, 'git add .env', true],
  ['git add of a .env with no pointer at all', { files: { '.env': 'PORT=3000\n' } }, 'git add .env', true],
  ['git add -C of a .env of pointers', { files: { '.env': pointersOnly } }, 'git -C app add .env', true],
  ['git add of a .env that cannot be read', {}, 'git add .env', true],
  ['commit of a staged .env of pointers', { git: { index: '.env\n', show: { '.env': pointersOnly } }, items: held() }, 'git commit -m wip', false],
  ['commit of a staged .env with a key', { git: { index: '.env\n', show: { '.env': `STRIPE_SECRET_KEY=${STRIPE}\n` } } }, 'git commit -m wip', true],
  ['commit -a of a changed .env of pointers', { files: { '.env': pointersOnly }, git: { tree: '.env\n' }, items: held() }, 'git commit -am wip', false],
  ['commit -a of a changed .env with a key', { files: { '.env': `STRIPE_SECRET_KEY=${STRIPE}\n` }, git: { tree: '.env\n' } }, 'git commit -am wip', true],
  ['commit -a when the staged copy has pointers but the file has a key', { files: { '.env': `STRIPE_SECRET_KEY=${STRIPE}\n` }, git: { index: '.env\n', tree: '.env\n', show: { '.env': pointersOnly } } }, 'git commit -am wip', true],
]
for (const [name, opts, command, isBlocked] of GUARD) {
  test(`commit guard: ${name} is ${isBlocked ? 'blocked' : 'allowed'}`, async ($, on) => {
    mac(on, opts)
    expect(Boolean((await call($, { tool: 'Bash', command })).deny)).toBe(isBlocked)
  })
}

// ------------------------------------------------------------ list_key_names

test('dumpedItems reads real dump-keychain output: genp items, quoted and hex attributes', async () => {
  // Attribute lines as security printed them for a test item on macOS
  const real = [
    'keychain: "/Users/tester/Library/Keychains/login.keychain-db"',
    'version: 512',
    'class: "genp"',
    'attributes:',
    '    0x00000007 <blob>="secret-box-test"',
    '    0x00000008 <blob>=<NULL>',
    '    "acct"<blob>="sbt-first"',
    '    "cdat"<timedate>=0x32303236313031363137303332325A00  "20261016170322Z\\000"',
    '    "crtr"<uint32>=<NULL>',
    '    "icmt"<blob>=<NULL>',
    '    "svce"<blob>="secret-box-test"',
    '    "type"<uint32>=<NULL>',
    'keychain: "/Users/tester/Library/Keychains/login.keychain-db"',
    'version: 512',
    'class: 0x0000000F ',
    'attributes:',
    '    0x00000001 <uint32>=0x0000000F ',
  ].join('\n')
  expect(dumpedItems(real)).toEqual([{ service: 'secret-box-test', account: 'sbt-first', label: 'secret-box-test', comment: '' }])
  const encoded = dumpOf([
    { s: 'café "x"', a: 'tab\there', j: 'secret-box', value: 'v' },
    { kind: 'internet', s: 'github.com', a: 'me', value: 'v' },
  ])
  expect(dumpedItems(encoded)).toEqual([{ service: 'café "x"', account: 'tab\there', label: 'café "x"', comment: 'secret-box' }])
})

const keychain = (): Item[] => [
  { s: 'myapp/STRIPE_SECRET_KEY', a: 'tester', j: 'secret-box', value: hex(7) },
  { s: 'acme-deploy', a: 'ci', l: 'Deploy token', value: hex(8) },
  { s: 'com.apple.unrelated', a: 'someone', value: hex(9) },
  { s: 'personal-bank', a: 'me', j: 'my note', value: hex(10) },
]

test('list_key_names: pointers, tagged items and listPrefixes items, by name only; nothing else in the keychain', { options: { listPrefixes: 'acme-, other/' } }, async ($, on) => {
  mac(on, { items: keychain(), files: { '.env': 'OPENAI_API_KEY=keychain:openai?account=work\nPORT=3000\n' } })
  const r = String((await call($, { tool: LIST })).result)
  expect(r.split('\n')[0]).toBe(NAMES_ONLY)
  expect(r).toContain('OPENAI_API_KEY in .env: service openai, account work')
  expect(r).toContain('service myapp/STRIPE_SECRET_KEY, account tester')
  expect(r).toContain('service acme-deploy, account ci, label Deploy token')
  for (const absent of ['com.apple.unrelated', 'personal-bank', 'cdat', 'icmt', hex(7), hex(8), hex(9), hex(10)]) expect(r).not.toContain(absent)
})

test('list_key_names: without listPrefixes only tagged items show, with how to tag others', async ($, on) => {
  mac(on, { items: keychain().slice(1) })
  const answer = await call($, { tool: LIST })
  expect(String(answer.result)).not.toContain('acme-deploy')
  expect((answer.context ?? []).join('\n')).toContain('-j secret-box -w')
})

test('list_key_names: a listing cut off or refused says so', async ($, on) => {
  mac(on, { items: keychain(), dumpCut: true })
  expect(String((await call($, { tool: LIST })).result)).toContain('cut off')
})

test('list_key_names: a dump that fails says so, and still lists pointers', async ($, on) => {
  mac(on, { fail: { exitCode: 51, stdout: '', stderr: 'denied' }, files: { '.env': 'K=keychain:k\n' } })
  const r = String((await call($, { tool: LIST })).result)
  expect(r).toContain('K in .env: service k')
  expect(r).toContain('could not be listed (security exited 51)')
})

test('list_key_names is registered with the names-only sentence first', async ($, on) => {
  const specs = await registered($, on, {})
  expect(specs.find((s) => s.name === 'list_key_names')!.description.startsWith(NAMES_ONLY)).toBe(true)
})

// ---------------------------------------------------- migrate_env_to_keychain

const plain = 'export OPENAI_API_KEY=sk-plain-' + hex(11) + '\r\nPORT=3000\r\nDB_PASSWORD="pw-' + hex(12) + '"\r\nGITHUB_TOKEN=keychain:github\r\n'

test('migrate: each secret-named plaintext entry goes to the Keychain, is read back, and its line becomes a pointer', async ($, on) => {
  const opts: Opts = { files: { '.env': plain }, argvs: [], seen: [], asked: [], answer: 'Move them' }
  mac(on, opts)
  const r = String((await call($, { tool: MIGRATE })).result)
  expect(opts.files!['.env']).toBe(
    'export OPENAI_API_KEY=keychain:repo/OPENAI_API_KEY?account=tester\r\nPORT=3000\r\nDB_PASSWORD=keychain:repo/DB_PASSWORD?account=tester\r\nGITHUB_TOKEN=keychain:github\r\n',
  )
  expect(securityCalls(opts.argvs!).filter((a) => a[1] === 'add-generic-password')).toEqual([
    [SECURITY, 'add-generic-password', '-U', '-s', 'repo/OPENAI_API_KEY', '-a', 'tester', '-j', 'secret-box', '-w', 'sk-plain-' + hex(11)],
    [SECURITY, 'add-generic-password', '-U', '-s', 'repo/DB_PASSWORD', '-a', 'tester', '-j', 'secret-box', '-w', 'pw-' + hex(12)],
  ])
  // Names only, in the dialog and the answer; the file went through $.fs, not the Write tool
  for (const text of [r, ...opts.asked!]) {
    expect(text).not.toContain(hex(11))
    expect(text).not.toContain(hex(12))
  }
  expect(opts.asked!.join()).toContain('OPENAI_API_KEY, DB_PASSWORD')
  expect(opts.seen!.filter((s) => s.tool === 'Write' || s.tool === 'Edit')).toEqual([])
  // The moved values are hidden wherever they turn up later
  const later = await call($, { tool: 'Bash', command: 'node print-config.js' })
  expect(later.result).toBe('ran')
})

test('migrate: a value a command prints later comes back hidden', async ($, on) => {
  const opts: Opts = { files: { '.env': 'API_KEY=' + hex(13) + '\n' }, answer: 'Move them', output: `key=${hex(13)}` }
  mac(on, opts)
  await call($, { tool: MIGRATE })
  expect(String((await call($, { tool: 'Bash', command: 'node app.js' })).result)).not.toContain(hex(13))
})

test('migrate: when the user cancels, nothing is written anywhere', async ($, on) => {
  const opts: Opts = { files: { '.env': plain }, argvs: [], answer: 'Cancel' }
  mac(on, opts)
  expect(String((await call($, { tool: MIGRATE })).result)).toContain('did not approve')
  expect(opts.files!['.env']).toBe(plain)
  expect(securityCalls(opts.argvs!)).toEqual([])
})

test('migrate: a permission rule that allows it skips the dialog; one that denies it refuses', async ($, on) => {
  const allowed: Opts = { files: { '.env': 'API_KEY=' + hex(14) + '\n' }, check: 'allow', asked: [] }
  mac(on, allowed)
  await call($, { tool: MIGRATE })
  expect(allowed.asked).toEqual([])
  expect(allowed.files!['.env']).toBe('API_KEY=keychain:repo/API_KEY?account=tester\n')
})

test('migrate: denied by a permission rule, nothing changes', async ($, on) => {
  const opts: Opts = { files: { '.env': plain }, check: 'deny', argvs: [] }
  mac(on, opts)
  expect(String((await call($, { tool: MIGRATE })).result)).toContain('denies')
  expect(opts.files!['.env']).toBe(plain)
  expect(securityCalls(opts.argvs!)).toEqual([])
})

test('migrate: a value that does not read back the same leaves its line as it was', async ($, on) => {
  const opts: Opts = { files: { '.env': plain }, answer: 'Move them', tamper: true, writes: [] }
  mac(on, opts)
  const r = String((await call($, { tool: MIGRATE })).result)
  expect(r).toContain('did not read back the same value')
  expect(opts.files!['.env']).toBe(plain)
  expect(opts.writes).toEqual([])
})

test('migrate: an item already holding a different value is not overwritten', async ($, on) => {
  const opts: Opts = { files: { '.env': 'API_KEY=' + hex(15) + '\n' }, answer: 'Move them', items: [{ s: 'repo/API_KEY', a: 'tester', value: 'other' }], argvs: [] }
  mac(on, opts)
  expect(String((await call($, { tool: MIGRATE })).result)).toContain('already holds a different value')
  expect(opts.files!['.env']).toBe('API_KEY=' + hex(15) + '\n')
  expect(securityCalls(opts.argvs!).some((a) => a[1] === 'add-generic-password')).toBe(false)
})

test('migrate: names picks the entries, secret-named or not', async ($, on) => {
  const opts: Opts = { files: { '.env': plain + 'WEBHOOK_URL_PART=abc123def456\n' }, answer: 'Move them' }
  mac(on, opts)
  const r = String((await call($, { tool: MIGRATE, names: ['WEBHOOK_URL_PART', 'NOPE'] })).result)
  expect(opts.files!['.env']).toContain('WEBHOOK_URL_PART=keychain:repo/WEBHOOK_URL_PART?account=tester')
  expect(opts.files!['.env']).toContain('OPENAI_API_KEY=sk-plain-')
  expect(r).toContain('Not found with a plaintext value: NOPE')
})

test('migrate: only a .env file, and only one that exists', async ($, on) => {
  mac(on, {})
  expect(String((await call($, { tool: MIGRATE, file: 'config.json' })).result)).toContain('is not a .env file')
  expect(String((await call($, { tool: MIGRATE, file: '.env.prod' })).result)).toContain('could not be read')
})

// ----------------------------------------------- the runner's reader, in JS

// tests/env-cases.ts; runner-parity.test.mts holds bin/keychain-env to the same cases
for (const c of ENV_CASES) {
  test(`envPointers, shared case: ${c.name}`, async () => {
    expect(envPointers(c.text).map(([n, p]: [string, any]) => [n, p.service, p.account])).toEqual(c.pointers.map(([n, s, a]) => [n, s, a]))
  })
}

// ------------------------------------- a key written after keychain: (B1, B2)

// An OpenAI project key's shape, built at run time
const PROJECT_KEY = 'sk-' + 'proj-' + 'Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St90'

test('a real key written after keychain: stays hidden, though it reads as a pointer, and real pointers still show', async ($, on) => {
  const text = `OPENAI_API_KEY=keychain:${PROJECT_KEY}\nDB_PASSWORD=keychain:myapp/DB_PASSWORD\n`
  mac(on, { files: { '.env': text }, output: text })
  const r = String((await call($, { tool: 'Read', file_path: `${CWD}/.env` })).result)
  expect(r).not.toContain(PROJECT_KEY)
  expect(r).not.toContain('keychain:sk-')
  expect(r).toContain('DB_PASSWORD=keychain:myapp/DB_PASSWORD')
})

test('a key already loaded into the vault stays hidden after keychain:', async ($, on) => {
  const VALUE = hex(40)
  const text = `OPENAI_API_KEY=keychain:${VALUE}\n`
  mac(on, { items: [{ s: 'svc', value: VALUE }], files: { '.env': text }, output: text })
  expect(String((await call($, { tool: USE, service: 'svc' })).result)).toMatch(TAG)
  expect(String((await call($, { tool: 'Read', file_path: `${CWD}/.env` })).result)).not.toContain(VALUE)
})

test('a key too short for the scrubber stays hidden after keychain: once the mod has hidden it', async ($, on) => {
  const SHORT = 'hunt3r7'
  const text = `DB_PASSWORD=keychain:${SHORT}\n`
  mac(on, { items: [{ s: 'db', value: SHORT }], files: { '.env': text }, output: text })
  await call($, { tool: USE, service: 'db' })
  expect(String((await call($, { tool: 'Read', file_path: `${CWD}/.env` })).result)).not.toContain(`keychain:${SHORT}`)
})

for (const [tool, input] of [
  ['Write', (tag: string) => ({ file_path: `${CWD}/.env`, content: `OPENAI_API_KEY=keychain:${tag}\n` })],
  ['Edit', (tag: string) => ({ file_path: `${CWD}/.env`, old_string: 'OPENAI_API_KEY=', new_string: `OPENAI_API_KEY=keychain:${tag}` })],
  ['Bash', (tag: string) => ({ command: `echo OPENAI_API_KEY=keychain:${tag} >> .env` })],
] as [string, (tag: string) => Record<string, string>][]) {
  test(`${tool} with keychain:<placeholder> is refused before the key is put in its place`, async ($, on) => {
    const seen: Record<string, unknown>[] = []
    mac(on, { items: [{ s: 'svc', value: hex(41) }], seen })
    const tag = String((await call($, { tool: USE, service: 'svc' })).result).match(TAG)![0]
    const r = await call($, { tool, ...input(tag) })
    expect(String(r.deny)).toContain('write its service name')
    expect(seen.filter((s) => s.tool === tool)).toEqual([])
  })
}

test('commit guard: a .env with a real key after keychain: is blocked', async ($, on) => {
  mac(on, { files: { '.env': `OPENAI_API_KEY=keychain:${PROJECT_KEY}\nOTHER=keychain:openai\n` } })
  expect(Boolean((await call($, { tool: 'Bash', command: 'git add .env' })).deny)).toBe(true)
})

test('commit guard: a .env with a vault value after keychain: is blocked', async ($, on) => {
  const VALUE = hex(42)
  mac(on, { items: [{ s: 'svc', value: VALUE }], files: { '.env': `OPENAI_API_KEY=keychain:${VALUE}\n` } })
  await call($, { tool: USE, service: 'svc' })
  expect(Boolean((await call($, { tool: 'Bash', command: 'git add .env' })).deny)).toBe(true)
})

const PEM = `PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\nMIIEow${hex(43)}\n-----END RSA PRIVATE KEY-----"\nAPI_KEY=${hex(44)}\n`

test('commit guard: a .env whose quote closes on a later line is blocked, pointers or not', async ($, on) => {
  mac(on, { files: { '.env': `OPENAI_API_KEY=keychain:openai\nNOTE="first line\nsecond line"\n` } })
  expect(Boolean((await call($, { tool: 'Bash', command: 'git add .env' })).deny)).toBe(true)
})

test('migrate: a quoted value spanning lines stays as it was, and the reason names the multi-line route', async ($, on) => {
  const opts: Opts = { files: { '.env': PEM }, answer: 'Move them', argvs: [] }
  mac(on, opts)
  const r = String((await call($, { tool: MIGRATE })).result)
  expect(r).toContain('PRIVATE_KEY (its value spans lines')
  expect(r).toContain('multi-line-values.md')
  expect(opts.files!['.env']).toBe(PEM.replace(`API_KEY=${hex(44)}`, 'API_KEY=keychain:repo/API_KEY?account=tester'))
  expect(securityCalls(opts.argvs!).filter((a) => a[1] === 'add-generic-password').map((a) => a[a.indexOf('-s') + 1])).toEqual(['repo/API_KEY'])
})

test('migrate: a value with backslash escapes stays as it was', async ($, on) => {
  const text = `TOKEN="line1\\nline2-${hex(45)}"\n`
  const opts: Opts = { files: { '.env': text }, answer: 'Move them', argvs: [] }
  mac(on, opts)
  const r = String((await call($, { tool: MIGRATE })).result)
  expect(r).toContain('TOKEN (its value spans lines or holds backslash escapes')
  expect(r).toContain('Nothing was changed')
  expect(opts.files!['.env']).toBe(text)
  expect(securityCalls(opts.argvs!)).toEqual([])
})

// --------------------------- key-shaped names after keychain: (the detector's blind spot)

// Built at run time: hex of the lengths API keys come in, and a UUID
const UUID = [hex(54).slice(0, 8), hex(55).slice(0, 4), hex(56).slice(0, 4), hex(57).slice(0, 4), hex(58).slice(0, 12)].join('-')
const KEY_SHAPES = [hex(50).slice(0, 16), hex(51).slice(0, 32), hex(52).slice(0, 40), UUID, 'Ab12Cd34Ef56Gh78Ij90Kl', `myapp/${hex(53).slice(0, 32)}`, `acme.prod/${UUID}`]
const NAMES = [
  'openai', 'myapp/STRIPE_SECRET_KEY', 'my-app/STRIPE_SECRET_KEY', 'acme.prod/DB_PASSWORD', 'secret-box-test-proj/DB_PASSWORD',
  'PROJECTDIR/ENV_NAME', 'repo/AWS_SECRET_ACCESS_KEY', 'OPENAI_API_KEY', 'david', 'work', 'ops@acme', 'john.smith2024',
  'deadbeef', 'project2024backup', 'my app/KEY',
]

test('looksLikeKey: hex, UUIDs and long mixed tokens are keys; names made by the conventions are not', async () => {
  expect(KEY_SHAPES.filter((s) => !looksLikeKey(s))).toEqual([])
  expect(NAMES.filter((s) => looksLikeKey(s))).toEqual([])
})

for (const [name, line] of [
  ['32 hex', `STRIPE_SECRET_KEY=keychain:${hex(51).slice(0, 32)}`],
  ['40 hex', `DD_API_KEY=keychain:${hex(52).slice(0, 40)}`],
  ['a UUID', `CLIENT_SECRET=keychain:${UUID}`],
  ['a UUID as the account', `CLIENT_SECRET=keychain:svc?account=${UUID}`],
]) {
  test(`a fresh session keeps a pointer to ${name} hidden: it is the key's shape, not a name`, async ($, on) => {
    const text = `${line}\nDB_PASSWORD=keychain:myapp/DB_PASSWORD\n`
    mac(on, { files: { '.env': text }, output: text })
    const r = String((await call($, { tool: 'Read', file_path: `${CWD}/.env` })).result)
    expect(r).not.toContain(line.split('keychain:')[1]!.replace(/^svc\?account=/, ''))
    expect(r).toContain('DB_PASSWORD=keychain:myapp/DB_PASSWORD')
  })
}

test('commit guard: API_TOKEN=keychain:<uuid> is blocked though the detector leaves the line alone', async ($, on) => {
  mac(on, { files: { '.env': `API_TOKEN=keychain:${UUID}\nOTHER=keychain:openai?account=work\n` }, items: [...held(), { s: UUID, value: hex(32) }] })
  expect(String((await call($, { tool: 'Bash', command: 'git add .env' })).deny)).toContain('API_TOKEN holds a key')
})

test('commit guard: a pointer to a key-shaped name is blocked even when that item exists', async ($, on) => {
  const service = hex(51).slice(0, 32)
  mac(on, { files: { '.env': `STRIPE_SECRET_KEY=keychain:${service}\n` }, items: [{ s: service, value: hex(31) }] })
  expect(Boolean((await call($, { tool: 'Bash', command: 'git add .env' })).deny)).toBe(true)
})

test('commit guard: a pointer to an item the Keychain does not hold is blocked, and says so', async ($, on) => {
  mac(on, { files: { '.env': 'OPENAI_API_KEY=keychain:openai?account=work\n' } })
  expect(String((await call($, { tool: 'Bash', command: 'git add .env' })).deny)).toContain("points to keychain:openai?account=work, which the Keychain doesn't hold")
})

for (const [name, opts] of [
  ['security fails', { fail: { exitCode: 51, stdout: '', stderr: 'denied' } }],
  ['security cannot run', { deny: 'timed out' }],
] as [string, Opts][]) {
  test(`commit guard: when ${name}, whether the item exists is unknown, and the commit is blocked`, async ($, on) => {
    mac(on, { ...opts, files: { '.env': 'OPENAI_API_KEY=keychain:openai?account=work\n' }, items: held() })
    expect(String((await call($, { tool: 'Bash', command: 'git add .env' })).deny)).toContain('could not be checked')
  })
}

test('commit guard: the item is looked up by attributes only, never its password, and once per session', async ($, on) => {
  const argvs: string[][] = []
  mac(on, { files: { '.env': pointersOnly }, items: held(), argvs })
  expect((await call($, { tool: 'Bash', command: 'git add .env' })).deny).toBeUndefined()
  expect((await call($, { tool: 'Bash', command: 'git add .env' })).deny).toBeUndefined()
  expect(securityCalls(argvs)).toEqual([[SECURITY, 'find-generic-password', '-s', 'openai', '-a', 'work']])
})

test('commit guard: an item added after a refusal is found on the next try', async ($, on) => {
  const opts: Opts = { files: { '.env': pointersOnly } }
  mac(on, opts)
  expect(Boolean((await call($, { tool: 'Bash', command: 'git add .env' })).deny)).toBe(true)
  opts.items!.push(...held())
  expect((await call($, { tool: 'Bash', command: 'git add .env' })).deny).toBeUndefined()
})
