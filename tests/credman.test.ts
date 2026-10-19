// Windows: Credential Manager by way of bin/credman.ps1, the PowerShell
// guard, and the reads a command makes through bin/credman. The machine is
// tests/fake-win.ts; no test here runs the real credman.ps1.
import { expect, mock, test } from 'claude-code/testing'

import { bashPath, credAddHint, credmanArgv, credmanCommand as credmanPath, credmanScript, credReadCommand } from '../hooks/credman'
import { keychainReads } from '../hooks/keychain'
import {
  BOX, call, credmanCalls, credmanCommand, CWD, hex, hexOf, LIST, MIGRATE, POWERSHELL, registeredWin, TAG, USE, win,
  type Cred, type WinOpts,
} from './fake-win'

const NAMES_ONLY = "Returns key names only and never fetches or returns any key's value."
// A placeholder no vault here ever minted: an old one, after a reload
const STALE = '[REDACTED-SECRET-0badc0de]'
// A Stripe-shaped fake key the detector hides on sight, built at run time
const STRIPE = 'sk_' + 'live_' + 'W1n2D3o4W5s6K7e8Y9z0A1b2'
// The mod's folder is the host's own ($.plugin.root, which a test can't set):
// C:\Users\...\secret-box on Windows, /Users/.../secret-box on a Mac. So the
// paths the mod builds on it are matched by shape, with a drive only where the
// host has one. 'the paths built on a Windows folder' below pins each one
// exactly, built on a Windows folder, on any host.
// bin/credman by the path Git Bash takes: absolute, forward slashes only
const CREDMAN = /(?:[A-Za-z]:)?\/[^\\\s"]*\/bin\/credman/
// bin/keychain-env the same way
const RUNNER = /(?:[A-Za-z]:)?\/[^\\\s"]*\/bin\/keychain-env/
// credman.ps1 by the path powershell.exe -File takes: the folder, then \bin\credman.ps1
const CREDMAN_PS1 = /(?:[A-Za-z]:\\|\/)[^"]*\\bin\\credman\.ps1/
const U = 'unknown'

// What credman.ps1 reads on stdin: each name, and the value for set, as hex of its UTF-8
const stdinOf = (...lines: string[]) => lines.map(hexOf).join('\n') + '\n'
// Every argv credman.ps1 was run with, as one string, for what must never be in one
const argvText = (opts: WinOpts) => JSON.stringify(credmanCalls(opts.argvs!))
const commands = (opts: WinOpts) => credmanCalls(opts.argvs!).map((a) => credmanCommand(a))

// use_secret's tag for `input`, then what a Write of that tag hands the tool
async function restored($: any, opts: WinOpts, input: Record<string, unknown>) {
  const tag = String((await call($, { tool: USE, ...input })).result).match(TAG)![0]
  await call($, { tool: 'Write', file_path: `${CWD}/k.txt`, content: tag })
  return opts.seen!.at(-1)!.content
}

// ------------------------------------------------------------- registration

test('on Windows the four tools are registered, in Credential Manager words, steering placeholders to Git Bash', async ($, on) => {
  const argvs: string[][] = []
  const specs = await registeredWin($, on, { argvs })
  expect(specs.map((s) => s.name)).toEqual(['request_secret', 'use_secret', 'list_key_names', 'migrate_env_to_keychain'])
  const [box, use, list, migrate] = specs
  expect(box!.description).toContain('saves it to Windows Credential Manager')
  expect(box!.description).toContain('Use the Bash tool (Git Bash) for such a command, not PowerShell')
  expect(box!.inputSchema.properties.name.description).toContain('The Credential Manager service')
  expect(use!.description).toContain('Windows Credential Manager (a generic credential)')
  expect(use!.description).toContain('Bash tool (Git Bash)')
  expect(use!.description).toMatch(new RegExp(`INSTEAD of running ${CREDMAN.source} get yourself`))
  expect(list!.description.startsWith(NAMES_ONLY)).toBe(true)
  expect(migrate!.description).toContain('account %USERNAME%')
  for (const s of specs) expect(s.description).not.toMatch(/macOS|Keychain item|security find/)
  // Windows says so in OS: no uname, and nothing read from Credential Manager yet
  expect(argvs.filter((a) => /uname$/.test(a[0]!))).toEqual([])
  expect(credmanCalls(argvs)).toEqual([])
})

// ---------------------------------------------------------------- use_secret

test('use_secret answers with a placeholder, and the names and value go over stdin as hex, never in argv', async ($, on) => {
  const VALUE = hex(1)
  const opts: WinOpts = { creds: [{ target: 'OPENAI_API_KEY', user: 'tester', value: VALUE }], argvs: [], stdins: [], seen: [] }
  win(on, opts)
  const r = await call($, { tool: USE, service: 'OPENAI_API_KEY' })
  expect(JSON.stringify(r)).not.toContain(VALUE)
  expect(String(r.result)).toMatch(new RegExp(`^Loaded OPENAI_API_KEY from Credential Manager as ${TAG.source}\\.$`))
  expect((r.context ?? []).join('\n')).toContain('Use the Bash tool (Git Bash) for that command: PowerShell gets no real values.')
  const [argv] = credmanCalls(opts.argvs!)
  expect(argv).toEqual([POWERSHELL, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', argv![6], 'read', '-Stdin'])
  expect(argv![6]).toMatch(new RegExp(`^${CREDMAN_PS1.source}$`))
  // No account given: an empty second line, so any account matches
  expect(opts.stdins).toEqual([stdinOf('OPENAI_API_KEY', '')])
  expect(argvText(opts)).not.toContain('OPENAI_API_KEY')
  expect(argvText(opts)).not.toContain(VALUE)
  expect(await restored($, opts, { service: 'OPENAI_API_KEY' })).toBe(VALUE)
  expect(argvText(opts)).not.toContain(VALUE)
})

test('use_secret with an account reads that item; another account is no item', async ($, on) => {
  const opts: WinOpts = { creds: [{ target: 'shared', user: 'work', value: hex(2) }], stdins: [], seen: [] }
  win(on, opts)
  expect(await restored($, opts, { service: 'shared', account: 'work' })).toBe(hex(2))
  expect(opts.stdins![0]).toBe(stdinOf('shared', 'work'))
  const r = String((await call($, { tool: USE, service: 'shared', account: 'home' })).result)
  expect(r).toContain('No Credential Manager item has the service shared and account home')
  expect(r).not.toMatch(TAG)
})

test('the placeholder from use_secret becomes the value in Bash, and comes back hidden', async ($, on) => {
  const VALUE = hex(3)
  const opts: WinOpts = { creds: [{ target: 'svc', user: 'tester', value: VALUE }], seen: [], output: VALUE }
  win(on, opts)
  const tag = String((await call($, { tool: USE, service: 'svc' })).result).match(TAG)![0]
  const r = await call($, { tool: 'Bash', command: `printf '%s' ${tag} | tee out.txt` })
  expect(String(opts.seen!.at(-1)!.command)).toBe(`printf '%s' ${VALUE} | tee out.txt`)
  expect(String(r.result)).toBe(tag)
})

test('use_secret gives a value with a shell character the bin/credman form, with forward slashes, and no placeholder', async ($, on) => {
  const VALUE = 'pass word ' + hex(4)
  win(on, { creds: [{ target: "Bob's site", user: 'bob', value: VALUE }] })
  const answer = await call($, { tool: USE, service: "Bob's site", account: 'bob' })
  const r = String(answer.result)
  const guide = (answer.context ?? []).join('\n')
  expect(JSON.stringify(answer)).not.toContain(VALUE)
  expect(r + guide).not.toMatch(TAG)
  const m = /^Loaded Bob's site \(account bob\) from Credential Manager\. Use it in Bash as ("\$\((\S+) get -s 'Bob'\\''s site' -a bob\)")\.$/.exec(r)
  expect(m).not.toBeNull()
  const [, command, script] = m!
  expect(script).toMatch(new RegExp(`^${CREDMAN.source}$`))
  expect(script).not.toContain('\\')
  expect(guide).toContain(`As a whole argument of its own, write exactly: ${command}.`)
  expect(guide).toContain(`-H "Authorization: Bearer ${command!.slice(1, -1)}"`)
  expect(guide).toContain('Use the Bash tool (Git Bash) for that command')
  // The form is a read the pre-load pins to this very item
  expect(keychainReads(`printf '%s' ${command} | tee out.txt`, {}, { windows: true })).toEqual([{ kind: 'credman', service: "Bob's site", account: 'bob' }])
})

test('the bin/credman form use_secret gives runs with the value out of the command and out of the output', async ($, on) => {
  const VALUE = 'pass word ' + hex(5)
  const opts: WinOpts = { creds: [{ target: 'site', user: 'tester', value: VALUE }], seen: [], argvs: [], stdins: [], output: VALUE }
  win(on, opts)
  const command = String((await call($, { tool: USE, service: 'site' })).result).match(/"\$\(.*? get -s site\)"/)![0]
  const r = await call($, { tool: 'Bash', command: `printf '%s' ${command} | tee out.txt` })
  expect(r.deny).toBeUndefined()
  expect(String(opts.seen!.at(-1)!.command)).not.toContain(VALUE)
  expect(String(r.result)).not.toContain(VALUE)
  expect(String(r.result)).toMatch(TAG)
  // use_secret's read, then the pre-load's read of the same item
  expect(commands(opts)).toEqual(['read', 'read'])
  expect(opts.stdins).toEqual([stdinOf('site', ''), stdinOf('site', '')])
})

test('a missing item answers with the credman.ps1 add command, to run in their own terminal', async ($, on) => {
  win(on)
  const r = String((await call($, { tool: USE, service: 'NEW_KEY' })).result)
  expect(r).toContain('No Credential Manager item has the service NEW_KEY.')
  expect(r).toContain('in their own terminal window (not through Claude, and not with !)')
  expect(r).toMatch(new RegExp(`\\npowershell -NoProfile -ExecutionPolicy Bypass -File "${CREDMAN_PS1.source}" add -Service NEW_KEY -Account tester\\n`))
  expect(r).not.toMatch(TAG)
  const named = String((await call($, { tool: USE, service: 'my key', account: 'work' })).result)
  expect(named).toContain('credman.ps1" add -Service "my key" -Account work')
})

test('the account defaults to USERNAME, and Windows PowerShell is run from SystemRoot', async ($, on) => {
  const argvs: string[][] = []
  win(on, { env: { OS: 'Windows_NT', USERNAME: 'jdoe', SystemRoot: 'D:\\WINNT\\' }, argvs })
  expect(String((await call($, { tool: USE, service: 'NEW_KEY' })).result)).toContain('add -Service NEW_KEY -Account jdoe')
  expect(credmanCalls(argvs)[0]![0]).toBe('D:\\WINNT\\System32\\WindowsPowerShell\\v1.0\\powershell.exe')
})

test('the keychainAccount setting comes before USERNAME', { options: { keychainAccount: 'work' } }, async ($, on) => {
  win(on)
  expect(String((await call($, { tool: USE, service: 'NEW_KEY' })).result)).toContain('add -Service NEW_KEY -Account work')
})

test('use_secret: a .env pointer names the item, read through credman', async ($, on) => {
  const opts: WinOpts = {
    creds: [{ target: 'OPENAI_API_KEY', user: 'tester', value: hex(6) }, { target: 'openai', user: 'work', value: hex(7) }],
    files: { '.env': 'OPENAI_API_KEY=keychain:openai?account=work\n' },
    stdins: [],
    seen: [],
  }
  win(on, opts)
  const answer = await call($, { tool: USE, service: 'OPENAI_API_KEY' })
  expect(String(answer.result)).toContain('Loaded openai (account work) from Credential Manager through the OPENAI_API_KEY pointer in .env')
  expect((answer.context ?? []).join('\n')).toMatch(new RegExp(`${RUNNER.source} -- COMMAND`))
  expect(opts.stdins).toEqual([stdinOf('openai', 'work')])
  expect(await restored($, opts, { service: 'OPENAI_API_KEY' })).toBe(hex(7))
})

test('use_secret: bytes that are not text, a failed read, a cut-off answer and no PowerShell each load nothing', async ($, on) => {
  const opts: WinOpts = { creds: [{ target: 'bin', user: 'tester', value: hex(8), bytes: true }] }
  win(on, opts)
  expect(String((await call($, { tool: USE, service: 'bin' })).result)).toContain('holds bytes that are not text')
  opts.fail = { exitCode: 1, stdout: 'LEAKED-STDOUT', stderr: 'credman: Credential Manager error 1312\r\nLEAKED-LINE' }
  const failed = String((await call($, { tool: USE, service: 'bin' })).result)
  expect(failed).toContain('could not be read (credman.ps1 could not read it (exit 1: Credential Manager error 1312))')
  expect(failed).toContain('Control Panel, Credential Manager, Windows Credentials')
  expect(failed).not.toContain('LEAKED')
  delete opts.fail
  opts.creds!.push({ target: 'svc', user: 'tester', value: hex(9) })
  opts.truncated = true
  const cut = JSON.stringify(await call($, { tool: USE, service: 'svc' }))
  expect(cut).toContain('cut off')
  expect(cut).not.toContain(hex(9))
  expect(cut).not.toMatch(TAG)
  opts.deny = "Command 'powershell.exe' failed to start: ENOENT"
  expect(String((await call($, { tool: USE, service: 'svc' })).result)).toBe(
    'secret-box could not read Credential Manager: Windows PowerShell is missing: the Credential Manager backend needs it. Nothing was loaded.',
  )
})

// ------------------------------------------------------------ list_key_names

const store = (): Cred[] => [
  { target: 'myapp/STRIPE_SECRET_KEY', user: 'tester', comment: 'secret-box', value: hex(10) },
  { target: 'acme-deploy', user: 'ci', comment: '', value: hex(11) },
  { target: 'git:https://github.com', user: 'someone', comment: '', value: hex(12) },
  { target: 'personal-bank', user: 'me', comment: 'my note', value: hex(13) },
]

test('list_key_names: pointers, tagged and listPrefixes items by name only; no other credential', { options: { listPrefixes: 'acme-' } }, async ($, on) => {
  const opts: WinOpts = { creds: store(), files: { '.env': 'OPENAI_API_KEY=keychain:openai?account=work\nPORT=3000\n' }, argvs: [] }
  win(on, opts)
  const answer = await call($, { tool: LIST })
  const r = String(answer.result)
  expect(r.split('\n')[0]).toBe(NAMES_ONLY)
  expect(r).toContain('OPENAI_API_KEY in .env: service openai, account work')
  expect(r).toContain('Credential Manager items secret-box saved, or whose service starts with a listPrefixes entry:')
  expect(r).toContain('  service myapp/STRIPE_SECRET_KEY, account tester')
  expect(r).toContain('  service acme-deploy, account ci')
  for (const absent of ['git:https://github.com', 'someone', 'personal-bank', 'my note', hex(10), hex(11), hex(12), hex(13)]) {
    expect(JSON.stringify(answer)).not.toContain(absent)
  }
  // One list run: no stdin, no -Stdin, and no read of any value
  expect(credmanCalls(opts.argvs!).map((a) => a.slice(7))).toEqual([['list']])
  expect((answer.context ?? []).join('\n')).toContain('credman.ps1" add -Service SERVICE -Account ACCOUNT')
})

test('list_key_names: without listPrefixes only tagged items show', async ($, on) => {
  win(on, { creds: store() })
  const r = String((await call($, { tool: LIST })).result)
  expect(r).toContain('service myapp/STRIPE_SECRET_KEY')
  expect(r).not.toContain('acme-deploy')
})

test('list_key_names: a listing cut off, or one that fails, says so and still lists pointers', async ($, on) => {
  const opts: WinOpts = { creds: store(), listCut: true, files: { '.env': 'K=keychain:k\n' } }
  win(on, opts)
  expect(String((await call($, { tool: LIST })).result)).toContain('The Credential Manager listing was cut off')
  opts.fail = { exitCode: 1, stdout: '', stderr: 'credman: Credential Manager error 5\n' }
  const r = String((await call($, { tool: LIST })).result)
  expect(r).toContain('K in .env: service k')
  expect(r).toContain('The Credential Manager could not be listed (Credential Manager error 5)')
})

// ---------------------------------------------------- migrate_env_to_keychain

const plain = 'export OPENAI_API_KEY=sk-plain-' + hex(14) + '\r\nPORT=3000\r\nDB_PASSWORD="pw-' + hex(15) + '"\r\nGITHUB_TOKEN=keychain:github\r\n'

test('migrate: each value is set over stdin, read back, and its line becomes a pointer', async ($, on) => {
  const opts: WinOpts = { files: { '.env': plain }, argvs: [], stdins: [], seen: [], asked: [], answer: 'Move them' }
  win(on, opts)
  const answer = await call($, { tool: MIGRATE })
  const r = String(answer.result)
  expect(opts.files!['.env']).toBe(
    'export OPENAI_API_KEY=keychain:repo/OPENAI_API_KEY?account=tester\r\nPORT=3000\r\nDB_PASSWORD=keychain:repo/DB_PASSWORD?account=tester\r\nGITHUB_TOKEN=keychain:github\r\n',
  )
  expect(r).toContain('Moved into Windows Credential Manager (account tester)')
  // Per entry: none there yet, set, read back
  expect(commands(opts)).toEqual(['read', 'set', 'read', 'read', 'set', 'read'])
  expect(opts.stdins![1]).toBe(stdinOf('repo/OPENAI_API_KEY', 'tester', 'sk-plain-' + hex(14)))
  expect(opts.stdins![4]).toBe(stdinOf('repo/DB_PASSWORD', 'tester', 'pw-' + hex(15)))
  expect(opts.creds).toEqual([
    { target: 'repo/OPENAI_API_KEY', user: 'tester', comment: 'secret-box', value: 'sk-plain-' + hex(14) },
    { target: 'repo/DB_PASSWORD', user: 'tester', comment: 'secret-box', value: 'pw-' + hex(15) },
  ])
  for (const text of [JSON.stringify(answer), argvText(opts), ...opts.asked!]) {
    expect(text).not.toContain(hex(14))
    expect(text).not.toContain(hex(15))
  }
  expect(opts.asked!.join()).toContain('into Windows Credential Manager?')
  expect(opts.seen!.filter((s) => s.tool === 'Write' || s.tool === 'Edit')).toEqual([])
  expect((answer.context ?? []).join('\n')).toContain('-- COMMAND in the Bash tool (Git Bash) so the pointers are set from Credential Manager')
})

test('migrate: in a Windows folder the service is that folder name and the variable', async ($, on) => {
  const opts: WinOpts = { cwd: 'C:\\Users\\tester\\dev\\myapp', files: { '.env': 'API_KEY=' + hex(16) + '\n' }, check: 'allow', asked: [], stdins: [] }
  win(on, opts)
  const r = String((await call($, { tool: MIGRATE })).result)
  expect(r).toContain('API_KEY=keychain:myapp/API_KEY?account=tester')
  expect(opts.files!['.env']).toBe('API_KEY=keychain:myapp/API_KEY?account=tester\n')
  expect(opts.creds!.map((c) => c.target)).toEqual(['myapp/API_KEY'])
  expect(opts.stdins![1]).toBe(stdinOf('myapp/API_KEY', 'tester', hex(16)))
  expect(opts.asked).toEqual([])
})

test('migrate: a service held under another account leaves its line as it was', async ($, on) => {
  const opts: WinOpts = { files: { '.env': 'API_KEY=' + hex(17) + '\n' }, check: 'allow', creds: [{ target: 'repo/API_KEY', user: 'someone-else', value: 'other' }], writes: [] }
  win(on, opts)
  const r = String((await call($, { tool: MIGRATE })).result)
  expect(r).toContain("Left as they were: API_KEY (the service 'repo/API_KEY' is held under the account 'someone-else'")
  expect(r).not.toContain(hex(17))
  expect(opts.files!['.env']).toBe('API_KEY=' + hex(17) + '\n')
  expect(opts.creds).toEqual([{ target: 'repo/API_KEY', user: 'someone-else', value: 'other' }])
  expect(opts.writes).toEqual([])
})

test('migrate: a value that does not read back the same leaves its line as it was', async ($, on) => {
  const opts: WinOpts = { files: { '.env': plain }, answer: 'Move them', tamper: true, writes: [] }
  win(on, opts)
  expect(String((await call($, { tool: MIGRATE })).result)).toContain('Credential Manager did not read back the same value')
  expect(opts.files!['.env']).toBe(plain)
  expect(opts.writes).toEqual([])
})

// ------------------------------------------------------------------- the box

// Claude calls request_secret, the box opens, the person types `value` and
// presses Enter. Resolves with what Claude is answered.
async function fillBox($: any, on: any, value: string, opts: WinOpts) {
  const clock = mock.clock(on)
  win(on, { ...opts, clock })
  const answer = call($, { tool: BOX, name: 'STRIPE_SECRET_KEY', reason: 'billing.js needs it' })
  await clock.settle()
  const pane = await $.ui.mount({
    plugin: 'secret-box',
    surface: 'terminal',
    component: 'Pane',
    requestId: 'secret-box',
    props: { title: 'secret-box', isFocused: true, bodyColumns: 80, placement: 'dock' },
  })
  await pane.input({ key: 'secret', text: value, kind: 'change' })
  await pane.input({ key: 'secret', text: '•'.repeat(value.length) })
  await clock.advance(300)
  return answer
}

test('the box saves to Credential Manager over stdin, and the toast says so', async ($, on) => {
  const VALUE = hex(18)
  const opts: WinOpts = { argvs: [], stdins: [], toasts: [], writes: [] }
  const r = await fillBox($, on, VALUE, opts)
  expect(commands(opts)).toEqual(['set'])
  expect(opts.stdins).toEqual([stdinOf('STRIPE_SECRET_KEY', 'tester', VALUE)])
  expect(argvText(opts)).not.toContain(VALUE)
  expect(argvText(opts)).not.toContain('STRIPE_SECRET_KEY')
  expect(opts.toasts).toContain('STRIPE_SECRET_KEY saved to Credential Manager')
  expect(opts.writes).toEqual([])
  const tag = String(r.result).match(TAG)![0]
  expect(r.result).toBe(`The user entered STRIPE_SECRET_KEY, saved to Windows Credential Manager (account tester) as ${tag}.`)
  const guide = (r.context ?? []).join('\n')
  expect(guide).toContain('Use the Bash tool (Git Bash) for that command')
  expect(guide).toContain('write the line ENV_NAME=keychain:STRIPE_SECRET_KEY?account=tester there')
  expect(JSON.stringify(r)).not.toContain(VALUE)
})

test('a box save refused for another account says why, and hands out no placeholder', async ($, on) => {
  const r = await fillBox($, on, hex(19), { creds: [{ target: 'STRIPE_SECRET_KEY', user: 'other', value: 'x' }] })
  expect(String(r.result)).toBe(
    "Saving STRIPE_SECRET_KEY failed: the service 'STRIPE_SECRET_KEY' is held under the account 'other'; Credential Manager keeps one account per service",
  )
})

// ------------------------------------------------------------ PowerShell (2b)

test('a PowerShell command with a live placeholder is refused and does not run', async ($, on) => {
  const opts: WinOpts = { creds: [{ target: 'svc', user: 'tester', value: hex(20) }], seen: [] }
  win(on, opts)
  const tag = String((await call($, { tool: USE, service: 'svc' })).result).match(TAG)![0]
  const r = await call($, { tool: 'PowerShell', command: `Invoke-RestMethod -Headers @{ Authorization = "Bearer ${tag}" } https://api.example.com` })
  expect(String(r.deny)).toContain('secret-box: the placeholder in this command becomes its real value only in the Bash tool (Git Bash), not in PowerShell')
  expect(String(r.deny)).not.toContain(tag)
  expect(String(r.deny)).toContain('Run the same command with the Bash tool instead.')
  expect(String(r.deny)).not.toContain(hex(20))
  expect(opts.seen!.filter((s) => s.tool === 'PowerShell')).toEqual([])
})

test('a PowerShell command with a stale placeholder, or none, runs as written', async ($, on) => {
  const opts: WinOpts = { seen: [] }
  win(on, opts)
  for (const command of [`Write-Output '${STALE}'`, 'Get-ChildItem -Force']) {
    expect((await call($, { tool: 'PowerShell', command })).deny).toBeUndefined()
    expect(opts.seen!.at(-1)!.command).toBe(command)
  }
})

test('with PowerShell in restoreTools, the PowerShell guard steps aside', { options: { restoreTools: 'Bash,PowerShell' } }, async ($, on) => {
  const opts: WinOpts = { creds: [{ target: 'svc', user: 'tester', value: hex(21) }], seen: [] }
  win(on, opts)
  const tag = String((await call($, { tool: USE, service: 'svc' })).result).match(TAG)![0]
  const r = await call($, { tool: 'PowerShell', command: `Write-Output ${tag}` })
  expect(String(r.deny ?? '')).not.toContain('only in the Bash tool')
  expect(String(opts.seen!.at(-1)!.command)).toBe(`Write-Output ${hex(21)}`)
})

// ------------------------------------------------------------- commit guard

test('commit guard: git add .env through PowerShell is refused when the file holds a key', async ($, on) => {
  const opts: WinOpts = { files: { '.env': `STRIPE_SECRET_KEY=${STRIPE}\n` }, seen: [] }
  win(on, opts)
  const r = await call($, { tool: 'PowerShell', command: 'git add .env; git commit -m wip' })
  expect(String(r.deny)).toContain('staging a .env file is blocked: STRIPE_SECRET_KEY holds a key.')
  expect(String(r.deny)).toContain("A pushed key can't be taken back.")
  expect(opts.seen).toEqual([])
})

test('commit guard: a .env of pointers Credential Manager holds may be added, checked by exists alone', async ($, on) => {
  const opts: WinOpts = { files: { '.env': 'OPENAI_API_KEY=keychain:openai?account=work\nPORT=3000\n' }, creds: [{ target: 'openai', user: 'work', value: hex(22) }], argvs: [], stdins: [] }
  win(on, opts)
  expect(await call($, { tool: 'PowerShell', command: 'git add .env' })).toMatchObject({ result: 'ran' })
  expect(commands(opts)).toEqual(['exists'])
  expect(opts.stdins).toEqual([stdinOf('openai', 'work')])
  // A pointer to an item it does not hold is refused, and says so
  opts.files!['.env'] = 'OPENAI_API_KEY=keychain:missing\n'
  expect(String((await call($, { tool: 'Bash', command: 'git add .env' })).deny)).toContain("points to keychain:missing, which Credential Manager doesn't hold")
})

// ------------------------------------------------------------ the pre-load (3b)

test('a bin/credman get in Bash is loaded before it runs, so the value it prints comes back hidden', async ($, on) => {
  const VALUE = hex(23)
  const opts: WinOpts = { creds: [{ target: 'svc', user: 'tester', value: VALUE }], stdins: [], log: [], output: VALUE + '\n' }
  win(on, opts)
  const r = await call($, { tool: 'Bash', command: 'C:/x/bin/credman get -s svc' })
  expect(String(r.result)).not.toContain(VALUE)
  expect(String(r.result)).toMatch(TAG)
  expect(opts.stdins).toEqual([stdinOf('svc', '')])
  expect(opts.log!.at(-1)).toBe('tool Bash')
})

test('credman.ps1 run from the PowerShell tool is loaded too', async ($, on) => {
  const VALUE = hex(24)
  const opts: WinOpts = { creds: [{ target: 'svc', user: 'work', value: VALUE }], stdins: [], output: VALUE + '\r\n' }
  win(on, opts)
  const r = await call($, { tool: 'PowerShell', command: "& 'C:\\x\\bin\\credman.ps1' get -Service svc -Account work" })
  expect(String(r.result)).not.toContain(VALUE)
  expect(opts.stdins).toEqual([stdinOf('svc', 'work')])
})

for (const command of ['powershell -File C:\\x\\bin\\credman.ps1 get -Service svc', '& C:\\x\\bin\\credman.ps1 get -s svc', '.\\bin\\credman.ps1 get -s svc']) {
  test(`PowerShell's own path form is loaded too: ${command}`, async ($, on) => {
    const VALUE = hex(25)
    const opts: WinOpts = { creds: [{ target: 'svc', user: 'tester', value: VALUE }], stdins: [], output: VALUE + '\r\n' }
    win(on, opts)
    const r = await call($, { tool: 'PowerShell', command })
    expect(String(r.result)).not.toContain(VALUE)
    expect(opts.stdins).toEqual([stdinOf('svc', '')])
  })
}

test('a credman get whose service is a $VAR runs by default, only the detector scanning it', async ($, on) => {
  const opts: WinOpts = { argvs: [] }
  win(on, opts)
  expect(await call($, { tool: 'Bash', command: 'C:/x/bin/credman get -s "$SVC"' })).toEqual({ result: 'ran' })
  expect(credmanCalls(opts.argvs!)).toEqual([])
})

test('refuseUnmaskable on: a credman get whose service is a $VAR is refused', { options: { refuseUnmaskable: true } }, async ($, on) => {
  const opts: WinOpts = { seen: [] }
  win(on, opts)
  expect(String((await call($, { tool: 'Bash', command: 'C:/x/bin/credman get -s $SVC' })).deny)).toContain("so what it prints can't be hidden")
  expect(opts.seen).toEqual([])
  // A missing item still runs: the command finds none either
  expect(await call($, { tool: 'Bash', command: 'C:/x/bin/credman get -s missing' })).toEqual({ result: 'ran' })
})

test('the runner on Windows: every pointer is loaded through credman before it runs', async ($, on) => {
  const opts: WinOpts = {
    creds: [{ target: 'openai', user: 'work', value: hex(25) }, { target: 'myapp/DB_PASSWORD', user: 'tester', value: hex(26) }],
    files: { '.env': 'OPENAI_API_KEY=keychain:openai?account=work\nPORT=3000\nDB_PASSWORD="keychain:myapp/DB_PASSWORD"\n' },
    stdins: [],
    output: `db=${hex(26)} key=${hex(25)}\n`,
  }
  win(on, opts)
  const r = String((await call($, { tool: 'Bash', command: 'C:/x/secret-box/bin/keychain-env -- node app.js' })).result)
  expect(r).not.toContain(hex(25))
  expect(r).not.toContain(hex(26))
  expect(opts.stdins).toEqual([stdinOf('openai', 'work'), stdinOf('myapp/DB_PASSWORD', '')])
})

test('on Windows a security command reads nothing, so nothing is fetched', async ($, on) => {
  const opts: WinOpts = { argvs: [] }
  win(on, opts)
  expect(await call($, { tool: 'Bash', command: 'security find-generic-password -s svc -w' })).toEqual({ result: 'ran' })
  expect(credmanCalls(opts.argvs!)).toEqual([])
})

// ---------------------------------------------------------------- the nudge

test('the nudge on Windows names Credential Manager and says placeholders work in Bash only', async ($, on) => {
  win(on, { output: 'PORT=3000' })
  const r = await call($, { tool: 'Read', file_path: `${CWD}/.env.local` })
  const nudge = (r.context ?? []).join('\n')
  expect(nudge).toContain('keys live in Windows Credential Manager')
  expect(nudge).toContain('in the Bash tool (Git Bash); a placeholder works in Bash, not in PowerShell')
})

// ------------------------------------------------- keychainReads, windows

const c = (service: string, account?: string) => ({ kind: 'credman', service, ...(account ? { account } : {}) })
const WIN_READS: [string, string, unknown[]][] = [
  ['bin/credman get -s', 'C:/x/bin/credman get -s svc', [c('svc')]],
  ['bin/credman get -s -a', 'C:/x/bin/credman get -s svc -a me', [c('svc', 'me')]],
  ['-Service and -Account spelled out', 'bin/credman get -Service svc -Account me', [c('svc', 'me')]],
  ['powershell -File credman.ps1, single-quoted path', "powershell -NoProfile -File 'C:\\x\\bin\\credman.ps1' get -Service x -Account y", [c('x', 'y')]],
  ['powershell.exe -File credman.ps1, forward slashes', 'powershell.exe -File C:/x/bin/credman.ps1 get -Service x -Account y', [c('x', 'y')]],
  ['pwsh', 'pwsh -File C:/x/bin/credman.ps1 get -s x', [c('x')]],
  ['a parameter prefix with :value', 'C:/x/bin/credman get -Serv:x -Acc:y', [c('x', 'y')]],
  ['inside "$( )"', 'curl -H "Authorization: Bearer $(C:/x/bin/credman get -s svc)" https://api.example.com', [c('svc')]],
  ['the runner', 'C:/x/bin/keychain-env -- node app.js', [{ envFiles: ['.env'] }]],
  ['the runner, and a read in the command it runs', 'C:/x/bin/keychain-env -- C:/x/bin/credman get -s svc', [{ envFiles: ['.env'] }, c('svc')]],
  // Reads it can't pin down to one item
  ['a $VAR service', 'C:/x/bin/credman get -s $SVC', [U]],
  ['credman read -Stdin', 'C:/x/bin/credman read -Stdin < names.txt', [U]],
  ['a flag it does not know', 'C:/x/bin/credman get -s svc -Force', [U]],
  ['-s with nothing after it', 'C:/x/bin/credman get -s', [U]],
  ['inside an echo', 'echo "C:/x/bin/credman get -s svc"', [U]],
  // In Bash a bare backslash is an escape, so this path can't be known
  ['an unquoted backslash path', 'powershell -File C:\\x\\bin\\credman.ps1 get -Service x', [U]],
  // Only naming it, or another command, reads nothing
  ['cat bin/credman', 'cat bin/credman', []],
  ['grep credman', 'grep -rn credman hooks/', []],
  ['credman list', 'C:/x/bin/credman list', []],
  ['credman exists', 'C:/x/bin/credman exists -s svc', []],
  ['get with no service', 'C:/x/bin/credman get', []],
  ['security on Windows', 'security find-generic-password -s x -w', []],
]
for (const [name, command, reads] of WIN_READS) {
  test(`keychainReads, windows: ${name}`, async () => {
    expect(keychainReads(command, {}, { windows: true }).map((r: any) => (r.unknown ? U : r))).toEqual(reads)
  })
}

test('keychainReads off Windows takes a credman command for nothing', async () => {
  expect(keychainReads('C:/x/bin/credman get -s svc', {})).toEqual([])
})

// ------------------------------------------- the paths, on a Windows folder

// $.plugin.root as Windows gives it. credman.js builds every path on it by
// text alone, so these hold on any host.
const WIN_ROOT = 'C:\\Users\\tester\\.claude\\plugins\\secret-box'

test('the paths built on a Windows folder: credman.ps1 with backslashes, bin/credman and keychain-env as Git Bash takes them', async () => {
  const ps1 = 'C:\\Users\\tester\\.claude\\plugins\\secret-box\\bin\\credman.ps1'
  const sh = 'C:/Users/tester/.claude/plugins/secret-box/bin/credman'
  for (const root of [WIN_ROOT, `${WIN_ROOT}\\`]) {
    expect(credmanScript(root)).toBe(ps1)
    expect(credmanPath(root)).toBe(sh)
  }
  expect(bashPath(WIN_ROOT)).toBe('C:/Users/tester/.claude/plugins/secret-box')
  const env = { env: { get: async (name: string) => (name === 'SystemRoot' ? 'C:\\Windows' : undefined) } }
  expect(await credmanArgv(env, WIN_ROOT, 'read')).toEqual([POWERSHELL, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', ps1, 'read', '-Stdin'])
  expect(credAddHint(WIN_ROOT, 'NEW_KEY', 'tester')).toBe(`powershell -NoProfile -ExecutionPolicy Bypass -File "${ps1}" add -Service NEW_KEY -Account tester`)
  const read = credReadCommand(WIN_ROOT, "Bob's site", 'bob')
  expect(read).toBe(`"$(${sh} get -s 'Bob'\\''s site' -a bob)"`)
  expect(keychainReads(`printf '%s' ${read} | tee out.txt`, {}, { windows: true })).toEqual([{ kind: 'credman', service: "Bob's site", account: 'bob' }])
  // The shapes the tests above match the host's paths by take these forms, and
  // not bin/credman with a backslash
  expect(sh).toMatch(new RegExp(`^${CREDMAN.source}$`))
  expect(`${bashPath(WIN_ROOT)}/bin/keychain-env`).toMatch(new RegExp(`^${RUNNER.source}$`))
  expect(ps1).toMatch(new RegExp(`^${CREDMAN_PS1.source}$`))
  expect(`${WIN_ROOT}\\bin\\credman`).not.toMatch(new RegExp(`^${CREDMAN.source}$`))
})
