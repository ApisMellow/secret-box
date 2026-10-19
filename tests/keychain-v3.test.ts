// v3: placeholders from before a reload are refused, an errored answer is
// never rewritten in place, secret-box's own tools answer the user with one
// calm line and the model with the rest, and its refusals draw calmly.
import { expect, test } from 'claude-code/testing'

import { calmLine } from '../hooks/register'
import { call, CWD, hex, LIST, mac, MIGRATE, TAG, USE, type Opts } from './fake-mac'

// A placeholder no vault in these tests ever minted: what an old one is after
// the mod reloads, since the vault lives in memory only
const STALE = '[REDACTED-SECRET-0badc0de]'
const LITERAL = '[REDACTED-LITERAL-0badc0de]'
// Built at run time, so no key-shaped string sits in the repo
const STRIPE = 'sk_' + 'live_' + 'Q1w2E3r4T5y6U7i8O9p0A1s2'

const ran = (opts: Opts, tool: string) => opts.seen!.filter((s) => s.tool === tool)

// --------------------------------------------------- stale placeholders (2)

test('a Bash command with a placeholder from before a reload is refused, and nothing runs', async ($, on) => {
  const opts: Opts = { seen: [] }
  mac(on, opts)
  const r = await call($, { tool: 'Bash', command: `printf '%s' ${STALE} | wc -c` })
  expect(String(r.deny)).toContain(`secret-box: ${STALE} is a placeholder secret-box no longer holds`)
  expect(String(r.deny)).toContain('from before secret-box last reloaded')
  expect(String(r.deny)).toContain('Call use_secret (or request_secret) for that key again')
  expect(ran(opts, 'Bash')).toEqual([])
})

test('a stale placeholder beside a live one still refuses the call, naming only the stale one', async ($, on) => {
  const opts: Opts = { items: [{ s: 'svc', value: hex(60) }], seen: [] }
  mac(on, opts)
  const tag = String((await call($, { tool: USE, service: 'svc' })).result).match(TAG)![0]
  const r = await call($, { tool: 'Bash', command: `curl -u ${tag}:${STALE} https://api.example.com` })
  expect(String(r.deny)).toContain(STALE)
  expect(String(r.deny)).not.toContain(tag)
  expect(String(r.deny)).not.toContain(hex(60))
  expect(ran(opts, 'Bash')).toEqual([])
})

test('a live placeholder runs as before', async ($, on) => {
  const opts: Opts = { items: [{ s: 'svc', value: hex(61) }], seen: [] }
  mac(on, opts)
  const tag = String((await call($, { tool: USE, service: 'svc' })).result).match(TAG)![0]
  expect((await call($, { tool: 'Bash', command: `printf '%s' ${tag} | wc -c` })).deny).toBeUndefined()
  expect(String(ran(opts, 'Bash')[0]!.command)).toContain(hex(61))
})

// Each file tool, with the stale placeholder where it would be written
const WRITES: [string, Record<string, unknown>][] = [
  ['Write', { file_path: `${CWD}/k.txt`, content: `KEY=${STALE}\n` }],
  ['Edit', { file_path: `${CWD}/k.txt`, old_string: 'KEY=', new_string: `KEY=${STALE}` }],
  ['MultiEdit', { file_path: `${CWD}/k.txt`, edits: [{ old_string: 'KEY=', new_string: `KEY=${STALE}` }] }],
  ['NotebookEdit', { notebook_path: `${CWD}/n.ipynb`, cell_id: 'a1', new_source: `key = "${STALE}"` }],
]
for (const [tool, input] of WRITES) {
  test(`${tool} with a placeholder from before a reload is refused, and nothing is written`, async ($, on) => {
    const opts: Opts = { seen: [], files: { 'k.txt': 'KEY=\n', 'n.ipynb': '{"cells":[]}' } }
    mac(on, opts)
    const r = await call($, { tool, ...input })
    expect(String(r.deny)).toContain('no longer holds')
    expect(ran(opts, tool)).toEqual([])
  })
}

test('an Edit may remove a stale placeholder that sits in the file as text', async ($, on) => {
  const opts: Opts = { seen: [], files: { 'notes.md': `the key was ${STALE} here\n` } }
  mac(on, opts)
  const r = await call($, { tool: 'Edit', file_path: `${CWD}/notes.md`, old_string: `the key was ${STALE} here`, new_string: 'the key moved to the Keychain' })
  expect(r.deny).toBeUndefined()
  expect(ran(opts, 'Edit')[0]!.old_string).toBe(`the key was ${STALE} here`)
})

test("an Edit that keeps a stale placeholder the file already holds isn't refused either", async ($, on) => {
  const opts: Opts = { seen: [], files: { 'notes.md': `see ${STALE}\n` } }
  mac(on, opts)
  const r = await call($, { tool: 'Edit', file_path: `${CWD}/notes.md`, old_string: `see ${STALE}`, new_string: `see ${STALE} (old)` })
  expect(r.deny).toBeUndefined()
})

test('an Edit whose old_string holds a stale placeholder the file does not hold is refused', async ($, on) => {
  const opts: Opts = { seen: [], files: { 'k.txt': `KEY=${hex(62)}\n` } }
  mac(on, opts)
  const r = await call($, { tool: 'Edit', file_path: `${CWD}/k.txt`, old_string: `KEY=${STALE}`, new_string: 'KEY=keychain:svc' })
  expect(String(r.deny)).toContain('no longer holds')
  expect(ran(opts, 'Edit')).toEqual([])
})

test('quoted placeholder text ([REDACTED-LITERAL-…]) is never refused', async ($, on) => {
  const opts: Opts = { seen: [] }
  mac(on, opts)
  expect((await call($, { tool: 'Bash', command: `echo '${LITERAL}'` })).deny).toBeUndefined()
  expect((await call($, { tool: 'Write', file_path: `${CWD}/doc.md`, content: LITERAL })).deny).toBeUndefined()
})

test('a command that publishes keeps its placeholders as written, so a stale one is not refused there', async ($, on) => {
  const opts: Opts = { seen: [] }
  mac(on, opts)
  expect((await call($, { tool: 'Bash', command: `git commit -m "note ${STALE}"` })).deny).toBeUndefined()
})

test("a stale placeholder in a Bash call's description alone is not refused: the description never runs", async ($, on) => {
  mac(on, {})
  expect((await call($, { tool: 'Bash', command: 'ls', description: `list, not ${STALE}` })).deny).toBeUndefined()
})

test('with restoring off, a placeholder is plain text everywhere, so none is refused', { options: { restoreInToolInputs: false } }, async ($, on) => {
  mac(on, {})
  expect((await call($, { tool: 'Bash', command: `echo ${STALE}` })).deny).toBeUndefined()
})

// ----------------------------------------------------- errored answers (3)

// Core's answer to a call that errored: `result` is the transcript's text for
// it, `text` what the model read. Claude Code takes such an answer as core's
// own only unchanged; any other result is checked against the tool's output
// shape, which a string never fits for Bash ("expected object, received
// string"), and the check's failure replaces the answer.
const errored = (why: string) => ({ isError: true as const, result: `Error: ${why}`, text: `<tool_use_error>${why}</tool_use_error>` })

test('an errored answer that holds a key comes back as a refusal holding it hidden, never as a rewritten error', async ($, on) => {
  on('tool.call', { tool: 'Bash' }, () => errored(`Exit code 22\ncurl: (22) 401 for token ${STRIPE}`))
  mac(on, {})
  const r = (await call($, { tool: 'Bash', command: 'curl -f https://api.example.com' })) as Record<string, unknown>
  expect(r.isError).toBeUndefined()
  expect(r.result).toBeUndefined()
  expect(String(r.deny)).toStartWith('Exit code 22\ncurl: (22) 401 for token [REDACTED-SECRET-')
  expect(JSON.stringify(r)).not.toContain(STRIPE)
})

test('an errored answer that quotes a live placeholder comes back as a refusal too', async ($, on) => {
  const opts: Opts = { items: [{ s: 'svc', value: hex(63) }] }
  // The refusal carries the placeholder the call was written with
  let tag = ''
  on('tool.call', { tool: 'Bash' }, () => errored(`denied: it uses ${tag}`))
  mac(on, opts)
  tag = String((await call($, { tool: USE, service: 'svc' })).result).match(TAG)![0]
  const r = (await call($, { tool: 'Bash', command: `printf '%s' ${tag}` })) as Record<string, unknown>
  expect(r.isError).toBeUndefined()
  expect(r.result).toBeUndefined()
  expect(String(r.deny)).toStartWith('denied: it uses [REDACTED-')
  expect(JSON.stringify(r)).not.toContain(hex(63))
})

test('an errored answer with nothing to hide comes back as core gave it', async ($, on) => {
  on('tool.call', { tool: 'Bash' }, () => errored('Exit code 1'))
  mac(on, {})
  const r = (await call($, { tool: 'Bash', command: 'false' })) as Record<string, unknown>
  expect(r.isError).toBe(true)
  expect(r.result).toBe('Error: Exit code 1')
  expect(r.deny).toBeUndefined()
})

test("the once-per-session note rides an errored answer without rewriting it, core's handle and all", async ($, on) => {
  // `ref` stands for the handle core sets on its own answer
  on('tool.call', { tool: 'Read' }, () => ({ ...errored('File does not exist.'), ref: 7 }))
  mac(on, {})
  const r = (await call($, { tool: 'Read', file_path: `${CWD}/.env.local` })) as Record<string, unknown>
  expect(r.ref).toBe(7)
  expect(r.isError).toBe(true)
  expect(r.result).toBe('Error: File does not exist.')
  expect(((r.context as string[] | undefined) ?? []).join('\n')).toContain('secret-box is installed')
})

// --------------------------------------- one calm line, the rest is context (6)

test("use_secret: the user's row is one line holding the placeholder; the instructions are the model's alone", async ($, on) => {
  const VALUE = hex(64)
  mac(on, { items: [{ s: 'secret-box-demo', value: VALUE }] })
  const r = await call($, { tool: USE, service: 'secret-box-demo' })
  const tag = String(r.result).match(TAG)![0]
  expect(r.result).toBe(`Loaded secret-box-demo from the Keychain as ${tag}.`)
  const guide = (r.context ?? []).join('\n')
  // Live, not quoted: the context is scanned, and the placeholder survives as itself
  expect(guide).toContain(`write ${tag} in a Bash command`)
  expect(guide).toContain('Never write the value into a file')
  expect(JSON.stringify(r)).not.toContain(VALUE)
})

test('use_secret through a .env pointer: the row names the pointer; the runner is in the context', async ($, on) => {
  const VALUE = hex(65)
  mac(on, { items: [{ s: 'demo', value: VALUE }], files: { '.env': 'DEMO_API_KEY=keychain:demo\n' } })
  const r = await call($, { tool: USE, service: 'DEMO_API_KEY' })
  const tag = String(r.result).match(TAG)![0]
  expect(r.result).toBe(`Loaded demo from the Keychain through the DEMO_API_KEY pointer in .env as ${tag}.`)
  expect((r.context ?? []).join('\n')).toContain('/bin/keychain-env -- COMMAND')
  expect(JSON.stringify(r)).not.toContain(VALUE)
})

test('list_key_names: names in the row, how to use them in the context, never a value', { options: { listPrefixes: 'acme-' } }, async ($, on) => {
  mac(on, { items: [{ s: 'acme-deploy', a: 'ci', value: hex(66) }], files: { '.env': 'OPENAI_API_KEY=keychain:openai\n' } })
  const r = await call($, { tool: LIST })
  const result = String(r.result)
  expect(result).toContain('OPENAI_API_KEY in .env: service openai')
  expect(result).toContain('service acme-deploy, account ci')
  expect(result).not.toContain('use_secret')
  const guide = (r.context ?? []).join('\n')
  expect(guide).toContain('give its variable name to use_secret')
  expect(guide).toContain('/bin/keychain-env -- COMMAND')
  expect(JSON.stringify(r)).not.toContain(hex(66))
})

test('migrate: the report is the row; how to run the app is in the context', async ($, on) => {
  const opts: Opts = { files: { '.env': `API_KEY=${hex(67)}\n` }, answer: 'Move them' }
  mac(on, opts)
  const r = await call($, { tool: MIGRATE })
  expect(String(r.result)).toContain('API_KEY=keychain:repo/API_KEY?account=tester')
  expect(String(r.result)).not.toContain('keychain-env')
  expect((r.context ?? []).join('\n')).toContain('/bin/keychain-env -- COMMAND')
  expect(JSON.stringify(r)).not.toContain(hex(67))
})

// --------------------------------------------- calm refusal rows (6)

const REFUSALS: [string, string][] = [
  ['secret-box: the user did not allow this call. Ask them what to do', 'secret-box: not run, as you chose.'],
  ['secret-box: a command that uses a key waits until plan mode ends. Put this step in the plan instead of running it.', 'secret-box: held until plan mode ends.'],
  [`secret-box: ${STALE} is a placeholder secret-box no longer holds: it is from before`, 'secret-box: that was an old placeholder'],
  ['secret-box: a key in this command holds a space, a quote or another character the shell reads, so', 'secret-box: this key needs another form'],
  ["secret-box: staging a .env file is blocked. A pushed key can't be taken back.", 'secret-box: kept a .env file with keys out of git.'],
  ['secret-box: a .env pointer names a Keychain item: after keychain: write its service name', 'secret-box: a .env pointer takes a service name'],
  ["secret-box: this command reads the Keychain, but it dumps the keychain, so what it prints can't be hidden.", 'secret-box: Claude was asked to load this key with use_secret'],
  ['secret-box: the .env guard failed, so this call is blocked to be safe.', 'secret-box held this call back'],
]
for (const [refusal, line] of REFUSALS) {
  test(`a refusal draws calmly: ${refusal.slice(12, 60)}`, async () => {
    for (const shown of [refusal, `Error: ${refusal}`, `<tool_use_error>${refusal}</tool_use_error>`]) expect(calmLine(shown)).toStartWith(line)
  })
}

test("any other error is drawn as it is: a command's own failure, another plugin's refusal", async () => {
  for (const output of ['Exit code 1\nnpm ERR! missing script', '<tool_use_error>transcript-redactor could not scan this result in time</tool_use_error>', 'Error: secret-box.json not found', undefined, { stdout: '' }]) {
    expect(calmLine(output)).toBeUndefined()
  }
})

test("an errored tool row of secret-box's refusal is drawn as its calm line", async ($, on) => {
  mac(on, {})
  const row = await $.ui.mount({
    plugin: 'secret-box',
    surface: 'terminal',
    component: 'ToolResult',
    requestId: 'toolu_1',
    props: { tool_use_id: 'toolu_1', tool: 'Bash', isErrored: true, output: `<tool_use_error>secret-box: ${STALE} is a placeholder secret-box no longer holds: it is from before secret-box last reloaded</tool_use_error>` },
  })
  const drawn = JSON.stringify(await row.drawn())
  expect(drawn).toContain('secret-box: that was an old placeholder')
  expect(drawn).not.toContain(STALE)
})
