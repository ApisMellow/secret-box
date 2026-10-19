// ownApproval: the permission check of a call secret-box filled with real
// values is answered on the call as Claude wrote it (placeholders), so no
// dialog or classifier sees a key. Core's verdict first, then the user's
// rules; then, ownPrompt off (the default), an allow in a mode known to allow
// asking, or, ownPrompt on (or the mode not known), secret-box's own prompt.
// In dontAsk mode core's verdict stands; in plan mode the call is refused.
import { expect, mock, test } from 'claude-code/testing'

import { SECURITY } from '../hooks/keychain'
import { call, hex, security, TAG, USE, type Item } from './fake-mac'

type Decision = 'allow' | 'ask' | 'deny'
type Verdict = { decision: Decision; reason?: string; rule?: string }

// Stand in for Claude Code beneath the mod. A restore tool's call runs the
// permission check (tool.check, with the call's tool_use_id) on the input as
// it will run, the way core's tool.call does, and runs only on allow. A
// refused call answers as core's does: an errored result, the reason its text.
type World = {
  items?: Item[]
  core?: Decision // core's verdict on the call as it will run
  rules?: Decision | 'throws' // a query's verdict: the user's rules on the call as written
  answer?: string // what the person picks; 'dismiss' closes the dialog
  surfaces?: string[]
  mode?: string // the permission mode the classic events report; unset, none is reported
  verdicts?: Verdict[] // what each real call's check came to
  ids?: string[] // each real call's tool_use_id
  coreSaw?: unknown[] // the input core's check was given
  queries?: unknown[] // the input each query was given
  asked?: string[] // the questions put to the person
  ran?: unknown[] // the input of each call that ran
}
const RESTORE = new Set(['Bash', 'Write', 'Edit', 'MultiEdit', 'NotebookEdit'])
const ok = (stdout = '') => ({ value: { exitCode: 0, stdout, stderr: '' as string, isStdoutTruncated: false, isStderrTruncated: false } })

function world($: any, on: any, w: World) {
  const items = (w.items ??= [])
  on('process.run', (_$: unknown, e: { argv: string[] }) => {
    if (e.argv[0] === '/usr/bin/uname' || e.argv[0] === '/bin/uname') return ok('Darwin\n')
    if (e.argv[0] === SECURITY) return { value: { ...security(items, e.argv), isStdoutTruncated: false, isStderrTruncated: false } }
    return ok()
  })
  on('tool.call', async (_$: unknown, e: Record<string, any>) => {
    if (e.tool === 'AskUserQuestion') {
      const questions = e.questions as { question: string }[]
      w.asked?.push(...questions.map((q) => q.question))
      if (w.answer === 'dismiss') return { deny: 'The user dismissed the question.' }
      return { result: { questions, answers: Object.fromEntries(questions.map((q) => [q.question, w.answer ?? 'Deny'])) } }
    }
    if (RESTORE.has(e.tool)) {
      const { tool, tool_use_id, agentId, requestMeta, ...input } = e
      w.ids?.push(tool_use_id)
      const v = (await $.tool.check({ tool, input, tool_use_id })) as Verdict
      w.verdicts?.push(v)
      if (v.decision !== 'allow') {
        const why = v.reason ?? `not run: ${v.decision}`
        return { isError: true, result: `Error: ${why}`, text: `<tool_use_error>${why}</tool_use_error>` }
      }
      w.ran?.push(input)
    }
    return { result: 'ran' }
  })
  on('tool.check', (_$: unknown, e: { input: unknown; tool_use_id?: string }) => {
    if (e.tool_use_id !== undefined) {
      w.coreSaw?.push(e.input)
      return { decision: w.core ?? 'ask' }
    }
    w.queries?.push(e.input)
    if (w.rules === 'throws') throw new Error('rules unreadable')
    return { decision: w.rules ?? 'ask', ...(w.rules === 'allow' ? { rule: 'Bash(curl:*)' } : {}) }
  })
  on('session.cwd', () => ({ value: '/repo' }))
  on('fs.list', () => ({ value: [] }))
  on('fs.exists', () => ({ value: false }))
  on('session.surfaces', () => ({ value: w.surfaces ?? ['terminal'] }))
  // No settings hooks beneath the classic events the mode is read from
  on('classic.UserPromptSubmit', () => ({}))
  on('classic.PostToolUse', () => ({}))
  mock.env(on, { USER: 'tester', HOME: '/Users/tester' })
}

// The prompt that sets the session's mode, as Claude Code reports it to hooks
const prompted = ($: any, mode: string) => $.classic.UserPromptSubmit({ prompt: 'go', permission_mode: mode })

// A Keychain item loaded with use_secret: its placeholder
const VALUE = hex(21)
async function loaded($: any, on: any, w: World) {
  w.items = [{ s: 'openai', a: 'tester', value: VALUE }]
  world($, on, w)
  if (w.mode !== undefined) await prompted($, w.mode)
  return String((await call($, { tool: USE, service: 'openai' })).result).match(TAG)![0]
}
const curl = (tag: string) => `curl -H "Authorization: Bearer ${tag}" https://api.example.com/v1/models`
const PROMPT = { options: { ownPrompt: true } }

// ----------------------------------------------------- both settings alike

test('core allow stands: no query, no prompt, and the call runs with the real value', async ($, on) => {
  const w: World = { core: 'allow', mode: 'default', verdicts: [], queries: [], asked: [], ran: [] }
  const tag = await loaded($, on, w)
  await call($, { tool: 'Bash', command: curl(tag) })
  expect(w.verdicts!.map((v) => v.decision)).toEqual(['allow'])
  expect(w.queries).toEqual([])
  expect(w.asked).toEqual([])
  expect(JSON.stringify(w.ran)).toContain(VALUE)
})

test('core deny stands: no query, no prompt', async ($, on) => {
  const w: World = { core: 'deny', rules: 'allow', answer: 'Allow', mode: 'default', verdicts: [], queries: [], asked: [] }
  const tag = await loaded($, on, w)
  await call($, { tool: 'Bash', command: curl(tag) })
  expect(w.verdicts!.map((v) => v.decision)).toEqual(['deny'])
  expect(w.queries).toEqual([])
  expect(w.asked).toEqual([])
})

test("on ask, the user's rules on the call as written allow it, and the query never holds the real value", async ($, on) => {
  const w: World = { core: 'ask', rules: 'allow', verdicts: [], coreSaw: [], queries: [], asked: [], ran: [] }
  const tag = await loaded($, on, w)
  await call($, { tool: 'Bash', command: curl(tag) })
  expect(w.verdicts!.map((v) => v.decision)).toEqual(['allow'])
  expect(w.verdicts![0]!.rule).toBe('Bash(curl:*)')
  // Core checked the call as it runs; the rules were asked about it as written
  expect(JSON.stringify(w.coreSaw)).toContain(VALUE)
  expect(w.queries).toEqual([{ command: curl(tag) }])
  expect(JSON.stringify(w.queries)).not.toContain(VALUE)
  expect(w.asked).toEqual([])
  expect(JSON.stringify(w.ran)).toContain(VALUE)
})

for (const mode of ['default', 'plan', 'dontAsk']) {
  test(`on ask, the user's rules on the call as written deny it (${mode} mode)`, async ($, on) => {
    const w: World = { core: 'ask', rules: 'deny', answer: 'Allow', mode, verdicts: [], asked: [], ran: [] }
    const tag = await loaded($, on, w)
    const r = await call($, { tool: 'Bash', command: curl(tag) })
    expect(w.verdicts!.map((v) => v.decision)).toEqual(['deny'])
    expect(w.asked).toEqual([])
    expect(w.ran).toEqual([])
    expect(JSON.stringify(r)).not.toContain(VALUE)
  })
}

for (const options of [{ ownPrompt: false }, { ownPrompt: true }]) {
  test(`no interactive surface: core's verdict goes on unchanged, and no prompt opens ${JSON.stringify(options)}`, { options }, async ($, on) => {
    const w: World = { core: 'ask', rules: 'ask', answer: 'Allow', mode: 'default', surfaces: [], verdicts: [], asked: [], ran: [] }
    const tag = await loaded($, on, w)
    await call($, { tool: 'Bash', command: curl(tag) })
    expect(w.verdicts!.map((v) => v.decision)).toEqual(['ask'])
    expect(w.asked).toEqual([])
    expect(w.ran).toEqual([])
  })

  // dontAsk refuses what no rule allows, with no dialog: the mode settles
  // core's ask as it would any call's, so nothing is allowed here
  test(`dontAsk mode: core's verdict stands, never an allow and never a prompt ${JSON.stringify(options)}`, { options }, async ($, on) => {
    const w: World = { core: 'ask', rules: 'ask', answer: 'Allow', mode: 'dontAsk', verdicts: [], asked: [], ran: [] }
    const tag = await loaded($, on, w)
    await call($, { tool: 'Bash', command: curl(tag) })
    expect(w.verdicts!.map((v) => v.decision)).toEqual(['ask'])
    expect(w.asked).toEqual([])
    expect(w.ran).toEqual([])
  })

  // Plan mode: core's ask would open Claude Code's own dialog with the real
  // value in it, so the call is refused, calmly, whoever is there to ask
  for (const surfaces of [['terminal'], []]) {
    test(`plan mode: a call no rule decides is refused, never asked about ${JSON.stringify(options)}${surfaces.length ? '' : ', no surface'}`, { options }, async ($, on) => {
      const w: World = { core: 'ask', rules: 'ask', answer: 'Allow', mode: 'plan', surfaces, verdicts: [], asked: [], ran: [] }
      const tag = await loaded($, on, w)
      const r = await call($, { tool: 'Bash', command: curl(tag) })
      expect(w.verdicts!.map((v) => v.decision)).toEqual(['deny'])
      expect(w.verdicts![0]!.reason).toBe('secret-box: a command that uses a key waits until plan mode ends. Put this step in the plan instead of running it.')
      expect(w.asked).toEqual([])
      expect(w.ran).toEqual([])
      expect(JSON.stringify(r)).not.toContain(VALUE)
    })
  }
}

test('plan mode: a file change that uses a key is refused the same way', async ($, on) => {
  const w: World = { core: 'ask', rules: 'ask', mode: 'plan', verdicts: [], asked: [] }
  const tag = await loaded($, on, w)
  await call($, { tool: 'Write', file_path: '/repo/k.txt', content: `KEY=${tag}\n` })
  expect(w.verdicts![0]!.decision).toBe('deny')
  expect(w.verdicts![0]!.reason).toStartWith('secret-box: a file change that uses a key waits until plan mode ends.')
  expect(w.asked).toEqual([])
})

// In plan mode, core's verdict and then the user's rules still come first
for (const [name, given, decision] of [
  ['core allows', { core: 'allow', rules: 'ask' }, 'allow'],
  ['core denies', { core: 'deny', rules: 'allow' }, 'deny'],
  ['the rules allow', { core: 'ask', rules: 'allow' }, 'allow'],
] as [string, World, Decision][]) {
  test(`plan mode: ${name}, and that stands`, async ($, on) => {
    const w: World = { ...given, mode: 'plan', verdicts: [], asked: [] }
    const tag = await loaded($, on, w)
    await call($, { tool: 'Bash', command: curl(tag) })
    expect(w.verdicts!.map((v) => v.decision)).toEqual([decision])
    expect(w.verdicts![0]!.reason ?? '').not.toContain('plan mode ends')
    expect(w.asked).toEqual([])
  })
}

// ------------------------------------------------- ownPrompt off (default)

for (const mode of ['default', 'acceptEdits', 'auto']) {
  test(`ownPrompt off, ${mode} mode: a call no rule decides is allowed with no prompt, and runs with the real value`, async ($, on) => {
    const w: World = { core: 'ask', rules: 'ask', answer: 'Deny', mode, verdicts: [], queries: [], asked: [], ran: [] }
    const tag = await loaded($, on, w)
    const r = await call($, { tool: 'Bash', command: curl(tag) })
    expect(w.verdicts!.map((v) => v.decision)).toEqual(['allow'])
    expect(w.verdicts![0]!.reason).toContain('secret-box')
    expect(w.verdicts![0]!.reason).not.toContain(VALUE)
    // The rules were still asked first, about the call as written
    expect(w.queries).toEqual([{ command: curl(tag) }])
    expect(w.asked).toEqual([])
    expect(JSON.stringify(w.ran)).toContain(VALUE)
    expect(JSON.stringify(r)).not.toContain(VALUE)
  })
}

test('ownPrompt off: the latest mode reported counts, so plan after default holds the call', async ($, on) => {
  const w: World = { core: 'ask', rules: 'ask', mode: 'default', verdicts: [], asked: [], ran: [] }
  const tag = await loaded($, on, w)
  await prompted($, 'plan')
  await call($, { tool: 'Bash', command: curl(tag) })
  expect(w.verdicts!.map((v) => v.decision)).toEqual(['deny'])
  expect(w.ran).toEqual([])
})

test("ownPrompt off: a mode a subagent's loop reports is that loop's, not the main one's", async ($, on) => {
  const w: World = { core: 'ask', rules: 'ask', mode: 'default', verdicts: [], asked: [], ran: [] }
  const tag = await loaded($, on, w)
  await $.classic.PostToolUse({ tool_name: 'Read', tool_input: {}, tool_response: {}, tool_use_id: 'toolu_sub', agent_id: 'sub-1', permission_mode: 'dontAsk' })
  await call($, { tool: 'Bash', command: curl(tag) })
  expect(w.verdicts!.map((v) => v.decision)).toEqual(['allow'])
})

test("ownPrompt off, the mode not known yet: secret-box's prompt, never an allow on its own", async ($, on) => {
  const w: World = { core: 'ask', rules: 'ask', answer: 'Deny', verdicts: [], asked: [], ran: [] }
  const tag = await loaded($, on, w)
  await call($, { tool: 'Bash', command: curl(tag) })
  expect(w.asked).toHaveLength(1)
  expect(w.verdicts!.map((v) => v.decision)).toEqual(['deny'])
  expect(w.ran).toEqual([])
})

test('ownPrompt off, an unfamiliar mode: the prompt too', async ($, on) => {
  const w: World = { core: 'ask', rules: 'ask', answer: 'Allow', mode: 'someNewMode', verdicts: [], asked: [], ran: [] }
  const tag = await loaded($, on, w)
  await call($, { tool: 'Bash', command: curl(tag) })
  expect(w.asked).toHaveLength(1)
  expect(w.verdicts!.map((v) => v.decision)).toEqual(['allow'])
})

// ----------------------------------------------------------- ownPrompt on

test('ownPrompt on: the person sees the call as written and the key names, never the value, and Allow runs it', PROMPT, async ($, on) => {
  const w: World = { core: 'ask', rules: 'ask', answer: 'Allow', mode: 'auto', verdicts: [], asked: [], ran: [] }
  const tag = await loaded($, on, w)
  await call($, { tool: 'Bash', command: curl(tag) })
  expect(w.asked).toHaveLength(1)
  const question = w.asked![0]!
  expect(question).toStartWith(curl(tag))
  expect(question).toContain(`It uses the Keychain item openai (${tag}).`)
  expect(question).toEndWith('The key is filled in only while it runs, and no one sees it. Allow this command?')
  expect(question).not.toContain('real value')
  expect(question).not.toContain(VALUE)
  expect(w.verdicts!.map((v) => v.decision)).toEqual(['allow'])
  expect(JSON.stringify(w.ran)).toContain(VALUE)
})

test('ownPrompt on: Deny refuses the call calmly, and the refusal holds no value and no placeholder', PROMPT, async ($, on) => {
  const w: World = { core: 'ask', rules: 'ask', answer: 'Deny', mode: 'default', verdicts: [], asked: [], ran: [] }
  const tag = await loaded($, on, w)
  const r = await call($, { tool: 'Bash', command: curl(tag) })
  expect(w.asked).toHaveLength(1)
  expect(w.verdicts!.map((v) => v.decision)).toEqual(['deny'])
  expect(w.verdicts![0]!.reason).toContain('did not allow')
  expect(w.verdicts![0]!.reason).not.toMatch(TAG)
  expect(w.ran).toEqual([])
  expect(JSON.stringify([r, w.verdicts])).not.toContain(VALUE)
})

test('ownPrompt on: a dismissed prompt is a deny', PROMPT, async ($, on) => {
  const w: World = { core: 'ask', rules: 'ask', answer: 'dismiss', mode: 'default', verdicts: [], asked: [], ran: [] }
  const tag = await loaded($, on, w)
  await call($, { tool: 'Bash', command: curl(tag) })
  expect(w.asked).toHaveLength(1)
  expect(w.verdicts!.map((v) => v.decision)).toEqual(['deny'])
  expect(w.ran).toEqual([])
})

test('ownPrompt on: a Write with a placeholder is shown as written, the file path and content in placeholder form', PROMPT, async ($, on) => {
  const w: World = { core: 'ask', rules: 'ask', answer: 'Allow', mode: 'default', verdicts: [], asked: [], ran: [] }
  const tag = await loaded($, on, w)
  await call($, { tool: 'Write', file_path: '/repo/k.txt', content: `KEY=${tag}\n` })
  const question = w.asked![0]!
  expect(question).toContain('/repo/k.txt')
  expect(question).toContain(tag)
  expect(question).toEndWith('Allow this Write?')
  expect(question).not.toContain(VALUE)
  expect(w.verdicts!.map((v) => v.decision)).toEqual(['allow'])
})

test('ownPrompt on: a value hidden from output, with no name, is listed by its placeholder', PROMPT, async ($, on) => {
  // Built at run time, so no key-shaped string sits in the repo
  const STRIPE = 'sk_' + 'live_' + '4eC39Hq' + 'LyjWDarjtT1zdp7dc'
  const w: World = { core: 'ask', rules: 'ask', answer: 'Deny', mode: 'default', asked: [] }
  // Registered first, so it stands above the world's stub (first is outermost)
  on('tool.call', { tool: 'Read' }, () => ({ result: `key is ${STRIPE}` }))
  world($, on, w)
  await prompted($, 'default')
  const tag = String((await call($, { tool: 'Read', file_path: '/repo/key.txt' })).result).match(TAG)![0]
  await call($, { tool: 'Bash', command: `echo ${tag} | wc -c` })
  expect(w.asked![0]).toContain(`It uses ${tag}.`)
  expect(w.asked![0]).not.toContain(STRIPE)
})

// With the prompt on, an allow comes only from core, the user's rules or the
// person: a call that no rule allows and no person allows is never allowed
const NO_ALLOW: [string, World][] = [
  ['no rule, no surface', { rules: 'ask', surfaces: [] }],
  ['rules unreadable, no surface', { rules: 'throws', surfaces: [] }],
  ['no rule, the person says Deny', { rules: 'ask', answer: 'Deny' }],
  ['no rule, the person dismisses the prompt', { rules: 'ask', answer: 'dismiss' }],
  ['no rule, the person types other text', { rules: 'ask', answer: 'allow it, please' }],
  ['no rule, the person types lowercase allow', { rules: 'ask', answer: 'allow' }],
  ['rules unreadable, the person says Deny', { rules: 'throws', answer: 'Deny' }],
]
for (const [name, given] of NO_ALLOW) {
  test(`ownPrompt on, never allowed without a rule or the person: ${name}`, PROMPT, async ($, on) => {
    const w: World = { ...given, core: 'ask', mode: 'default', verdicts: [], ran: [] }
    const tag = await loaded($, on, w)
    await call($, { tool: 'Bash', command: curl(tag) })
    expect(w.verdicts).toHaveLength(1)
    expect(w.verdicts![0]!.decision).not.toBe('allow')
    expect(w.ran).toEqual([])
  })
}

// ------------------------------------------------------- calls left alone

test('a call with no placeholder put back is untouched: no query, no prompt', async ($, on) => {
  const w: World = { core: 'ask', rules: 'allow', answer: 'Allow', verdicts: [], queries: [], asked: [] }
  world($, on, w)
  await prompted($, 'default')
  await call($, { tool: 'Bash', command: 'npm test' })
  expect(w.verdicts!.map((v) => v.decision)).toEqual(['ask'])
  expect(w.queries).toEqual([])
  expect(w.asked).toEqual([])
})

test('a command that publishes keeps its placeholders, so it is untouched', async ($, on) => {
  const w: World = { core: 'ask', rules: 'allow', answer: 'Allow', mode: 'default', verdicts: [], queries: [], asked: [] }
  const tag = await loaded($, on, w)
  await call($, { tool: 'Bash', command: `git commit -m "rotate ${tag}"` })
  expect(w.verdicts!.map((v) => v.decision)).toEqual(['ask'])
  expect(w.queries).toEqual([])
  expect(w.asked).toEqual([])
})

test('a query (no tool_use_id) passes through, even one naming a placeholder', async ($, on) => {
  const w: World = { core: 'allow', rules: 'ask', answer: 'Allow', mode: 'default', asked: [] }
  const tag = await loaded($, on, w)
  const v = (await $.tool.check({ tool: 'Bash', input: { command: curl(tag) } })) as Verdict
  expect(v.decision).toBe('ask')
  expect(w.asked).toEqual([])
})

test('the record is dropped once the call ends, and once it is refused', async ($, on) => {
  const w: World = { core: 'allow', rules: 'allow', answer: 'Allow', mode: 'default', ids: [], queries: [], asked: [] }
  const tag = await loaded($, on, w)
  await call($, { tool: 'Bash', command: curl(tag) })
  w.core = 'deny'
  await call($, { tool: 'Bash', command: curl(tag) })
  expect(w.ids).toHaveLength(2)
  // A late check under either id is no longer one of secret-box's calls
  w.core = 'ask'
  for (const tool_use_id of w.ids!) {
    const v = (await $.tool.check({ tool: 'Bash', input: { command: curl(tag) }, tool_use_id })) as Verdict
    expect(v.decision).toBe('ask')
  }
  expect(w.queries).toEqual([])
  expect(w.asked).toEqual([])
})

test("ownApproval off: core's verdict on the call as it runs, no query, no prompt", { options: { ownApproval: false } }, async ($, on) => {
  const w: World = { core: 'ask', rules: 'allow', answer: 'Allow', mode: 'default', verdicts: [], queries: [], asked: [] }
  const tag = await loaded($, on, w)
  await call($, { tool: 'Bash', command: curl(tag) })
  expect(w.verdicts!.map((v) => v.decision)).toEqual(['ask'])
  expect(w.queries).toEqual([])
  expect(w.asked).toEqual([])
})

test('a tool that gets no real values is untouched', { options: { restoreTools: 'Bash' } }, async ($, on) => {
  const w: World = { core: 'ask', rules: 'allow', answer: 'Allow', mode: 'default', verdicts: [], queries: [], asked: [] }
  const tag = await loaded($, on, w)
  // Write is no restore tool here: its placeholder stays one, and its check is core's
  await call($, { tool: 'Write', file_path: '/repo/k.txt', content: tag })
  expect(w.verdicts!.map((v) => v.decision)).toEqual(['ask'])
  expect(w.queries).toEqual([])
  expect(w.asked).toEqual([])
})
