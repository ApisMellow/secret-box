// The Mac beneath secret-box in its tests: uname, a `security` that answers
// like the real one, a project folder of files, git, and the dialogs.
import { mock } from 'claude-code/testing'

import { MACOS_VERSION_FILE, SECURITY } from '../hooks/keychain'

export const USE = 'mcp__secret-box__use_secret'
export const BOX = 'mcp__secret-box__request_secret'
export const LIST = 'mcp__secret-box__list_key_names'
export const MIGRATE = 'mcp__secret-box__migrate_env_to_keychain'
export const TAG = /\[REDACTED-SECRET-[0-9a-f]{8}\]/
export const HOME = '/Users/tester'
export const LOGIN = `${HOME}/Library/Keychains/login.keychain-db`
export const OTHER = `${HOME}/Library/Keychains/other.keychain-db`
export const CWD = '/repo'

// Fake Keychain values, built at run time: 48 hex characters, the shape of
// `openssl rand -hex 24`. Bare hex is a shape the detector leaves alone (it
// could be a hash), so only the vault can hide it.
export const hex = (seed: number) => Array.from({ length: 48 }, (_, i) => ((i * 7 + seed * 5) % 16).toString(16)).join('')

// What /usr/bin/security prints, from its real output on macOS (pinned in
// keychain.test.ts): -w prints the text, or lowercase hex when any byte is
// not printable ASCII; -g prints `password: "text"`, or hex and an escaped
// copy when any byte is not printable or is " or \, or `password: ` for an
// empty one. Attributes print the same way.
export const utf8 = (v: string) => (encodeURIComponent(v).match(/%..|./g) || []).map((c) => (c.length === 3 ? parseInt(c.slice(1), 16) : c.charCodeAt(0)))
export const hexOf = (v: string) => utf8(v).map((b) => b.toString(16).padStart(2, '0')).join('')
const isPrintable = (v: string) => utf8(v).every((b) => b >= 0x20 && b < 0x7f)
export const wOutput = (v: string) => (isPrintable(v) ? v : hexOf(v)) + '\n'
const shown = (v: string) => {
  if (isPrintable(v) && !/["\\]/.test(v)) return `"${v}"`
  const escaped = utf8(v).map((b) => (b >= 0x20 && b < 0x7f && b !== 0x5c ? String.fromCharCode(b) : '\\' + b.toString(8).padStart(3, '0'))).join('')
  return `0x${hexOf(v).toUpperCase()}  "${escaped}"`
}
export const gLine = (v: string) => (v === '' ? 'password: \n' : `password: ${shown(v)}\n`)

// An item, keyed by everything a read can match on: its kind, the match
// options by flag letter (s service or server, a account, l label, j comment,
// r protocol, P port, ...) and the keychain file it lives in.
export type Item = { kind?: 'generic' | 'internet'; keychain?: string; value: string } & Record<string, string | undefined>

// Answers one `security find-*-password` argv the way the real one does:
// getopt over the options, then the keychain files (none means the search
// list, here the login keychain); the first item matching every option.
export function security(items: Item[], argv: string[]) {
  const kind = argv[1] === 'find-internet-password' ? 'internet' : 'generic'
  const criteria: [string, string][] = []
  let g = false
  let w = false
  let k = 2
  for (; k < argv.length && argv[k]!.startsWith('-'); k++) {
    if (argv[k] === '-g') g = true
    else if (argv[k] === '-w') w = true
    else criteria.push([argv[k]!.slice(1), argv[++k]!])
  }
  const keychains = argv.slice(k)
  const item = items.find(
    (it) =>
      (it.kind ?? 'generic') === kind &&
      criteria.every(([f, v]) => it[f] === v) &&
      (keychains.length ? keychains : [LOGIN]).includes(it.keychain ?? LOGIN),
  )
  if (!item) return { exitCode: 44, stdout: '', stderr: 'security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.\n' }
  if (w) return { exitCode: 0, stdout: wOutput(item.value), stderr: '' }
  const attributes = `keychain: "${item.keychain ?? LOGIN}"\nclass: "${kind === 'generic' ? 'genp' : 'inet'}"\nattributes:\n    "acct"<blob>="${item.a ?? ''}"\n`
  return { exitCode: 0, stdout: attributes, stderr: g ? gLine(item.value) : '' }
}

// `security dump-keychain` (no -d) over the items: attributes, never a password
export function dumpOf(items: Item[]) {
  const attr = (v: string | undefined) => (v === undefined ? '<NULL>' : shown(v))
  return items
    .map((it) =>
      [
        `keychain: "${it.keychain ?? LOGIN}"`,
        'version: 512',
        `class: "${(it.kind ?? 'generic') === 'generic' ? 'genp' : 'inet'}"`,
        'attributes:',
        `    0x00000007 <blob>=${attr(it.l ?? it.s)}`,
        '    0x00000008 <blob>=<NULL>',
        `    "acct"<blob>=${attr(it.a)}`,
        '    "cdat"<timedate>=0x32303236313031363137303332325A00  "20261016170322Z\\000"',
        `    "icmt"<blob>=${attr(it.j)}`,
        `    "${(it.kind ?? 'generic') === 'generic' ? 'svce' : 'srvr'}"<blob>=${attr(it.s)}`,
        '    "type"<uint32>=<NULL>',
      ].join('\n'),
    )
    .join('\n')
}

export type Answer = { deny?: string; result?: unknown; context?: string[] }
export const call = async ($: any, input: Record<string, unknown>) => (await $.tool.call(input as never)) as Answer

export type Opts = {
  items?: Item[]
  platform?: 'Darwin' | 'Linux'
  uname?: 'both' | 'bin-only' | 'none' // which of /usr/bin/uname and /bin/uname run (both by default)
  versionFile?: 'present' | 'absent' | 'fails' // macOS's SystemVersion.plist, asked when no uname answers
  env?: Record<string, string> // in place of USER and HOME
  toasts?: string[]
  fail?: { exitCode: number; stdout: string; stderr: string } // every security call answers this instead
  deny?: string // every security call is refused (it could not start, or timed out)
  truncated?: boolean // security's answer was cut off
  tamper?: boolean // the Keychain keeps something other than what is added
  dumpCut?: boolean // dump-keychain's answer was cut off
  argvs?: string[][]
  log?: string[]
  seen?: Record<string, unknown>[]
  output?: string | ((command: string) => string)
  files?: Record<string, string> // the project folder (CWD): name -> text
  writes?: { path: string; text: string }[]
  git?: { index?: string; tree?: string; show?: Record<string, string> }
  check?: 'allow' | 'ask' | 'deny' // the engine's permission verdict
  answer?: string // what the user picks in a dialog
  asked?: string[]
  opened?: string[]
  clock?: { sleep: (ms: number) => Promise<void> }
}

// On Windows core hands the fs mocks the path resolved (C:\repo\.env), so a
// path is read with its drive taken off and its separators made /
export const unixPath = (path: string) => String(path).replace(/^[A-Za-z]:(?=[\\/])/, '').replace(/\\/g, '/')
const inFolder = (raw: string) => {
  const path = unixPath(raw)
  return path.startsWith(`${CWD}/`) ? path.slice(CWD.length + 1) : path
}

// Stand in for the Mac beneath the mod
export function mac(on: any, opts: Opts = {}) {
  const items = (opts.items ??= [])
  const files = (opts.files ??= {})
  on('process.run', async (_$: unknown, e: { argv: string[] }) => {
    opts.argvs?.push([...e.argv])
    opts.log?.push(`process.run ${e.argv.slice(0, 2).join(' ')}`)
    const answer = (r: { exitCode: number; stdout: string; stderr: string }, cut = false) => ({
      value: { isStdoutTruncated: cut, isStderrTruncated: Boolean(opts.truncated), ...r },
    })
    const ok = (stdout = '') => answer({ exitCode: 0, stdout, stderr: '' })
    if (e.argv[0] === '/usr/bin/uname' || e.argv[0] === '/bin/uname') {
      const runs = opts.uname === 'none' ? false : opts.uname === 'bin-only' ? e.argv[0] === '/bin/uname' : true
      return runs ? ok(`${opts.platform ?? 'Darwin'}\n`) : { deny: `${e.argv[0]} failed to start: ENOENT` }
    }
    if (e.argv[0] === 'sleep') {
      await opts.clock?.sleep(300)
      return ok()
    }
    if (e.argv[0] === 'git') {
      const g = opts.git ?? {}
      const sub = e.argv.find((a) => ['diff', 'ls-files', 'show'].includes(a))
      if (sub === 'diff') return ok(g.index ?? '')
      if (sub === 'ls-files') return ok(g.tree ?? '')
      const path = e.argv.at(-1)!.replace(/^:/, '')
      return g.show?.[path] !== undefined ? ok(g.show[path]) : answer({ exitCode: 128, stdout: '', stderr: 'fatal' })
    }
    if (e.argv[0] !== SECURITY) return ok()
    if (opts.deny) return { deny: opts.deny }
    if (opts.fail) return answer(opts.fail)
    if (e.argv[1] === 'dump-keychain') return answer({ exitCode: 0, stdout: dumpOf(items), stderr: '' }, Boolean(opts.dumpCut))
    if (e.argv[1] === 'add-generic-password') {
      const flag = (f: string) => e.argv[e.argv.indexOf(f) + 1]
      const added: Item = { s: flag('-s'), a: flag('-a'), j: e.argv.includes('-j') ? flag('-j') : undefined, value: flag('-w')! + (opts.tamper ? 'X' : '') }
      const at = items.findIndex((it) => it.s === added.s && it.a === added.a)
      if (at >= 0) items[at] = added
      else items.push(added)
      return ok()
    }
    return answer(security(items, e.argv))
  })
  on('tool.call', (_$: unknown, e: Record<string, any>) => {
    if (e.tool === 'AskUserQuestion') {
      const questions = e.questions as { question: string }[]
      opts.asked?.push(...questions.map((q) => q.question))
      return { result: { questions, answers: Object.fromEntries(questions.map((q) => [q.question, opts.answer ?? 'Cancel'])) } }
    }
    opts.seen?.push({ ...e })
    opts.log?.push(`tool ${String(e.tool)}`)
    const out = opts.output
    return { result: typeof out === 'function' ? out(String(e.command ?? '')) : out ?? 'ran' }
  })
  on('tool.check', () => ({ decision: opts.check ?? 'ask' }))
  on('session.cwd', () => ({ value: CWD }))
  on('fs.list', () => ({ value: Object.keys(files).map((name) => ({ name, kind: 'file', size: files[name]!.length })) }))
  on('fs.exists', (_$: unknown, e: { path: string }) => {
    if (unixPath(e.path) === MACOS_VERSION_FILE) return opts.versionFile === 'fails' ? { deny: 'not allowed' } : { value: opts.versionFile === 'present' }
    return { value: inFolder(e.path) in files }
  })
  on('fs.read', (_$: unknown, e: { path: string }) => {
    const name = inFolder(e.path)
    return name in files ? { value: files[name] } : { deny: `ENOENT: ${e.path}` }
  })
  on('fs.write', (_$: unknown, e: { path: string; text: string }) => {
    opts.writes?.push({ path: unixPath(e.path), text: e.text })
    files[inFolder(e.path)] = e.text
    return { value: undefined }
  })
  on('ui.toast', (_$: unknown, e: { text: string }) => {
    opts.toasts?.push(String(e.text))
    return { value: undefined }
  })
  on('session.surfaces', () => ({ value: ['terminal'] }))
  on('ui.open', (_$: unknown, e: { id: string }) => {
    opts.opened?.push(e.id)
    return { value: { isPlaced: true } }
  })
  on('ui.close', () => ({ value: undefined }))
  mock.env(on, opts.env ?? { USER: 'tester', HOME })
}

export const securityCalls = (argvs: string[][]) => argvs.filter((a) => a[0] === SECURITY)

// Raise session.start and return what the mod registered
export async function registered($: any, on: any, opts: Opts) {
  const specs: Record<string, any>[] = []
  mac(on, opts)
  on('tool.register', (_$: unknown, e: Record<string, any>) => {
    specs.push(e)
    return { value: { tool: `mcp__secret-box__${e.name}` } }
  })
  on('session.start', () => ({ cwd: CWD }))
  await $.session.start({ cwd: CWD, surface: 'terminal', isInteractive: true })
  return specs
}
