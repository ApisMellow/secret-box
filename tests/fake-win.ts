// The Windows beneath secret-box in its tests: OS=Windows_NT, a Credential
// Manager that bin/credman.ps1 answers for the way the real one does, a
// project folder of files, git, the waits, and the dialogs.
import { mock } from 'claude-code/testing'

import { hexOf, unixPath } from './fake-mac'

export { BOX, call, hex, hexOf, LIST, MIGRATE, TAG, unixPath, USE, type Answer } from './fake-mac'

export const CWD = '/repo'
export const ENV = { OS: 'Windows_NT', USERNAME: 'tester', SystemRoot: 'C:\\Windows' }
export const POWERSHELL = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'

// A generic credential: its target name (the service), user name (the
// account), comment, and value. `bytes` marks a value that is not text.
export type Cred = { target: string; user?: string; comment?: string; value: string; bytes?: boolean }

export type WinOpts = {
  creds?: Cred[]
  env?: Record<string, string> // in place of ENV
  cwd?: string // the session's folder (CWD by default); C:\x\y works too
  toasts?: string[]
  fail?: { exitCode: number; stdout: string; stderr: string } // every credman.ps1 call answers this instead
  deny?: string // every credman.ps1 call is refused (it could not start, or timed out)
  truncated?: boolean // credman.ps1's answer was cut off
  tamper?: boolean // Credential Manager keeps something other than what is set
  listCut?: boolean // list's answer was cut off
  argvs?: string[][]
  stdins?: string[] // the raw stdin of each credman.ps1 call
  log?: string[]
  seen?: Record<string, unknown>[]
  output?: string | ((command: string) => string)
  files?: Record<string, string> // the project folder: name -> text
  writes?: { path: string; text: string }[]
  git?: { index?: string; tree?: string; show?: Record<string, string> }
  check?: 'allow' | 'ask' | 'deny'
  answer?: string // what the user picks in a dialog
  asked?: string[]
  opened?: string[]
  clock?: { sleep: (ms: number) => Promise<void> }
}

// Hex of UTF-8 bytes back to text, as credman.ps1 reads its stdin
export const fromHex = (h: string) => decodeURIComponent(h.replace(/../g, '%$&'))

// A powershell.exe run of credman.ps1: which command, or undefined for any other argv
export function credmanCommand(argv: readonly string[]) {
  if (!/(?:^|[\\/])powershell\.exe$/i.test(argv[0] ?? '')) return undefined
  const at = argv.findIndex((a) => /(?:^|[\\/])credman\.ps1$/i.test(a))
  return at < 0 ? undefined : argv[at + 1] ?? ''
}
export const credmanCalls = (argvs: string[][]) => argvs.filter((a) => credmanCommand(a) !== undefined)

// Answers one credman.ps1 run as the real script does (see its top): read,
// exists, set and list, with its exit codes and output shapes
export function credman(creds: Cred[], argv: readonly string[], stdin: string | undefined, opts: { tamper?: boolean } = {}) {
  const command = credmanCommand(argv)!
  const out = (exitCode: number, stdout = '', stderr = '') => ({ exitCode, stdout, stderr })
  if (command === 'list') return out(0, creds.map((c) => `${hexOf(c.target)} ${hexOf(c.user ?? '')} ${hexOf(c.comment ?? '')}\n`).join(''))
  if (!argv.includes('-Stdin')) return out(2, '', 'credman: usage\n')
  const lines = String(stdin ?? '').split(/\r?\n/)
  const [service, account] = [fromHex(lines[0] ?? ''), lines.length > 1 ? fromHex(lines[1] ?? '') : '']
  if (!service) return out(2, '', `credman: ${command} needs -Service\n`)
  const cred = creds.find((c) => c.target === service)
  const found = cred && (!account || (cred.user ?? '') === account) ? cred : undefined
  if (command === 'read') {
    if (!found) return out(44)
    return out(0, `ok ${hexOf(found.user ?? '')} ${found.bytes ? 'bytes' : 'text'} ${hexOf(found.value)}\n`)
  }
  if (command === 'exists') return out(found ? 0 : 44)
  if (command === 'set') {
    if (lines.length < 3 || lines[2] === undefined) return out(2, '', 'credman: set needs the value on the third line of stdin\n')
    if (!account) return out(2, '', 'credman: set needs an account\n')
    if (cred && (cred.user ?? '') && cred.user !== account) {
      return out(5, '', `credman: the service '${service}' is held under the account '${cred.user}'; Credential Manager keeps one account per service\n`)
    }
    const saved: Cred = { target: service, user: account, comment: 'secret-box', value: fromHex(lines[2]) + (opts.tamper ? 'X' : '') }
    if (cred) creds[creds.indexOf(cred)] = saved
    else creds.push(saved)
    return out(0)
  }
  return out(2, '', 'credman: usage\n')
}

// Stand in for Windows beneath the mod
export function win(on: any, opts: WinOpts = {}) {
  const creds = (opts.creds ??= [])
  const files = (opts.files ??= {})
  const cwd = opts.cwd ?? CWD
  const folder = unixPath(cwd).replace(/\/+$/, '')
  // Core hands the fs mocks the path it resolved on the host. On Windows that
  // is C:\repo\.env. A Mac or Linux host takes a drive-letter folder for a
  // relative one and puts its own folder first
  // (/x/secret-box/C:\Users\tester\dev\myapp/.env), so that prefix comes off.
  // Then the drive comes off and the separators become /.
  const hostPath = (raw: string) => unixPath(String(raw).replace(/^\/(?:[^/]*\/)*?(?=[A-Za-z]:[\\/])/, ''))
  const inFolder = (raw: string) => {
    const path = hostPath(raw)
    return path.toLowerCase().startsWith(`${folder.toLowerCase()}/`) ? path.slice(folder.length + 1) : path
  }
  on('process.run', async (_$: unknown, e: { argv: string[]; init?: { stdin?: string } }) => {
    opts.argvs?.push([...e.argv])
    opts.log?.push(`process.run ${e.argv.slice(0, 2).join(' ')}`)
    const answer = (r: { exitCode: number; stdout: string; stderr: string }, cut = false) => ({
      value: { isStdoutTruncated: cut, isStderrTruncated: false, ...r },
    })
    const ok = (stdout = '') => answer({ exitCode: 0, stdout, stderr: '' })
    // Windows has no uname: a run of one is a bug, so it fails as it would
    if (/uname$/.test(e.argv[0] ?? '')) return { deny: `${e.argv[0]} failed to start: ENOENT` }
    if (['node', 'ping', 'sleep'].includes(e.argv[0]!)) {
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
    const command = credmanCommand(e.argv)
    if (command === undefined) return ok()
    opts.stdins?.push(e.init?.stdin ?? '')
    if (opts.deny) return { deny: opts.deny }
    if (opts.fail) return answer(opts.fail)
    const r = credman(creds, e.argv, e.init?.stdin, opts)
    return answer(r, command === 'list' ? Boolean(opts.listCut) : command === 'read' ? Boolean(opts.truncated) : false)
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
  on('session.cwd', () => ({ value: cwd }))
  on('fs.list', () => ({ value: Object.keys(files).map((name) => ({ name, kind: 'file', size: files[name]!.length })) }))
  on('fs.exists', (_$: unknown, e: { path: string }) => ({ value: inFolder(e.path) in files }))
  on('fs.read', (_$: unknown, e: { path: string }) => {
    const name = inFolder(e.path)
    return name in files ? { value: files[name] } : { deny: `ENOENT: ${e.path}` }
  })
  on('fs.write', (_$: unknown, e: { path: string; text: string }) => {
    opts.writes?.push({ path: hostPath(e.path), text: e.text })
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
  mock.env(on, opts.env ?? ENV)
}

// Raise session.start and return what the mod registered
export async function registeredWin($: any, on: any, opts: WinOpts) {
  const specs: Record<string, any>[] = []
  win(on, opts)
  on('tool.register', (_$: unknown, e: Record<string, any>) => {
    specs.push(e)
    return { value: { tool: `mcp__secret-box__${e.name}` } }
  })
  const cwd = opts.cwd ?? CWD
  on('session.start', () => ({ cwd }))
  await $.session.start({ cwd, surface: 'terminal', isInteractive: true })
  return specs
}
