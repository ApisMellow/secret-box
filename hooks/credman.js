// The Windows Credential Manager backend: secrets live in Credential Manager
// as generic credentials, not in a plaintext .env, and Claude only ever holds
// placeholders. It mirrors keychain.js: the service is the credential's target
// name, the account its user name, and the mod tags what it saves with the
// comment `secret-box`.
//
// Every call runs bin/credman.ps1 under Windows PowerShell, by its full path
// and by argv through $.process.run, never a shell. The names and the value go
// in on stdin as hex lines, so none of them sits in a command line (any
// process of this user can read one) and no quoting can go wrong. Nothing here
// touches the vault; the caller hands what it reads to keepSecret.
//
// Unlike the Keychain, Credential Manager asks no one before a process of this
// user reads an item. It keeps keys out of files and transcripts; it is no
// wall against a program running as you.

import { MIN_HIDDEN } from './keychain.js'

// What credman.ps1 exits with (keychain.js's NOT_FOUND is 44 too)
export const CRED_NOT_FOUND = 44
export const CRED_OTHER_ACCOUNT = 5
export const CRED_TOO_LARGE = 4

// Windows PowerShell 5.1, which every Windows 10 and 11 has, by its full path:
// a powershell.exe earlier on PATH would be handed the key
export async function powershellPath($) {
  let root = ''
  try {
    root = (await $.env.get('SystemRoot')) || ''
  } catch {}
  return `${(root || 'C:\\Windows').replace(/[\\/]+$/, '')}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`
}

// A path as Git Bash takes it in a command: C:/x/y, since a backslash there is an escape
export const bashPath = (path) => String(path).replace(/\\/g, '/')

export const credmanScript = (root) => `${String(root).replace(/[\\/]+$/, '')}\\bin\\credman.ps1`
// bin/credman, the script for Git Bash, by the path a command names it with
export const credmanCommand = (root) => `${bashPath(String(root).replace(/[\\/]+$/, ''))}/bin/credman`

export async function credmanArgv($, root, command) {
  return [await powershellPath($), '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', credmanScript(root), command, '-Stdin']
}

// Text to the hex credman.ps1 reads, by way of its UTF-8 bytes (the hooks
// have no TextEncoder). A lone surrogate is no text and throws.
export function hexOf(text) {
  const pieces = encodeURIComponent(String(text)).match(/%[0-9A-Fa-f]{2}|[^%]/g) || []
  return pieces.map((c) => (c.length === 3 ? c.slice(1).toLowerCase() : c.charCodeAt(0).toString(16).padStart(2, '0'))).join('')
}

// Bytes to text by way of %XX, since the hooks run with no TextDecoder
export function fromHex(hex) {
  try {
    return decodeURIComponent(String(hex).replace(/../g, '%$&'))
  } catch {
    return undefined
  }
}

// A rejected $.process.run may quote its command, and the stdin may hold the
// key, so the reason is put in words of our own
async function run($, root, command, lines) {
  try {
    return await $.process.run(await credmanArgv($, root, command), { stdin: lines.map(hexOf).join('\n') + '\n' })
  } catch (err) {
    throw new Error(/ENOENT|not found/i.test(String((err && err.message) || err))
      ? 'Windows PowerShell is missing: the Credential Manager backend needs it'
      : 'credman.ps1 did not finish')
  }
}

// credman.ps1's own one-line reason, which never holds a value
const reason = (r) => String(r.stderr || '').replace(/^credman: /, '').split(/\r?\n/)[0].slice(0, 200)

export async function saveToCredman($, root, service, account, value) {
  const r = await run($, root, 'set', [service, account, value])
  if (r.exitCode !== 0) throw new Error(reason(r) || `credman.ps1 exited ${r.exitCode}`)
}

// A read: what use_secret and the Bash pre-load ask credman.ps1 for
export function credRead(service, account) {
  return { kind: 'credman', service, ...(account ? { account } : {}) }
}

// Reads one item: { value, printed, account }, or { exitCode } when there is
// no such item or it could not be read. `printed` is every way a command can
// print it (bin/credman get prints the text as it is, and a command may print
// one line of a value that has several); `value` is undefined when the bytes
// are not text.
export async function readCredman($, root, read) {
  const r = await run($, root, 'read', [read.service, read.account ?? ''])
  if (r.exitCode !== 0) return { exitCode: r.exitCode, why: reason(r) }
  if (r.isStdoutTruncated) throw new Error("credman.ps1's answer was cut off")
  const m = /^ok ((?:[0-9a-f]{2})*) (text|bytes) ((?:[0-9a-f]{2})*)\r?\n?$/.exec(String(r.stdout))
  if (!m) throw new Error('credman.ps1 printed no value line')
  const account = fromHex(m[1]) ?? ''
  if (m[2] === 'bytes') return { value: undefined, printed: [], account }
  const text = fromHex(m[3])
  if (text === undefined) return { value: undefined, printed: [], account }
  const lines = text.includes('\n') ? text.split(/\r?\n/).filter((l) => l.length >= MIN_HIDDEN) : []
  return { value: text, printed: [...new Set([text, ...lines])].filter(Boolean), account }
}

// Whether Credential Manager holds the item a pointer names: true, false, or
// undefined when that can't be told. No value is read out.
export async function credExists($, root, { service, account }) {
  try {
    const r = await run($, root, 'exists', [service, account ?? ''])
    return r.exitCode === 0 ? true : r.exitCode === CRED_NOT_FOUND ? false : undefined
  } catch {
    return undefined
  }
}

// Every generic credential's names (target, user, comment), as list_key_names
// filters them. credman.ps1 never reads a value out for this.
export async function credmanItems($, root) {
  let r
  try {
    r = await $.process.run([await powershellPath($), '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', credmanScript(root), 'list'])
  } catch {
    throw new Error('credman.ps1 did not finish')
  }
  if (r.exitCode !== 0) throw new Error(reason(r) || `credman.ps1 exited ${r.exitCode}`)
  const items = []
  for (const line of String(r.stdout).split(/\r?\n/)) {
    const m = /^((?:[0-9a-f]{2})*) ((?:[0-9a-f]{2})*) ((?:[0-9a-f]{2})*)$/.exec(line)
    if (!m || !m[1]) continue
    items.push({ service: fromHex(m[1]) ?? '', account: fromHex(m[2]) ?? '', label: '', comment: fromHex(m[3]) ?? '' })
  }
  return { items: items.filter((i) => i.service), isCut: Boolean(r.isStdoutTruncated) }
}

// What Claude writes in a Bash command for a value it can't hold as a
// placeholder: the shell reads the item as the command runs, so the value
// never enters the command text
export function credReadCommand(root, service, account) {
  return `"$(${credmanCommand(root)} get -s ${shellWord(service)}${account ? ` -a ${shellWord(account)}` : ''})"`
}

// The command you run in your own terminal to add an item: it prompts for the
// value with the typing hidden, so the key never lands in shell history, and
// tags it for list_key_names
export function credAddHint(root, service, account) {
  return `powershell -NoProfile -ExecutionPolicy Bypass -File "${credmanScript(root)}" add -Service ${psWord(service)}${account ? ` -Account ${psWord(account)}` : ''}`
}

function shellWord(s) {
  return /^[A-Za-z0-9_.,:@%+=\/-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`
}

// One argument as powershell.exe -File passes it on: bare when plain, else in
// double quotes (a name holds no control character; badName sees to it)
function psWord(s) {
  return /^[A-Za-z0-9_.,:@%+=\/\\-]+$/.test(s) ? s : `"${s.replace(/"/g, '\\"')}"`
}
