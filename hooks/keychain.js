// The macOS Keychain backend: secrets live in the Keychain as generic
// passwords, not in a plaintext .env, and Claude only ever holds placeholders.
//
// Every call runs /usr/bin/security by argv through $.process.run, never a
// shell, so a service name can't run as code. The full path, not `security`:
// a `security` earlier on PATH would be handed the key. Nothing here touches
// the vault; the caller hands what it reads to keepSecret, as the box does.

export const SECURITY = '/usr/bin/security'

// What `security find-*-password` exits with when no item matches
export const NOT_FOUND = 44

// The vault can only find a value again where it turns up when it is at least
// this long (detect.ts indexes values by their first 8 characters)
export const MIN_HIDDEN = 8

// The redactor's rule (redact.ts SHELL_ACTIVE) for a value it won't put into
// a Bash command, since it could run there as code. A test pins the two together.
export const SHELL_ACTIVE = /[\s$`"'\\;&|<>()*?[\]{}#~]|[\x00-\x1f\x7f]/

// Which vault this machine has: 'mac' (the Keychain), 'windows' (Credential
// Manager), 'other', or 'unknown' when it can't be told. The mods API has no
// platform call: Windows says so in OS; anything else answers uname, run by
// its full path so nothing on PATH stands in for it. Where neither uname is
// there (NixOS, Termux), every Mac has macOS's version file; only if that
// can't be checked either is the platform unknown.
export const MACOS_VERSION_FILE = '/System/Library/CoreServices/SystemVersion.plist'
export async function platformOf($) {
  try {
    if ((await $.env.get('OS')) === 'Windows_NT') return 'windows'
  } catch {}
  for (const uname of ['/usr/bin/uname', '/bin/uname']) {
    try {
      const r = await $.process.run([uname, '-s'])
      const name = r.exitCode === 0 ? r.stdout.trim() : ''
      if (name) return name === 'Darwin' ? 'mac' : 'other'
    } catch {}
  }
  try {
    return (await $.fs.exists(MACOS_VERSION_FILE)) ? 'mac' : 'other'
  } catch {
    return 'unknown'
  }
}

// Where the box saves: keychain, dotenv, or unknown when `auto` (and any value
// that is neither) meets a platform that can't be told. The box saves nowhere then.
// `keychain` is the system's vault: the Keychain on macOS, Credential Manager
// on Windows.
export function boxBackend(choice, platform) {
  if (choice === 'keychain' || choice === 'dotenv') return choice
  return platform === 'mac' || platform === 'windows' ? 'keychain' : platform === 'other' ? 'dotenv' : 'unknown'
}

// A service or account goes into argv and into a command you paste into a
// shell: one line of printable text, and not huge.
const MAX_NAME = 256
export function badName(label, value) {
  if (/[\x00-\x1f\x7f-\x9f]/.test(value)) return `The ${label} holds a control character.`
  if (value.length > MAX_NAME) return `The ${label} is longer than ${MAX_NAME} characters.`
  return ''
}

// The comment on every item the mod saves, so list_key_names can find them
export const BOX_COMMENT = 'secret-box'

// -U updates the item when it is already there; -j tags it as the mod's. The
// value sits in argv while the command runs, where `ps` and any mod hooked on
// process.run can see it.
export function addArgv(service, account, value) {
  return [SECURITY, 'add-generic-password', '-U', '-s', service, '-a', account, '-j', BOX_COMMENT, '-w', value]
}

// The command you run to add an item by hand. With -w last, `security`
// prompts for the value, so the key never lands in your shell history; -U
// replaces an item that is already there.
export function addHint(service, account) {
  return `security add-generic-password -U -s ${shellWord(service)} -a ${account ? shellWord(account) : '"$USER"'} -w`
}

// What Claude writes in a Bash command for a value it can't hold as a
// placeholder: the shell reads the item as the command runs, so the value
// never enters the command text. -w prints a printable value as it is.
export function readCommand(service, account) {
  return `"$(${SECURITY} find-generic-password -s ${shellWord(service)}${account ? ` -a ${shellWord(account)}` : ''} -w)"`
}

function shellWord(s) {
  return /^[A-Za-z0-9_.,:@%+=\/-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`
}

// The account the box saves under: the keychainAccount setting, else your
// macOS user name, as `security add-generic-password -a "$USER"` would.
export async function defaultAccount($, options) {
  return String((options && options.keychainAccount) || '').trim() || (await $.env.get('USER')) || ''
}

export async function saveToKeychain($, service, account, value) {
  const r = await run($, addArgv(service, account, value))
  if (r.exitCode !== 0) throw new Error(`security exited ${r.exitCode}`)
}

// A rejected $.process.run may quote its command, and the command may hold
// the key, so the reason is put in words of our own.
async function run($, argv) {
  try {
    return await $.process.run(argv)
  } catch (err) {
    throw new Error(/ENOENT|not found/i.test(String((err && err.message) || err))
      ? `${SECURITY} is missing: the Keychain backend needs macOS`
      : 'security did not finish')
  }
}

// ------------------------------------------------------------- reading an item

// A read is the subcommand's kind, its match options in the order given, as
// [flag, value] pairs, and the keychain files it searches. use_secret reads by
// service, and by account when one is given: without -a an item matches by its
// service alone, the way the items you already have were saved.
export function serviceRead(service, account) {
  return { kind: 'generic', criteria: [['-s', service], ...(account ? [['-a', account]] : [])], keychains: [] }
}

// Always -g, whatever a command used: it says plainly how the password is
// written, where -w prints plain text and hex alike.
export function findArgv(read) {
  return [SECURITY, `find-${read.kind}-password`, ...read.criteria.flat(), '-g', ...read.keychains]
}

// `security -g` prints the password on stderr in one of three shapes:
//   password: "text"                       every byte printable, no " or \
//   password: 0x6C696E65310A  "line1\012"   anything else: hex, then an escaped copy
//   password:                              an empty password
// `-w` prints the text and a newline, or, when any byte is not printable
// ASCII, the bytes as lowercase hex and a newline.
const PASSWORD = /^password: (?:"(.*)"|0x((?:[0-9A-F]{2})*) {2}".*"|)$/m

// Reads one item: { value, printed }, or { exitCode } when security found no
// item or could not read it. `printed` is every way security can print the
// password, so each can be hidden; `value` is its text, undefined when the
// bytes are not UTF-8. Nothing security prints goes anywhere else.
export async function readKeychain($, read) {
  const r = await run($, findArgv(read))
  if (r.exitCode !== 0) return { exitCode: r.exitCode }
  // A cut-off answer could hold half a password
  if (r.isStdoutTruncated || r.isStderrTruncated) throw new Error("security's answer was cut off")
  const m = String(r.stderr).match(PASSWORD)
  if (!m) throw new Error('security printed no password line')
  if (m[2] === undefined) return { value: m[1] ?? '', printed: m[1] ? [m[1]] : [] }
  return { value: utf8(m[2]), printed: printedForms(m[2]) }
}

// The ways a password security shows as hex can turn up: the text, each of its
// lines long enough to hide (a command may print one line of a PEM), -w's
// lowercase hex, -g's uppercase hex, and -g's escaped copy, where \ and every
// byte that is not printable ASCII is written \ooo in octal.
function printedForms(hex) {
  const bytes = (hex.match(/../g) || []).map((b) => parseInt(b, 16))
  const escaped = bytes.map((n) => (n >= 0x20 && n < 0x7f && n !== 0x5c ? String.fromCharCode(n) : '\\' + n.toString(8).padStart(3, '0'))).join('')
  const text = utf8(hex)
  const lines = text && text.includes('\n') ? text.split(/\r?\n/).filter((l) => l.length >= MIN_HIDDEN) : []
  return [...new Set([text, ...lines, hex.toLowerCase(), hex, escaped])].filter(Boolean)
}

// Bytes to text by way of %XX, since the hooks run with no TextDecoder
function utf8(hex) {
  try {
    return decodeURIComponent(hex.replace(/../g, '%$&'))
  } catch {
    return undefined
  }
}

// ---------------------------------------------------------------- .env pointers

// A pointer stands in a .env file where a key's value would, and names the
// Keychain item that holds it: keychain:SERVICE or keychain:SERVICE?account=ACCOUNT.
// Printable ASCII only; anything outside the plain set is percent-encoded
// (%20 for a space). bin/keychain-env reads pointers by the same rule.
const SEG = '(?:[A-Za-z0-9._~:@/+,;=!*-]|%(?:2[0-9A-Fa-f]|[3-6][0-9A-Fa-f]|7[0-9A-Ea-e]))+'
const POINTER = new RegExp(`^keychain:(${SEG})(?:\\?account=(${SEG}))?$`)
const unescapePointer = (s) => s.replace(/%([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
const escapePointer = (s) => s.replace(/[^A-Za-z0-9._~:@/+,;=!*-]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0'))

// { service, account? } for a pointer, undefined for anything else
export function parsePointer(value) {
  const m = POINTER.exec(String(value))
  return m ? { service: unescapePointer(m[1]), ...(m[2] ? { account: unescapePointer(m[2]) } : {}) } : undefined
}

// A service or account shaped like a key, which the detector leaves alone on
// purpose (it could be a hash or an id): 16+ hex digits, a UUID, or 20+
// letters and digits mixed with no / . - _ or space between them. Datadog,
// Algolia and Twilio keys and UUID API keys look like this; names made the
// usual way (myapp/STRIPE_SECRET_KEY, openai, acme.prod/DB_PASSWORD, a login
// name) don't.
export function looksLikeKey(name) {
  const s = String(name)
  if (/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/.test(s)) return true
  return s.split(/[/._\- ]+/).some((run) => /^[0-9a-fA-F]{16,}$/.test(run) || (run.length >= 20 && /[A-Za-z]/.test(run) && /[0-9]/.test(run)))
}

// Whether the Keychain holds the item a pointer names: true, false (security
// exits 44), or undefined when that can't be told. Attributes only, no -g or
// -w, so no password is read and nothing prompts; what it prints stays here.
export async function itemExists($, { service, account }) {
  try {
    const r = await $.process.run([SECURITY, 'find-generic-password', '-s', service, ...(account ? ['-a', account] : [])])
    return r.exitCode === 0 ? true : r.exitCode === NOT_FOUND ? false : undefined
  } catch {
    return undefined
  }
}

// The pointer to an item, or undefined when a name holds a character a
// pointer can't carry (anything but printable ASCII)
export function pointerTo(service, account) {
  if (!/^[\x20-\x7e]+$/.test(service) || (account && !/^[\x20-\x7e]+$/.test(account))) return undefined
  return `keychain:${escapePointer(service)}${account ? `?account=${escapePointer(account)}` : ''}`
}

// bin/keychain-env reads .env files in the C locale, where a blank is one of
// space, tab, CR, VT and FF and every other character (U+2028, U+00A0) is
// text. These follow it exactly, so the mod loads every pointer the runner
// will resolve; tests/env-cases.ts pins the two together.
const trimBlanks = (s) => s.replace(/^[ \t\r\v\f]+|[ \t\r\v\f]+$/g, '')
const DQ = /^"([^"]*)"(?:[ \t\r\v\f]+#[^\n]*)?$/
const SQ = /^'([^']*)'(?:[ \t\r\v\f]+#[^\n]*)?$/

// A .env value as dotenv libraries read it: in quotes, the text inside them;
// bare, the text before a ` #` comment
export function envValue(raw) {
  const v = trimBlanks(String(raw))
  const q = DQ.exec(v) || SQ.exec(v)
  return q ? q[1] : trimBlanks(v.replace(/[ \t\r\v\f]+#[^\n]*$/, ''))
}

// False for a value whose opening quote doesn't close on its line: a
// multi-line value (a PEM key) whose rest sits on the lines below
export function quoteCloses(raw) {
  const v = trimBlanks(String(raw))
  return !/^["']/.test(v) || DQ.test(v) || SQ.test(v)
}

// Each NAME=value line of a .env file, as [name, value, raw value]
export function envAssignments(text) {
  const out = []
  for (const line of String(text).split('\n')) {
    const m = /^[ \t\r\v\f]*(?:export[ \t\r\v\f]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t\r\v\f]*=[ \t\r\v\f]*([^\n]*)$/.exec(line)
    if (m) out.push([m[1], envValue(m[2]), m[2]])
  }
  return out
}

// The pointers in a .env file, as [name, { service, account? }]
export function envPointers(text) {
  return envAssignments(text).flatMap(([name, value]) => {
    const pointer = parsePointer(value)
    return pointer ? [[name, pointer]] : []
  })
}

// --------------------------------------------------------------- listing names

// The generic passwords in `security dump-keychain` output. Without -d it
// prints attributes only, never a password. Each item gives its service,
// account, label and comment. An attribute is "text", or 0xHEX and an escaped
// copy when it holds a byte that isn't printable, or <NULL>.
export function dumpedItems(text) {
  const items = []
  let item
  for (const line of String(text).split('\n')) {
    if (line.startsWith('keychain: ')) items.push((item = {}))
    else if (item && line.startsWith('class: ')) item.class = attribute(line.slice('class: '.length))
    else if (item) {
      // `    "acct"<blob>="..."`, and the label as `    0x00000007 <blob>="..."`
      const m = /^\s+(?:"(\w{4})"|0x(00000007) )<\w+>=(.*)$/.exec(line)
      // 0x00000007 is the label (the item's name in Keychain Access)
      if (m) item[m[1] || 'labl'] = attribute(m[3])
    }
  }
  return items
    .filter((i) => i.class === 'genp' && i.svce)
    .map((i) => ({ service: i.svce, account: i.acct ?? '', label: i.labl ?? '', comment: i.icmt ?? '' }))
}

function attribute(raw) {
  const q = /^"(.*)"$/.exec(raw)
  if (q) return q[1]
  const h = /^0x((?:[0-9A-Fa-f]{2})*)(?: {2}".*")?$/.exec(raw)
  return h ? utf8(h[1]) : undefined
}

// The generic passwords in the keychain search list, names only: the dump is
// read here and never handed on
export async function keychainItems($) {
  const r = await run($, [SECURITY, 'dump-keychain'])
  if (r.exitCode !== 0) throw new Error(`security exited ${r.exitCode}`)
  return { items: dumpedItems(r.stdout), isCut: Boolean(r.isStdoutTruncated) }
}

// ---------------------------------------------- Keychain reads in a Bash command

// The variables a read may name that the hook can know. $.env only reads
// names spelled in the source, so these are the ones it fetches.
export const READ_ENV = ['USER', 'LOGNAME', 'HOME']

// The match options of each subcommand: the flags that take a value. -g and -w
// take none; any other flag (-h) is one we don't follow.
const MATCH = { generic: 'acCDGjls', internet: 'acCdDjlpPrst' }
const READS = ['find-generic-password', 'find-internet-password']
const MENTION = /find-(?:generic|internet)-password|dump-keychain|keychain-env/g
// On Windows, bin/credman (Git Bash) and bin/credman.ps1 are what read an item
const CREDMAN_MENTION = /credman|keychain-env/gi
const isCredman = (w) => typeof w === 'string' && /(?:^|[\\/])credman(?:\.ps1)?$/i.test(w)
const unknown = (why) => ({ unknown: why })
const unknowable = unknown('a word in it is only known when it runs')

// The runner, by name or by any path to it (C:\x\keychain-env too)
const RUNNER = 'keychain-env'
const isRunner = (w) => typeof w === 'string' && (w === RUNNER || w.endsWith('/' + RUNNER) || w.endsWith('\\' + RUNNER))
// Commands that run the command they are given, so a runner after one is run
const WRAPPERS = ['sudo', 'env', 'exec', 'command', 'nohup', 'nice', 'xargs', 'bash', 'sh', 'zsh']

// A keyword that starts a command inside if, for or while is not the command
const command = (words) => {
  let k = 0
  while (['do', 'then', 'else', 'elif', '!', 'time'].includes(words[k])) k++
  return words.slice(k)
}

// The Keychain reads a Bash command makes, each a read for readKeychain, a
// runner's { envFiles } (the .env files bin/keychain-env will resolve), or
// { unknown: why } where we can't know exactly which item it reads or what it
// prints: a word only the shell can know ($VAR, a glob, $(...)), a prefix
// (sudo, env, VAR=x) that could change whose Keychain it reads, a relative
// keychain file, `security -i` or `dump-keychain`, a runner whose .env can't
// be known, or a read that isn't a command of its own (inside quotes for
// `sh -c`). `env` holds READ_ENV's values. With `windows`, the reads are
// bin/credman's (credRead's { kind: 'credman', service, account }), and a
// `security` command is nothing: Windows has none.
export function keychainReads(cmd, env = {}, { windows = false } = {}) {
  const text = String(cmd || '')
  const ctx = { text, env, commands: [], comments: [] }
  lex(text, 0, '', ctx)
  const reads = new Map()
  const add = (read) => reads.set(JSON.stringify(read), read)
  const readsOf = windows ? credmanReadOf : readOf
  const mention = windows ? CREDMAN_MENTION : MENTION
  const isMention = windows ? (w) => isCredman(w) || isRunner(w) : (w) => READS.includes(w) || w === 'dump-keychain' || isRunner(w)
  let seen = 0
  for (const words of ctx.commands) {
    seen += words.filter(isMention).length
    for (const read of commandReads(words, readsOf)) add(read)
  }
  // A mention outside a comment that isn't a word of its own: inside quotes, or glued to others
  let code = ''
  let from = 0
  for (const [start, end] of ctx.comments) {
    code += text.slice(from, start)
    from = end
  }
  code += text.slice(from)
  if ((code.match(mention) || []).length > seen) add(unknown('part of it could not be parsed'))
  // The runner reads ./.env from the shell's folder: a cd before it moves that
  if (ctx.commands.some((w) => ['cd', 'pushd', 'popd'].includes(command(w)[0]))) {
    for (const [key, read] of reads) {
      if (read.envFiles) {
        reads.delete(key)
        add(unknown('it changes folder, so which .env keychain-env reads is unknown'))
      }
    }
  }
  return [...reads.values()]
}

// What one simple command reads: the runner's .env files and the command it
// runs, or the command's own read
function commandReads(all, readsOf) {
  const words = command(all)
  if (isRunner(words[0])) return runnerReads(words.slice(1), readsOf)
  if (words.slice(1).some(isRunner) && (words[0] === null || WRAPPERS.includes(String(words[0]).split(/[\\/]/).pop().replace(/\.exe$/i, '')))) {
    return [unknown('something runs keychain-env in a way secret-box can\'t follow')]
  }
  const read = readsOf(words)
  return read ? [read] : []
}

// keychain-env [--env-file PATH]... -- COMMAND: the .env files it resolves
// (./.env when none is named), then whatever COMMAND reads in turn. Anything
// else is what the runner itself refuses.
function runnerReads(args, readsOf) {
  const envFiles = []
  for (let k = 0; k < args.length; k++) {
    const a = args[k]
    if (a === null) return [unknowable]
    if (a === '--') return [{ envFiles: envFiles.length ? envFiles : ['.env'] }, ...commandReads(args.slice(k + 1), readsOf)]
    if (a === '--env-file' && typeof args[k + 1] === 'string') envFiles.push(args[++k])
    else if (a.startsWith('--env-file=')) envFiles.push(a.slice('--env-file='.length))
    else return [a === '--env-file' ? unknowable : unknown(`keychain-env is given ${a}`)]
  }
  return [unknown('keychain-env is run without --')]
}

// What one simple command reads from the Keychain: nothing (undefined), a
// read, or { unknown }. A read is `security [-lqv] [-p prompt]
// find-*-password [options] [keychain...]`, its options read as getopt does:
// bundled (`-wa NAME`), attached (`-sNAME`), and ended by the first word that
// is not one, which starts the keychain files.
function readOf(words) {
  const at = words.findIndex((w) => READS.includes(w) || w === 'dump-keychain')
  const runsSecurity = typeof words[0] === 'string' && /(?:^|\/)security$/.test(words[0])
  if (at < 0 && !runsSecurity) return undefined
  if (words[0] !== 'security' && words[0] !== SECURITY) {
    // sudo security, env security, $SEC find-...: security run in a way we can't
    // follow. `grep find-generic-password` only names the subcommand.
    const before = words.slice(0, Math.max(at, 1))
    return before.some((w) => w === null || /(?:^|\/)security$/.test(w)) ? unknown('something other than security runs it') : undefined
  }
  let k = 1
  for (; k < words.length; k++) {
    if (words[k] === '-p') k++
    else if (/^-[hilqv]+$/.test(words[k] ?? '')) {
      if (words[k].includes('i')) return unknown('it runs security interactively')
    } else break
  }
  // No command: security reads its commands from its input
  if (k >= words.length) return unknown('it runs security without a command')
  if (words[k] === null) return unknowable
  if (k !== at) return undefined // another command (add-generic-password ...)
  if (words[at] === 'dump-keychain') return unknown('it dumps the keychain')
  const kind = words[at].slice('find-'.length, -'-password'.length)
  const args = words.slice(at + 1)
  const criteria = []
  for (k = 0; k < args.length; k++) {
    const a = args[k]
    if (a === null) return unknowable
    if (a === '--') {
      k++
      break
    }
    if (a[0] !== '-' || a === '-') break
    for (let p = 1; p < a.length; p++) {
      if (a[p] === 'g' || a[p] === 'w') continue
      if (!MATCH[kind].includes(a[p])) return unknown(`it uses -${a[p]}`)
      const value = p + 1 < a.length ? a.slice(p + 1) : args[++k]
      if (value === undefined) return unknown(`its -${a[p]} has no value`)
      if (value === null) return unknowable
      criteria.push([`-${a[p]}`, value])
      break
    }
  }
  const keychains = args.slice(k)
  if (keychains.includes(null)) return unknowable
  // A relative path is found from the shell's folder, which the hook can't see
  if (keychains.some((f) => !f.startsWith('/'))) return unknown('it names a keychain file by a relative path')
  return { kind, criteria, keychains }
}

// What one simple command reads from Windows Credential Manager: nothing
// (undefined), a read, or { unknown }. A read is bin/credman, or credman.ps1
// run by Windows PowerShell, with `get` and its -s/-Service and -a/-Account
// (PowerShell takes any prefix of a parameter's name, and -Name:value). `read`
// takes its names on stdin, which can't be known. The other commands print
// names at most.
const POWERSHELL = /^(?:.*[\\/])?(?:powershell|pwsh)(?:\.exe)?$/i
function credmanReadOf(words) {
  const at = words.findIndex(isCredman)
  if (at < 0) return undefined
  const before = words.slice(0, at)
  if (before.includes(null)) return unknown('something other than credman runs it')
  // `cat bin/credman`, `grep credman`: the script is only named
  if (before.length && !POWERSHELL.test(before[0])) return undefined
  const sub = words[at + 1]
  if (sub === null) return unknowable
  if (typeof sub !== 'string') return undefined
  if (/^read$/i.test(sub)) return unknown('it reads which item from its input')
  if (!/^get$/i.test(sub)) return undefined
  let service
  let account
  const args = words.slice(at + 2)
  for (let k = 0; k < args.length; k++) {
    const a = args[k]
    if (a === null) return unknowable
    const m = /^-([A-Za-z]+)(?::(.*))?$/.exec(a)
    if (!m) return unknown(`credman is given ${a}`)
    const flag = m[1].toLowerCase()
    const isService = flag === 's' || 'service'.startsWith(flag)
    const isAccount = flag === 'a' || 'account'.startsWith(flag)
    if (!isService && !isAccount) return unknown(`it uses -${m[1]}`)
    const value = m[2] !== undefined ? m[2] : args[++k]
    if (value === undefined) return unknown(`its -${m[1]} has no value`)
    if (value === null) return unknowable
    if (isService) service = value
    else account = value
  }
  if (!service) return undefined
  return { kind: 'credman', service, ...(account ? { account } : {}) }
}

// Splits a command into the words of each simple command, the way zsh and
// bash hand them over, as far as we can know them: a word is its text, or
// null where the shell turns it into something we don't hold. The commands
// inside $( ) and backticks are read as commands too. Returns where it stopped.
function lex(s, i, stop, ctx) {
  let words = []
  let word // undefined: none started; null: one we can't know
  let drop = false // the next word is a redirection's target, not an argument
  const put = (piece) => { word = word === null || piece === null ? null : (word ?? '') + piece }
  const endWord = () => {
    if (word === undefined) return
    if (drop) drop = false
    else words.push(word)
    word = undefined
  }
  const endCommand = () => {
    endWord()
    if (words.length) ctx.commands.push(words)
    words = []
    drop = false
  }
  while (i < s.length) {
    const c = s[i]
    if (c === stop) {
      endCommand()
      return i + 1
    }
    if (c === '\\') {
      // A line continuation joins two lines; any other escaped character is itself
      if (s[i + 1] !== '\n') put(s[i + 1] ?? '')
      i += 2
    } else if (c === ' ' || c === '\t') {
      endWord()
      i++
    } else if (c === '#' && word === undefined) {
      const start = i
      while (i < s.length && s[i] !== '\n') i++
      ctx.comments.push([start, i])
    } else if (c === '<' || c === '>' || (c === '&' && s[i + 1] === '>')) {
      // A redirection (2>/dev/null, &>log, 2>&1): its fd and its target aren't arguments
      if (typeof word === 'string' && /^\d+$/.test(word)) word = undefined
      endWord()
      drop = true
      i++
      while (i < s.length && '<>&|-'.includes(s[i])) i++
    } else if (';&|\n()'.includes(c)) {
      endCommand()
      i++
    } else if (c === "'") {
      const end = s.indexOf("'", i + 1)
      put(end < 0 ? null : s.slice(i + 1, end))
      i = end < 0 ? s.length : end + 1
    } else if (c === '"') {
      i = quoted(s, i + 1, ctx, put)
    } else if (c === '$' || c === '`') {
      i = expand(s, i, ctx, put, false)
    } else if (c === '~' && word === undefined) {
      // ~ and ~/x are the home folder, unless the command changes HOME; ~name is someone else's
      const tilde = /^~[\w.+-]*/.exec(s.slice(i))[0]
      put(tilde === '~' && !isSet('HOME', ctx.text) ? (ctx.env.HOME ?? null) : null)
      i += tilde.length
    } else if ('*?[]{}'.includes(c) || (c === '=' && word === undefined)) {
      // Globs, braces and zsh's =cmd become text we can't know
      put(null)
      i++
    } else {
      put(c)
      i++
    }
  }
  endCommand()
  return i
}

// The inside of "...": $ and backticks expand, a backslash escapes only
// $ ` " \ and a newline. An unterminated quote can't be known.
function quoted(s, i, ctx, put) {
  let piece = ''
  const add = (p) => { piece = piece === null || p === null ? null : piece + p }
  while (i < s.length && s[i] !== '"') {
    if (s[i] === '\\' && '$`"\\\n'.includes(s[i + 1] ?? 'x')) {
      if (s[i + 1] !== '\n') add(s[i + 1])
      i += 2
    } else if (s[i] === '$' || s[i] === '`') {
      i = expand(s, i, ctx, add, true)
    } else {
      add(s[i])
      i++
    }
  }
  put(i < s.length ? piece : null)
  return i + 1
}

// Whether the command could change a variable: its name as a word of its own
// anywhere (`USER=x`, `for USER in`, `read USER`, `unset USER`), not as $NAME
// or ${NAME}. A name that only appears in some other sense makes it unknown too.
function isSet(name, text) {
  return new RegExp(`(?<![\\w$]|\\$\\{)${name}(?!\\w)`).test(text)
}

// $NAME, ${NAME}, $( ) and backticks. Only READ_ENV's names are known, and
// only while the command can't change them. The command inside $( ) or
// backticks is read too; what it prints can't be known.
function expand(s, i, ctx, put, isQuoted) {
  if (s[i] === '`') {
    put(null)
    return lex(s, i + 1, '`', ctx)
  }
  const next = s[i + 1]
  if (next === '(') {
    put(null)
    return lex(s, i + 2, ')', ctx)
  }
  if (next === "'") {
    // $'...' turns escapes into bytes
    put(null)
    const end = s.indexOf("'", i + 2)
    return end < 0 ? s.length : end + 1
  }
  if (next === '"') {
    // $"..." is translated text
    put(null)
    return quoted(s, i + 2, ctx, () => {})
  }
  const m = /^\$(?:\{(\w+)\}|([A-Za-z_]\w*))/.exec(s.slice(i, i + 130))
  if (m) {
    const name = m[1] || m[2]
    const end = i + m[0].length
    // zsh changes an unbraced $USER:u (modifiers) and $USER[1] (subscripts)
    const isChanged = m[2] !== undefined && (s[end] === '[' || (s[end] === ':' && /[A-Za-z]/.test(s[end + 1] ?? '')))
    let value = READ_ENV.includes(name) && !isChanged && !isSet(name, ctx.text) ? ctx.env[name] : undefined
    // Unquoted, bash splits a value on IFS and globs it, and zsh does neither
    if (value !== undefined && !isQuoted && (/[\s*?[\]]/.test(value) || /IFS/.test(ctx.text))) value = undefined
    put(value ?? null)
    return end
  }
  if (next === '{') {
    put(null)
    const end = s.indexOf('}', i)
    return end < 0 ? s.length : end + 1
  }
  if (/[\w?$!#*@-]/.test(next ?? '')) {
    put(null)
    return i + 2
  }
  // A $ before a space, a quote or the end is itself
  put('$')
  return i + 1
}
