// secret-box: Claude can use a secret without ever seeing it.
//
// Pattern: guard what you can't undo. A secret in the conversation is in the
// transcript for good, so it must never get there:
//   - In: Claude calls request_secret, you paste the value into a masked box,
//     the mod saves it to the macOS Keychain (or .env) and hands Claude a
//     placeholder. use_secret loads a Keychain item as a placeholder too.
//   - Out: every secret a tool would show Claude (a `cat .env`, an API answer,
//     a key you paste) is swapped for a placeholder like [REDACTED-SECRET-1a2b3c4d].
//   - Use: a placeholder in a tool's input becomes the real value as the tool
//     runs, so `curl -H "Authorization: Bearer [REDACTED-SECRET-...]"` works.
//   - Never: committing .env is refused, since a pushed key can't be taken back.
//
// The redaction is transcript-redactor (./redact.ts, ./detect.ts): its hooks
// do the In, Out and Use. redact.ts adds one thing: a call it filled with real
// values gets its permission check answered on the call as Claude wrote it
// (ownApproval), so the key never reaches the dialog or the auto-mode
// classifier. This file adds the box, use_secret,
// list_key_names and migrate_env_to_keychain, keeps .env pointers readable,
// teaches the vault the values in .env and the Keychain items a command (or
// bin/keychain-env) reads, and guards commits. Nothing is written but Keychain
// items and .env.

import { register as redactor, LIVE_TAG_TOOLS, brand, errorText, tagNames } from './redact.ts'
import { collect, keepSecret, makeConfig, restore, scrubSecrets, walk } from './detect.ts'
import {
  addHint, badName, BOX_COMMENT, boxBackend, defaultAccount, envAssignments, envPointers, envValue, keychainItems, keychainReads,
  itemExists, looksLikeKey, MIN_HIDDEN, NOT_FOUND, parsePointer, platformOf, pointerTo, quoteCloses, readCommand, readKeychain, saveToKeychain,
  serviceRead, SHELL_ACTIVE,
} from './keychain.js'
import { bashPath, credAddHint, credExists, credmanItems, credRead, credReadCommand, readCredman, saveToCredman } from './credman.js'

const TOOL = 'mcp__secret-box__request_secret'
const USE = 'mcp__secret-box__use_secret'
const LIST = 'mcp__secret-box__list_key_names'
const MIGRATE = 'mcp__secret-box__migrate_env_to_keychain'
// list_key_names says this first, word for word, and so do the README and the skill
const NAMES_ONLY = "Returns key names only and never fetches or returns any key's value."
const PANE = 'secret-box'
const DOT = '•'

// The one request being collected right now. The real value lives only here,
// in the mod's memory, until it is saved.
let pending = null // { name, reason, value, answer, isInBand }

// A .env key whose name says it holds a secret
const SECRET_NAME = /KEY|TOKEN|SECRET|PASS|PWD|CREDENTIAL|AUTH|PRIVATE|DSN|SALT|SIGNING|WEBHOOK/i
const ASSIGNMENT = /^(\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*)(.*)$/gm

// A Keychain read in a Bash command whose output the pre-load can't promise to
// hide: it can't be parsed, it names something only the shell knows, the fetch
// failed, the value is too short to hide, or it dumps the keychain. Every such
// case comes here, and `refuse` is the one switch: the refuseUnmaskable
// option, off by default. Off, the command runs and only the detector scans
// what it prints. On, the command is refused.
export function unmaskable(why, refuse) {
  return refuse
    ? { deny: `secret-box: this command reads the Keychain, but ${why}, so what it prints can't be hidden. Use use_secret instead.` }
    : undefined
}

// 'mac', 'windows', 'other' or 'unknown', asked once per load (`memo` is that load's)
function platformIn($, memo) {
  return (memo.platform ??= platformOf($))
}

// The system's vault, by platform: the macOS Keychain, or Windows Credential
// Manager by way of bin/credman.ps1. Both hold items by service and account,
// and the rest of this file reads and writes through these alone. Off both,
// the Keychain's (use_secret and the rest aren't registered there, and on an
// unknown platform a Mac is what they may still find).
function vaultOf($, platform) {
  const root = $.plugin.root
  if (platform === 'windows') {
    return {
      name: 'Windows Credential Manager',
      short: 'Credential Manager',
      the: 'Credential Manager',
      The: 'Credential Manager',
      inBash: ' in the Bash tool (Git Bash)',
      reader: 'credman.ps1',
      serviceRead: credRead,
      read: (read) => readCredman($, root, read),
      save: (service, account, value) => saveToCredman($, root, service, account, value),
      exists: (pointer) => credExists($, root, pointer),
      items: () => credmanItems($, root),
      account: async (options) => String((options && options.keychainAccount) || '').trim() || (await $.env.get('USERNAME')) || '',
      addHint: (service, account) => credAddHint(root, service, account),
      readCommand: (service, account) => credReadCommand(root, service, account),
      tagHint: credAddHint(root, 'SERVICE', 'ACCOUNT'),
      directRead: `${bashPath(root)}/bin/credman get`,
      failed: (got) => `credman.ps1 could not read it (exit ${got.exitCode}${got.why ? `: ${got.why}` : ''})`,
      unreadable: 'Ask the user to check the item in Credential Manager (Control Panel, Credential Manager, Windows Credentials)',
    }
  }
  return {
    name: 'the macOS Keychain',
    short: 'Keychain',
    the: 'the Keychain',
    The: 'The Keychain',
    inBash: '',
    reader: 'security',
    serviceRead,
    read: (read) => readKeychain($, read),
    save: (service, account, value) => saveToKeychain($, service, account, value),
    exists: (pointer) => itemExists($, pointer),
    items: () => keychainItems($),
    account: (options) => defaultAccount($, options),
    addHint,
    readCommand,
    tagHint: 'security add-generic-password -U -s SERVICE -a ACCOUNT -j secret-box -w',
    directRead: '`security find-generic-password`',
    failed: (got) => `security exited ${got.exitCode}`,
    unreadable: 'the keychain may be locked, or access to the item was refused. Ask the user to unlock it (security unlock-keychain) or to allow access when macOS asks',
  }
}

// How Claude is to use a Keychain value it now has a placeholder for, by what
// the value holds, in two parts. `loaded(head)` ends the one line the user
// sees in the tool's row: what to write in a command (the placeholder, or a
// read of the item inside the command), so the model has it even if the
// context is lost. `guide` is the rest, for the model alone (the answer's
// context). The redactor won't put a value with a space, a quote or another
// shell character into a Bash command. So such a value gets no placeholder:
// Claude reads it from the Keychain inside the command, or not at all.
function howToUse(vault, service, account, value, tag) {
  const never = "Never write the value into a file: Claude Code keeps a plain copy of every file it edits under ~/.claude/file-history."
  const short = value.length < MIN_HIDDEN ? ` It is under ${MIN_HIDDEN} characters, so if a command prints it, it can't be hidden: don't print it.` : ''
  if (!SHELL_ACTIVE.test(value)) {
    return {
      loaded: (head) => `${head} as ${tag}.`,
      guide: `You can't see the value. To use it, write ${tag} in a Bash command: it becomes the real value when the command runs and is hidden again in the output.${short} ${never}`,
    }
  }
  if (/^[\x20-\x7e]*$/.test(value)) {
    // Pasted with its own quotes into a string already in double quotes, the
    // quotes would cancel and the shell would split the value into fragments
    const quoted = vault.readCommand(service, account)
    const bare = quoted.slice(1, -1)
    return {
      loaded: (head) => `${head}. Use it in Bash as ${quoted}.`,
      guide: `You can't see the value. It holds a space or a shell character, so it can't go into a command as a placeholder. Instead, have the shell read it from ${vault.name} where the value goes. As a whole argument of its own, write exactly: ${quoted}. Inside a string that is already in double quotes, write it without the outer quotes, so it stays one word inside that string: -H "Authorization: Bearer ${bare}". The value never appears in the command, and anything the command prints of it comes back hidden.${short} ${never}`,
    }
  }
  return {
    loaded: (head) => `${head}, but its value can't go into a Bash command.`,
    guide: `You can't see the value. It holds characters that can't safely go into a Bash command (a newline, say), so it can't be used here. ${never} Ask the user to store it base64-encoded instead, as the secret-box README describes.`,
  }
}

// bin/keychain-env, by the absolute path Claude can run it from (C:/x/y on
// Windows, as Git Bash takes it)
function runnerPath($) {
  return `${bashPath($.plugin.root)}/bin/keychain-env`
}


// Every value this file hands the vault. The vault can't be asked what it
// holds, and values under 8 characters aren't indexed for the scrubber to
// find, so isCleanPointer checks against this set too. `name` says what the
// value is (a Keychain item, a .env variable) in the approval prompt.
const keptValues = new Set()
function keep(value, name) {
  keptValues.add(value)
  const tag = keepSecret(value)
  if (name) tagNames.set(tag, name)
  return tag
}

// How the approval prompt names an item of the vault
function itemName(vault, service, account) {
  return `the ${vault.short} item ${service}${account ? ` (account ${account})` : ''}`
}

// A pointer that is only a pointer: its service and account each pass the
// detector on their own, aren't shaped like a key (hex, a UUID, a long mixed
// token, which the detector leaves alone), and hold no placeholder and no
// value this mod hid. The text a hidden span stands for has any key inside it
// put back, so a real key written after `keychain:` reads back as
// `keychain:<key>`. It stays hidden.
function isCleanPointer(value, cfg) {
  const pointer = parsePointer(value)
  if (!pointer) return false
  return [pointer.service, pointer.account ?? ''].every(
    (s) =>
      !s.includes('[REDACTED-') &&
      !looksLikeKey(s) &&
      ![...keptValues].some((v) => v.length >= 4 && s.includes(v)) &&
      collect(() => scrubSecrets(s, cfg)).tags.size === 0,
  )
}

// The detector takes the value of `OPENAI_API_KEY=keychain:openai` for a
// password and hides it. A pointer only names a Keychain item, so a
// placeholder that stands for a clean one is put back as the pointer text.
const SECRET_TAG = /\[REDACTED-SECRET-[0-9a-f]{8}\]/g
function showPointers(r, cfg) {
  let changed = false
  const show = (text) =>
    typeof text !== 'string' || !text.includes('[REDACTED-SECRET-')
      ? text
      : text.replace(SECRET_TAG, (tag) => {
          const value = restore(tag)
          if (value === tag || !isCleanPointer(value, cfg)) return tag
          changed = true
          return value
        })
  if (r.deny !== undefined) {
    const deny = show(r.deny)
    return changed ? { deny } : r
  }
  const st = { incomplete: false }
  const result = walk(r.result, show, st)
  const text = show(r.text)
  const context = r.context?.map(show)
  if (!changed || st.incomplete) return r
  // An errored answer can't be rewritten in place (see the redactor's
  // tool.call): it goes back as a refusal holding the new text
  if (r.isError) return { deny: errorText(text, result) }
  return { result, ...(context ? { context } : {}) }
}

// A .env file with a key written in it in plaintext
const holdsPlaintext = (text) => envAssignments(text).some(([name, value]) => SECRET_NAME.test(name) && value !== '' && !parsePointer(value))

// The one note per session, at the first sign of keys in play, that tells the
// model secret-box is here and how .env pointers work
async function nudgeText($, vault, platform) {
  let plaintext = []
  try {
    plaintext = (await projectEnvFiles($)).filter((f) => holdsPlaintext(f.text)).map((f) => f.name)
  } catch {}
  return (
    `secret-box is installed: keys live in ${vault.name}, never in a file or the chat. In a .env file, write a pointer ` +
    'instead of a value, NAME=keychain:SERVICE or NAME=keychain:SERVICE?account=ACCOUNT, and run the app with ' +
    `${runnerPath($)} -- COMMAND${platform === 'windows' ? ' in the Bash tool (Git Bash); a placeholder works in Bash, not in PowerShell' : ''}. ` +
    'Load the secret-box:secrets skill before working with any key or .env file.' +
    (plaintext.length ? ` ${plaintext.join(', ')} hold${plaintext.length === 1 ? 's' : ''} plaintext keys: offer to move them with migrate_env_to_keychain.` : '')
  )
}

// The project's .env files (not .env.example and the like) in the shell's
// folder, with their text
async function projectEnvFiles($) {
  const cwd = await $.session.cwd()
  const files = []
  for (const entry of await $.fs.list(cwd)) {
    if (entry.kind !== 'file' || !isEnvFile(entry.name)) continue
    try {
      files.push({ name: entry.name, path: `${cwd}/${entry.name}`, text: await $.fs.read(`${cwd}/${entry.name}`) })
    } catch {}
  }
  return files.sort((a, b) => (a.name < b.name ? -1 : 1))
}

// Why a .env file may not be committed, or '' when it may: it holds pointers,
// each a clean one to an item the Keychain holds, every secret-named value is
// a pointer (or empty), every quote closes on its line, and the detector finds
// no key in the rest. Whether the Keychain holds an item is asked once per
// load (`memo.items` keeps only items found, so one added later is seen); an
// answer that can't be had refuses, since this is a guard.
async function keyIn(vault, text, cfg, memo) {
  let pointers = 0
  const rest = []
  for (const line of String(text).split('\n')) {
    const [assignment] = envAssignments(line)
    if (assignment) {
      const [name, value, raw] = assignment
      // A quoted value that runs on below its line (a PEM key) can't be judged line by line
      if (!quoteCloses(raw)) return `${name} has a quoted value that runs past its line`
      if (isCleanPointer(value, cfg)) {
        const pointer = parsePointer(value)
        const key = JSON.stringify([pointer.service, pointer.account ?? ''])
        if (!memo.items.has(key)) {
          const exists = await vault.exists(pointer)
          if (exists === false) return `${name} points to ${value}, which ${vault.the} doesn't hold`
          if (exists !== true) return `whether ${vault.the} holds ${name}'s item (${value}) could not be checked`
          memo.items.add(key)
        }
        pointers++
        continue
      }
      if (value !== '' && SECRET_NAME.test(name)) return `${name} holds a key`
    }
    rest.push(line)
  }
  if (pointers === 0) return 'it holds no keychain: pointer'
  return collect(() => scrubSecrets(rest.join('\n'), cfg)).tags.size === 0 ? '' : 'it holds a key'
}

// Before bin/keychain-env runs: load every pointer it will resolve, from the
// .env files it will read. '' when all are loaded, else why not.
async function preloadRunner($, vault, envFiles) {
  const cwd = await $.session.cwd()
  for (const file of envFiles) {
    const path = isAbsolute(file) ? file : `${cwd}/${file}`
    // A missing file: the runner resolves nothing from it (and stops if it was named)
    if (!(await $.fs.exists(path))) continue
    let text
    try {
      text = await $.fs.read(path)
    } catch {
      return `keychain-env reads ${file}, which secret-box can't read`
    }
    for (const [, pointer] of envPointers(text)) {
      const got = await vault.read(vault.serviceRead(pointer.service, pointer.account))
      for (const shown of got.printed || []) keep(shown, itemName(vault, pointer.service, pointer.account))
      if (got.exitCode !== undefined && got.exitCode !== NOT_FOUND) return `${vault.reader} could not read ${pointer.service} (exit ${got.exitCode})`
      if ((got.printed || []).some((p) => p.length < MIN_HIDDEN)) return `the value of ${pointer.service} is too short to be hidden`
    }
  }
  return ''
}

// list_key_names: the pointers in the project's .env files, and the Keychain
// items the box tagged or whose service starts with a listPrefixes entry.
// Names only: no value is ever fetched. The names are the answer the user
// sees; how to use them is the model's alone (its context).
async function listKeyNames($, vault, options) {
  const clean = (s) => String(s).replace(/[\x00-\x1f\x7f]/g, '?')
  const pointers = []
  try {
    for (const f of await projectEnvFiles($)) {
      for (const [name, p] of envPointers(f.text)) pointers.push(`  ${name} in ${f.name}: service ${clean(p.service)}${p.account ? `, account ${clean(p.account)}` : ''}`)
    }
  } catch {}
  const prefixes = String((options || {}).listPrefixes || '').split(',').map((p) => p.trim()).filter(Boolean)
  const items = []
  let note = ''
  try {
    const listed = await vault.items()
    for (const i of listed.items) {
      if (i.comment !== BOX_COMMENT && !prefixes.some((p) => i.service.startsWith(p))) continue
      const line = `  service ${clean(i.service)}${i.account ? `, account ${clean(i.account)}` : ''}${i.label && i.label !== i.service ? `, label ${clean(i.label)}` : ''}`
      if (!items.includes(line)) items.push(line)
    }
    if (listed.isCut) note = `The ${vault.short} listing was cut off, so some names may be missing.`
  } catch (err) {
    note = `The ${vault.short} could not be listed (${String((err && err.message) || err).slice(0, 100)}).`
  }
  const result = [
    NAMES_ONLY,
    "Pointers in this project's .env files:",
    ...(pointers.length ? pointers : ['  none']),
    `${vault.short} items secret-box saved, or whose service starts with a listPrefixes entry:`,
    ...(items.length ? items : ['  none']),
    ...(note ? [note] : []),
  ].join('\n')
  const context = [
    `To load a pointer's key, give its variable name to use_secret, or run the app with ${runnerPath($)} -- COMMAND to set every pointer. ` +
      `To load a listed ${vault.short} item, give use_secret its service, and its account when several items share the service. ` +
      `An item shows in this list once it is tagged (${vault.tagHint}) or its service starts with a listPrefixes entry.`,
  ]
  return { result, context }
}

// migrate_env_to_keychain. Per entry: save to the Keychain, read it back and
// compare, and only then rewrite that line as a pointer. The file is written
// with $.fs, not the Write tool, so no copy of the old text lands in
// ~/.claude/file-history, and no backup is made. A tool the mod answers gets
// no approval dialog from Claude Code, so the mod asks the user itself unless
// a permission rule already allows or denies the call.
async function migrateEnv($, vault, e, options) {
  const file = String(e.file || '.env')
  if (!isEnvFile(file)) return `${file} is not a .env file. Nothing was changed.`
  const path = isAbsolute(file) ? file : `${await $.session.cwd()}/${file}`
  let text
  try {
    text = await $.fs.read(path)
  } catch {
    return `${file} could not be read. Nothing was changed.`
  }
  const wanted = Array.isArray(e.names) && e.names.length ? e.names.map(String) : undefined
  const lines = text.split('\n')
  const plan = []
  const leftAsIs = []
  for (const [i, line] of lines.entries()) {
    const eol = line.endsWith('\r') ? '\r' : ''
    const m = /^([ \t\r\v\f]*(?:export[ \t\r\v\f]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t\r\v\f]*=)[ \t\r\v\f]*([^\n]*)$/.exec(eol ? line.slice(0, -1) : line)
    if (!m) continue
    const value = envValue(m[3])
    if (value === '' || parsePointer(value) || !(wanted ? wanted.includes(m[2]) : SECRET_NAME.test(m[2]))) continue
    // A quote that closes below its line (a PEM key) or a backslash escape
    // (`"a\nb"`): this line alone is not the value, so it stays as it is
    if (!quoteCloses(m[3]) || value.includes('\\')) {
      leftAsIs.push(`${m[2]} (its value spans lines or holds backslash escapes: store it base64-encoded, as the secret-box skill's multi-line-values.md describes)`)
      continue
    }
    plan.push({ i, name: m[2], value, head: m[1], eol })
  }
  const missing = (wanted || []).filter((n) => !plan.some((p) => p.name === n) && !leftAsIs.some((k) => k.startsWith(`${n} `)))
  const notFound = missing.length ? ` Not found with a plaintext value: ${missing.join(', ')}.` : ''
  if (plan.length === 0) {
    const why = leftAsIs.length ? `Left as they were: ${leftAsIs.join('; ')}.` : `${file} has no ${wanted ? 'such entries' : 'secret-named entries'} with a plaintext value.`
    return `${why} Nothing was changed.${notFound}`
  }
  const names = plan.map((p) => p.name).join(', ')

  let decision = 'ask'
  try {
    ;({ decision } = await $.tool.check({ tool: MIGRATE, input: { file: e.file, names: e.names } }))
  } catch {}
  if (decision === 'deny') return 'A permission rule denies migrate_env_to_keychain. Nothing was changed.'
  if (decision !== 'allow') {
    const answer = await $.ui.ask(`Move ${names} from ${file} into ${vault.name}? Each line becomes a keychain: pointer once ${vault.the} holds its value.`, ['Move them', 'Cancel']).catch(() => '')
    if (answer !== 'Move them') return `The user did not approve moving ${names}. Nothing was changed.`
  }

  const account = await vault.account(options)
  if (!account || badName('account', account)) return `No ${vault.short} account: set the keychainAccount option. Nothing was changed.`
  // PROJECTDIR/ENV_NAME, the folder that holds the .env file
  const folder = path.split(/[\\/]/).slice(-2, -1)[0] || 'project'
  const moved = []
  for (const p of plan) {
    const service = `${folder}/${p.name}`
    const pointer = pointerTo(service, account)
    if (!pointer) {
      leftAsIs.push(`${p.name} (the folder or account name holds a character a pointer can't carry)`)
      continue
    }
    try {
      const before = await vault.read(vault.serviceRead(service, account))
      if (before.exitCode === undefined && before.value !== p.value) {
        leftAsIs.push(`${p.name} (${vault.the} already holds a different value for ${service})`)
        continue
      }
      if (before.exitCode !== undefined && before.exitCode !== NOT_FOUND) {
        leftAsIs.push(`${p.name} (${vault.failed(before)})`)
        continue
      }
      if (before.exitCode === NOT_FOUND) await vault.save(service, account, p.value)
      const after = await vault.read(vault.serviceRead(service, account))
      if (after.exitCode !== undefined || after.value !== p.value) {
        leftAsIs.push(`${p.name} (${vault.the} did not read back the same value)`)
        continue
      }
      for (const shown of after.printed) keep(shown, itemName(vault, service, account))
      lines[p.i] = `${p.head}${pointer}${p.eol}`
      moved.push(`  ${p.name}=${pointer}`)
    } catch (err) {
      leftAsIs.push(`${p.name} (${String((err && err.message) || err).slice(0, 100)})`)
    }
  }
  if (moved.length) {
    try {
      await $.fs.write(path, lines.join('\n'))
    } catch {
      return `${vault.The} now holds the values of ${moved.length} entries, but ${file} could not be rewritten, so it is unchanged. Nothing else was changed.`
    }
  }
  // The report is the answer the user sees; how to run the app is the model's
  const result = [
    moved.length ? `Moved into ${vault.name} (account ${account}); these lines of ${file} are now pointers:` : `Nothing in ${file} was changed.`,
    ...moved,
    ...(leftAsIs.length ? [`Left as they were: ${leftAsIs.join('; ')}.`] : []),
  ].join('\n') + notFound
  return moved.length ? { result, context: [`Run the app with ${runnerPath($)} -- COMMAND${vault.inBash} so the pointers are set from ${vault.the}.`] } : { result }
}

export function register(on, options) {
  // request_secret and use_secret answer with a live placeholder: keep it live
  LIVE_TAG_TOOLS.add(TOOL)
  LIVE_TAG_TOOLS.add(USE)
  brand.name = 'secret-box'
  // use_secret, list_key_names, migrate_env_to_keychain and the pre-load are on
  // unless this is known not to be a Mac, and the box saves to the Keychain
  // only on one (unless backend says otherwise)
  const memo = { items: new Set() }
  const refuse = [true, 'true'].includes((options || {}).refuseUnmaskable)
  // The detector's settings, for the commit guard's own scan of a .env file
  const cfg = makeConfig(options || {})
  // The nudge is said once per session: at the first prompt when the session
  // starts beside .env files, else at the first tool call that touches one or
  // has a key hidden from its result
  const once = { isNudged: false, isEnvAtStart: false }

  // 0. Outside the redactor, so these see what it made of each call: pointers
  //    it hid are put back, and the nudge rides along when its moment comes.
  //    (A match-all matcher: the redactor holds the bare registration.)
  on('tool.call', { tool: /^/ }, async ($, e, next) => {
    // `keychain:[REDACTED-SECRET-…]` would be restored into the key itself,
    // written where a service name belongs
    if (cfg.restore && cfg.restoreTools.has(e.tool) && /keychain:\[REDACTED-SECRET-[0-9a-f]{8}\]/.test(JSON.stringify(e))) {
      return {
        deny:
          'secret-box: a .env pointer names a Keychain item: after keychain: write its service name (keychain:openai, ' +
          'keychain:myapp/STRIPE_SECRET_KEY), never a placeholder, which would put the key itself in its place.',
      }
    }
    const r = showPointers(await next(e), cfg)
    const platform = await platformIn($, memo)
    if (once.isNudged || r.deny !== undefined || platform === 'other') return r
    const input = JSON.stringify(e)
    const hidKey = !LIVE_TAG_TOOLS.has(e.tool) && (JSON.stringify([r.result, r.text]).match(SECRET_TAG) || []).some((t) => !input.includes(t))
    if (!hidKey && envFiles(e).length === 0) return r
    once.isNudged = true
    // The answer as it came, context added: core's own answer (an errored
    // one too) keeps the handle on its messages, so its result isn't checked
    // against the tool's output shape again
    return { ...r, context: [...(r.context ?? []), await nudgeText($, vaultOf($, platform), platform)] }
  }).catch(($, e, next) => next(e))
  on('prompt.attachment', { type: /^/ }, async ($, e, next) => {
    const r = await next(e)
    if (typeof r.text !== 'string') return r
    const shown = showPointers({ result: r.text }, cfg)
    return shown.result === r.text ? r : { text: shown.result }
  }).catch(($, e, next) => next(e))

  // What the redactor's refusals tell Claude to do: never write a key to a file
  brand.shellHint =
    'If it is a Keychain item, call use_secret and write exactly the form it gives, which reads the key inside the command. ' +
    "Otherwise ask the user to save it with request_secret, then do the same. Don't write it into a file."
  brand.staleHint = 'Call use_secret (or request_secret) for that key again and use the placeholder it gives.'
  redactor(on, options || {})

  // 1. Give Claude the tools, and teach the vault the secrets already in .env
  on('session.start', async ($, e, next) => {
    const platform = await platformIn($, memo)
    const vault = vaultOf($, platform)
    const isKeychain = boxBackend((options || {}).backend, platform) !== 'dotenv'
    // On Windows a placeholder works in the Bash tool (Git Bash) alone
    const inBash = platform === 'windows' ? ' Use the Bash tool (Git Bash) for such a command, not PowerShell: PowerShell gets no real values.' : ''
    if (platform === 'unknown') {
      $.ui.toast("secret-box couldn't tell whether this is a Mac (uname didn't answer). use_secret stays on; the box won't save until the backend option is set to keychain or dotenv.")
    }
    await $.tool.register({
      name: 'request_secret',
      description: isKeychain
        ? 'Ask the user for a secret (API key, token, password) without it ever entering the conversation. ' +
          `The user pastes it into a masked box and the mod saves it to ${vault.name} under that name. ` +
          'You get back a placeholder like [REDACTED-SECRET-1a2b3c4d]. Write that placeholder in a command ' +
          `and it becomes the real value when the tool runs.${inBash} Use this INSTEAD of asking the user to paste a ` +
          `secret into chat. For a secret already in ${vault.the}, use use_secret.`
        : 'Ask the user for a secret (API key, token, password) without it ever entering the conversation. ' +
          'The user pastes it into a masked box and the mod saves it to the project .env. You get back the ' +
          'variable name and a placeholder like [REDACTED-SECRET-1a2b3c4d]. Write that placeholder in a command ' +
          `or file and it becomes the real value when the tool runs.${inBash} Use this INSTEAD of asking the user to ` +
          'paste a secret into chat.',
      inputSchema: {
        type: 'object',
        properties: {
          name: {
            type: 'string',
            description: isKeychain
              ? `The ${vault.short} service to save it under: PROJECTDIR/ENV_NAME for this project's own key (myapp/STRIPE_SECRET_KEY), a short shared name (openai) for a key used across projects`
              : 'Environment variable name, e.g. STRIPE_SECRET_KEY',
          },
          reason: { type: 'string', description: 'One short line telling the user why it is needed' },
        },
        required: ['name', 'reason'],
      },
      isDeferred: false,
    })
    if (platform !== 'other') {
      const runner = runnerPath($)
      await $.tool.register({
        name: 'use_secret',
        description:
          `Load a secret the user keeps in ${vault.name} (a generic ${platform === 'windows' ? 'credential' : 'password'}) without it ever entering the ` +
          'conversation. Give its service name, or the name of a variable whose .env value is a keychain: pointer, ' +
          'and the account when several items share a service. You get back how to use it in a Bash command: usually ' +
          'a placeholder like [REDACTED-SECRET-1a2b3c4d] that becomes the real value when the command runs and is ' +
          `hidden again in the output.${inBash} Use this INSTEAD of running ${vault.directRead} yourself. Never ` +
          `write the value into a file. To run an app with every .env pointer set, use ${runner} -- COMMAND. If the ` +
          'item is missing, you get the command the user can run to add it.',
        inputSchema: {
          type: 'object',
          properties: {
            service: { type: 'string', description: `The ${vault.short} service (openai, myapp/STRIPE_SECRET_KEY), or a .env variable name whose value is a keychain: pointer` },
            account: { type: 'string', description: `The ${vault.short} account, only when several items share the service. Given, \`service\` is always read as a service` },
          },
          required: ['service'],
        },
        isDeferred: false,
      })
      await $.tool.register({
        name: 'list_key_names',
        description:
          `${NAMES_ONLY} Lists the keychain: pointers in this project's .env files, and ${vault.name} items ` +
          'secret-box saved or whose service starts with one of the listPrefixes setting: service, account and label. ' +
          'Call it to find the name to give use_secret.',
        inputSchema: { type: 'object', properties: {} },
        isDeferred: false,
      })
      await $.tool.register({
        name: 'migrate_env_to_keychain',
        description:
          `Move plaintext keys out of one .env file into ${vault.name}, and rewrite each moved line as a ` +
          'keychain: pointer. By default it moves every secret-named entry that holds a plaintext value; give names ' +
          `to choose. Each goes to service PROJECTDIR/NAME, account ${platform === 'windows' ? '%USERNAME%' : '$USER'}, tagged for list_key_names. A value is ` +
          'written, read back and compared before its line changes; any failure leaves that line as it was. The user ' +
          'confirms first. Never returns a value.',
        inputSchema: {
          type: 'object',
          properties: {
            file: { type: 'string', description: 'The .env file, relative to the current folder (default .env)' },
            names: { type: 'array', items: { type: 'string' }, description: 'The variables to move (default: every secret-named one with a plaintext value)' },
          },
        },
      })
    }
    await learnDotenv($, ['.env'])
    // Beside .env files on a Mac, the nudge goes with the first prompt
    try {
      once.isEnvAtStart = platform !== 'other' && (await projectEnvFiles($)).length > 0
    } catch {}
    return next(e)
  })

  // The first prompt of a session that starts beside .env files carries the nudge
  on('prompt.submit', { text: /^/ }, async ($, e, next) => {
    if (once.isNudged || !once.isEnvAtStart || e.command || e.isMeta) return next(e)
    once.isNudged = true
    const platform = await platformIn($, memo)
    return next({ ...e, context: [...(e.context ?? []), await nudgeText($, vaultOf($, platform), platform)] })
  }).catch(($, e, next) => next(e))

  // 2. The guard: .env may be read (its secrets come back hidden), never
  //    committed, from Bash or (on Windows) PowerShell, where git runs the same
  on('tool.call', { tool: /^(Bash|PowerShell)$/ }, async ($, e, next) => {
    const why = await commitBlockReason($, vaultOf($, await platformIn($, memo)), String(e.command || ''), cfg, memo)
    return why ? { deny: `secret-box: ${why} A pushed key can't be taken back.` } : next(e)
  }).catch(() => ({ deny: 'secret-box: the .env guard failed, so this call is blocked to be safe.' }))

  // 2b. PowerShell gets no real values (it isn't in restoreTools, and the
  //     redactor's rules for what may go into a command are Bash's), so a
  //     placeholder there would run as its own text. Refused, with the way
  //     that works: the Bash tool, which on Windows is Git Bash.
  on('tool.call', { tool: 'PowerShell' }, async ($, e, next) => {
    if (!cfg.restore || cfg.restoreTools.has('PowerShell')) return next(e)
    const live = (String(e.command || '').match(SECRET_TAG) || []).filter((t) => restore(t) !== t)
    if (live.length === 0) return next(e)
    // No placeholder in the reason: the redactor would quote it as a literal
    return {
      deny:
        `secret-box: ${live.length === 1 ? 'the placeholder in this command becomes its real value' : 'the placeholders in this command become their real values'} only in the Bash tool (Git Bash), ` +
        'not in PowerShell, so it would run with the placeholder text. Nothing ran. Run the same command with the Bash tool instead.',
    }
  }).catch(($, e, next) => (next.called ? next(e) : { deny: 'secret-box: could not check this PowerShell command for placeholders, so it is blocked to be safe.' }))

  // 3. A call that reads a .env file: learn its secret values before it runs,
  //    so the redactor hides them in the output even when they look weak
  //    (a word password). Reading .env is fine; its secrets come back hidden.
  on('tool.call', { tool: /^(Bash|PowerShell|Read|Grep|Edit|MultiEdit|NotebookEdit)$/ }, async ($, e, next) => {
    const files = envFiles(e)
    if (files.length > 0) await learnDotenv($, files)
    return next(e)
  }).catch(($, e, next) => (next.called ? next(e) : { deny: 'secret-box: could not check this .env file, so the call is blocked to be safe.' }))

  // 3b. A command that reads the Keychain itself (`security find-generic-password
  //     -s NAME -w`): load the item it reads into the vault before it runs, by
  //     the same match options and keychain files, so what it prints (-w on
  //     stdout, -g on stderr, as text or hex) comes back hidden. A read it
  //     can't promise to hide goes to unmaskable(). Every command is read,
  //     not only ones that spell find-*-password: a read can be spelled
  //     around that (find-generic-pass\word, security -i < commands).
  //     A hook nested under the redactor's that throws fails into the
  //     redactor's .catch, which withholds the call, not into its own. So
  //     failures are handled here.
  //     On Windows the read is bin/credman get (or credman.ps1, in Bash or
  //     PowerShell), and the runner the same keychain-env.
  on('tool.call', { tool: /^(Bash|PowerShell)$/ }, async ($, e, next) => {
    // PowerShell takes a backslash as a path's own character, never an escape
    // (its escape is the backtick, which the parser can't follow and so calls
    // unknown): read it as / so C:\x\bin\credman.ps1 is the script it names
    const command = e.tool === 'PowerShell' ? String(e.command || '').replace(/\\/g, '/') : String(e.command || '')
    let reads = []
    let vault
    try {
      const platform = await platformIn($, memo)
      const windows = { windows: platform === 'windows' }
      if (e.tool === 'PowerShell' && !windows.windows) return next(e)
      if (keychainReads(command, {}, windows).length > 0 && platform !== 'other') {
        vault = vaultOf($, platform)
        reads = keychainReads(command, { USER: await $.env.get('USER'), LOGNAME: await $.env.get('LOGNAME'), HOME: await $.env.get('HOME') }, windows)
      }
    } catch {
      reads = [{ unknown: 'secret-box could not read it' }]
    }
    for (const read of reads) {
      let why = read.unknown
      if (!why && read.envFiles) {
        // bin/keychain-env: every pointer in the .env files it will read
        try {
          why = await preloadRunner($, vault, read.envFiles)
        } catch (err) {
          why = String((err && err.message) || err)
        }
      } else if (!why) {
        try {
          const got = await vault.read(read)
          const service = read.kind === 'credman' ? read.service : ((read.criteria || []).find(([flag]) => flag === '-s') || [])[1]
          for (const shown of got.printed || []) keep(shown, service ? itemName(vault, service) : undefined)
          // No such item: the command finds none either. Locked or refused: it might still print it
          if (got.exitCode !== undefined && got.exitCode !== NOT_FOUND) why = `${vault.reader} could not read the item (exit ${got.exitCode})`
          // The vault can't find a form this short where it turns up
          else if ((got.printed || []).some((p) => p.length < MIN_HIDDEN)) why = 'its value is too short to be hidden'
        } catch (err) {
          why = String((err && err.message) || err)
        }
      }
      const refusal = why && unmaskable(why, refuse)
      if (refusal) return refusal
    }
    return next(e)
  }).catch(($, e, next) => next(e))

  // 3c. use_secret: load a Keychain item and answer with a placeholder, or the
  //     way to read it inside a command, never the value. What `security`
  //     prints is never put in the answer. Failures are answered here, for the
  //     same reason as above.
  on('tool.call', { tool: USE }, async ($, e, next) => {
    const platform = await platformIn($, memo)
    if (platform === 'other') return { result: 'use_secret needs macOS or Windows. Nothing was loaded.' }
    const vault = vaultOf($, platform)
    let service = String(e.service ?? '')
    let account = String(e.account ?? '')
    const why = (service ? badName('service', service) : `Give the ${vault.short} service name.`) || badName('account', account)
    if (why) return { result: `${why} Nothing was loaded.` }

    try {
      // Which item: with no account, a variable in the project's .env files
      // whose value is a pointer names it; otherwise `service` is the service
      let via = ''
      let runner = ''
      if (!account) {
        const name = service
        let defs = []
        try {
          defs = (await projectEnvFiles($)).flatMap((f) => envPointers(f.text).filter(([n]) => n === name).map(([, p]) => ({ file: f.name, ...p })))
        } catch {}
        const items = [...new Set(defs.map((d) => pointerTo(d.service, d.account)))]
        const files = [...new Set(defs.map((d) => d.file))].join(', ')
        if (items.length > 1) return { result: `${name} points to different ${vault.short} items in ${files}: ${items.join(' and ')}. Call use_secret with the service and account you mean. Nothing was loaded.` }
        if (defs.length) {
          service = defs[0].service
          account = defs[0].account ?? ''
          via = ` through the ${name} pointer in ${files}`
          runner = ` To run an app with every .env pointer set, use ${runnerPath($)} -- COMMAND.`
        }
      }
      const got = await vault.read(vault.serviceRead(service, account))
      const { value, printed, exitCode } = got
      const item = `The ${vault.short} item ${service}${account ? ` (account ${account})` : ''}`
      if (exitCode === undefined) {
        // Every form the vault's reader prints it in is hidden, should a command print the item itself
        for (const shown of printed) keep(shown, itemName(vault, service, account))
        if (value) {
          const tag = keep(value, itemName(vault, service, account))
          // The ONLY things Claude learns: the service, and how to use the
          // value without seeing it. The user's row gets the one line.
          const use = howToUse(vault, service, account, value, tag)
          const inBash = platform === 'windows' ? ' Use the Bash tool (Git Bash) for that command: PowerShell gets no real values.' : ''
          return { result: use.loaded(`Loaded ${service}${account ? ` (account ${account})` : ''} from ${vault.the}${via}`), context: [use.guide + inBash + runner] }
        }
        if (value === undefined) return { result: `${item} holds bytes that are not text, so it can't be used in a command. Nothing was loaded.` }
      }
      const hint = vault.addHint(service, account || (await vault.account(options)))
      const where = platform === 'windows' ? 'in their own terminal window (not through Claude, and not with !)' : 'in a terminal'
      if (exitCode === NOT_FOUND) {
        return { result: `No ${vault.short} item has the service ${service}${account ? ` and account ${account}` : ''}. Ask the user to add it ${where} with this command, which prompts for the value so the key never lands in shell history:\n${hint}\nThen call use_secret again.` }
      }
      if (exitCode === undefined) {
        return { result: `${item} holds no value. Ask the user to set one ${where} with this command, which prompts for it:\n${hint}\nThen call use_secret again.` }
      }
      return { result: `${item} could not be read (${vault.failed(got)}): ${vault.unreadable}, then call use_secret again.` }
    } catch (err) {
      return { result: `secret-box could not read ${vault.the}: ${String((err && err.message) || err).slice(0, 200)}. Nothing was loaded.` }
    }
  }).catch(() => ({ result: 'secret-box could not read the vault. Nothing was loaded.' }))

  // 3d. list_key_names: names only. The pointers in the project's .env files,
  //     and the Keychain items the box saved (tagged) or whose service starts
  //     with a listPrefixes entry. The dump it reads holds every item's names,
  //     so it is filtered here and never handed on whole.
  on('tool.call', { tool: LIST }, async ($, e, next) => {
    const platform = await platformIn($, memo)
    if (platform === 'other') return { result: 'list_key_names needs macOS or Windows.' }
    try {
      return await listKeyNames($, vaultOf($, platform), options)
    } catch {
      return { result: `${NAMES_ONLY}\nsecret-box could not list them.` }
    }
  }).catch(() => ({ result: 'secret-box could not list key names.' }))

  // 3e. migrate_env_to_keychain: move plaintext keys from one .env file into
  //     the Keychain, each line becoming a pointer only once the Keychain reads
  //     its value back
  on('tool.call', { tool: MIGRATE }, async ($, e, next) => {
    const platform = await platformIn($, memo)
    if (platform === 'other') return { result: 'migrate_env_to_keychain needs macOS or Windows. Nothing was changed.' }
    try {
      const answer = await migrateEnv($, vaultOf($, platform), e, options)
      return typeof answer === 'string' ? { result: answer } : answer
    } catch (err) {
      return { result: `migrate_env_to_keychain stopped before rewriting the file (${String((err && err.message) || err).slice(0, 100)}). The file is unchanged.` }
    }
  }).catch(() => ({ result: 'migrate_env_to_keychain failed. The file is unchanged.' }))

  // @.env would attach the raw file to your prompt
  on('prompt.mention', { path: /(^|[\\/])\.env(\.[\w.-]+)?$/ }, async ($, e, next) =>
    isEnvFile(e.path) ? { deny: 'secret-box: ask Claude to read .env instead; its secrets come back hidden' } : next(e))
    .catch(() => ({ deny: 'secret-box: the .env guard failed' }))

  // 4. The box. Claude calls the tool: open it, wait for you, save, answer.
  on('tool.call', { tool: TOOL }, async ($, e, next) => {
    const name = String(e.name || '').trim()
    // Refuse before anyone types, rather than fall back to a plaintext .env, when
    // backend keychain was set off macOS, or auto can't tell what this is
    const platform = await platformIn($, memo)
    const backend = boxBackend((options || {}).backend, platform)
    const isKeychain = backend === 'keychain'
    const vault = vaultOf($, platform)
    // .env needs a variable name; the Keychain takes a service (myapp/STRIPE_SECRET_KEY)
    if (!isKeychain && !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
      return { result: `"${name}" is not a valid variable name. Use letters, digits and underscores.` }
    }
    if (isKeychain && (!name || badName('name', name))) return { result: `"${name}" can't be a ${vault.short} service name. ${badName('name', name) || 'Give one.'}` }
    if (isKeychain && platform === 'other') return { result: `secret-box's Keychain backend needs macOS or Windows, so ${name} was not asked for. Set the backend option to auto or dotenv.` }
    if (backend === 'unknown') return { result: `secret-box couldn't tell whether this is a Mac (uname didn't answer), so ${name} was not asked for and nothing was written. Ask the user to set the backend option to keychain or dotenv.` }
    // A plain -p run has no one to type into the box
    if ((await $.session.surfaces()).length === 0) {
      return { result: `secret-box needs an interactive session to collect ${name}. Ask the user to run Claude Code interactively.` }
    }
    if (pending) return { result: `secret-box is already waiting for ${pending.name}. Ask for one secret at a time.` }

    // `answer` stays undefined until Enter (the value) or Escape (empty)
    pending = { name, reason: String(e.reason || ''), value: '', answer: undefined, isInBand: false }
    const opened = await $.ui.open({ id: PANE, title: 'secret-box', focus: true, closeOnEscape: true, holdToasts: true, rows: 7 })
    // A narrow terminal (under 144 columns) keeps the pane undrawn: use the band above the prompt instead
    if (!opened.isPlaced) {
      pending.isInBand = true
      await $.ui.close({ id: PANE })
      $.ui.invalidate('ui.render')
      $.ui.toast(`Claude wants ${name}: press ctrl+x then tab to type it in the box above the prompt`, { timeoutMs: 10000 })
    }

    // A hook's own run time is capped at 10 s, but time inside a mods API call
    // is not counted, so wait for the person in short `sleep` processes.
    const deadline = (await $.clock.now()) + 10 * 60_000
    while (pending.answer === undefined && !next.signal.aborted && (await $.clock.now()) < deadline) {
      await pause($)
    }
    const value = pending.answer
    pending = null
    await $.ui.close({ id: PANE })
    $.ui.invalidate('ui.render')
    if (!value) return { result: `The user cancelled. ${name} was not saved.` }

    try {
      if (isKeychain) {
        const account = await vault.account(options)
        const why = account ? badName('keychainAccount', account) : `No ${vault.short} account: set the keychainAccount option.`
        if (why) return { result: `Saving ${name} failed: ${why}` }
        await vault.save(name, account, value)
        const tag = keep(value, itemName(vault, name, account))
        const pointer = pointerTo(name, account)
        $.ui.toast(`${name} saved to ${vault.short}`)
        // The ONLY things Claude learns: the name, the place, and a
        // placeholder. The user's row gets the one line.
        const use = howToUse(vault, name, account, value, tag)
        const inBash = platform === 'windows' ? ' Use the Bash tool (Git Bash) for that command: PowerShell gets no real values.' : ''
        return {
          result: use.loaded(`The user entered ${name}, saved to ${vault.name} (account ${account})`),
          context: [
            `${name} is saved as service ${name}, account ${account}; .env was not touched. ${use.guide}${inBash} In a later session, call use_secret with service ${name} and account ${account}.` +
              (pointer ? ` For an app that reads .env, write the line ENV_NAME=${pointer} there, never the value, and run the app with ${runnerPath($)} -- COMMAND.` : ''),
          ],
        }
      }
      const where = await saveToDotenv($, await $.session.cwd(), name, value)
      const tag = keep(value, `${name} in .env`)
      $.ui.toast(`${name} saved to ${where}`)
      // The ONLY things Claude learns: the name, the place, and a placeholder
      return { result: `The user entered ${name}. It was saved to ${where}. You can't see the value. To use it in a command or a file, write ${tag}: it becomes the real value when the tool runs and is hidden again in the output. Code should read it from the environment.` }
    } catch (err) {
      return { result: `Saving ${name} failed: ${String(err && err.message || err).slice(0, 300)}` }
    }
  }).catch(async ($, e, next) => {
    // If the hook itself fails (or times out), drop the request, close the box and tell Claude plainly
    pending = null
    try { await $.ui.close({ id: PANE }) } catch {}
    $.ui.invalidate('ui.render')
    $.ui.log('request_secret failed: ' + JSON.stringify(next.error).slice(0, 500))
    return { result: 'secret-box failed before anything was saved. Nothing was written.' }
  })

  // Draw the box, in our pane or (narrow terminal) in the band above the prompt
  on('ui.render', { component: 'Pane' }, async ($, e, next) => {
    if (e.requestId !== PANE || !pending) return next(e)
    return drawBox($, e, pending)
  })
  on('ui.render', { component: 'AbovePrompt' }, async ($, e, next) => {
    if (!pending || !pending.isInBand) return next(e)
    return drawBox($, e, pending)
  })

  // A refusal of secret-box's own, drawn in the user's view as one calm line.
  // The model still reads the whole text: a refusal can't carry context, so
  // only its row changes. An errored row draws the error text whatever its
  // output, so this draws a tree of its own rather than rewrite the output.
  on('ui.render', { component: 'ToolResult', props: { isErrored: true } }, async ($, e, next) => {
    const line = calmLine(e.props.output)
    if (!line) return next(e)
    const { Text } = $.ui.resolve(e)
    return <Text dimColor>{line}</Text>
  })

  // Escape (or any close) on the pane before Enter means cancel
  on('ui.close', async ($, e, next) => {
    if (e.id === PANE && pending && !pending.isInBand) pending.answer = ''
    return next(e)
  }).catch(($, e, next) => next(e))
}

// One short wait, in a process, so it is not the hook's own time. Mac and
// Linux have `sleep`. A native Windows terminal does not, so there node waits
// where it is installed, else ping, which every Windows has (about 1 s).
export const WAITS = {
  unix: [['sleep', '0.3']],
  windows: [['node', '-e', 'setTimeout(() => {}, 300)'], ['ping', '-n', '2', '127.0.0.1']],
}
let waits = null
async function pause($) {
  waits ||= [...((await $.env.get('OS')) === 'Windows_NT' ? WAITS.windows : WAITS.unix)]
  for (;;) {
    try {
      return await $.process.run(waits[0])
    } catch (err) {
      // Only a command that is not there moves on to the next one
      if (waits.length > 1 && isNotFound(err)) waits.shift()
      else throw err
    }
  }
}
export function isNotFound(err) {
  return /ENOENT|not found/i.test(String((err && err.message) || err))
}

// What the user sees of a refusal secret-box made, by what it was about, or
// undefined for any other error (a command's own failure is drawn as it is).
// The model reads the refusal whole; these say only what happened.
const CALM = [
  [/the user did not allow this call/, 'secret-box: not run, as you chose.'],
  [/waits until plan mode ends/, 'secret-box: held until plan mode ends. Claude was asked to put this step in the plan.'],
  [/no longer holds/, 'secret-box: that was an old placeholder, from before secret-box reloaded. Claude was asked to load the key again.'],
  [/character the shell reads/, 'secret-box: this key needs another form in a command. Claude was told which.'],
  [/A pushed key can't be taken back/, 'secret-box: kept a .env file with keys out of git. Claude was told why.'],
  [/write its service name/, 'secret-box: a .env pointer takes a service name, not a placeholder. Claude was told how to write it.'],
  [/reads the Keychain, but/, 'secret-box: Claude was asked to load this key with use_secret instead.'],
  [/only in the Bash tool/, 'secret-box: a key works in Bash, not PowerShell. Claude was asked to run it in Bash.'],
]
export function calmLine(output) {
  if (typeof output !== 'string') return undefined
  const text = errorText(output.replace(/^Error: /, ''), undefined)
  if (!text.startsWith('secret-box: ')) return undefined
  return (CALM.find(([pattern]) => pattern.test(text)) || [, 'secret-box held this call back to keep a key out of view. Claude was told why.'])[1]
}

// .env, .env.local, .env.production ... but not .env.example and friends
export function isEnvFile(path) {
  const base = String(path || '').split(/[\\/]/).pop()
  return /^\.env(\.[\w.-]+)?$/.test(base) && !/\.(example|sample|template|dist)$/.test(base)
}

// The .env files a tool call reads or names, as written in the call
function envFiles(e) {
  const direct = [e.file_path, e.notebook_path, e.path].filter(isEnvFile)
  const named = String(e.command || '').match(/(?:^|[^\w.\/-])((?:[\w.\/-]*\/)?\.env(?:\.[\w.-]+)?)(?![\w.-])/g) || []
  return [...direct, ...named.map(m => m.replace(/^[^\w.\/-]/, '')).filter(isEnvFile)]
}

// Read .env files and hand every secret-named value to the vault, so it is
// hidden wherever it turns up. Never throws: a file it can't read teaches it
// nothing, and the redactor still scans the output.
async function learnDotenv($, files) {
  let cwd = ''
  try { cwd = await $.session.cwd() } catch {}
  for (const f of files) {
    try {
      const path = isAbsolute(f) ? f : f.startsWith('~/') ? f : cwd + '/' + f
      if (path.startsWith('~/') || !(await $.fs.exists(path))) continue
      for (const m of (await $.fs.read(path)).matchAll(ASSIGNMENT)) {
        const value = m[3].trim().replace(/^["']|["']$/g, '')
        // A pointer only names a Keychain item: it stays readable
        if (value.length >= 6 && SECRET_NAME.test(m[2]) && !parsePointer(envValue(m[3]))) keep(value, `${m[2]} in ${f}`)
      }
    } catch {}
  }
}

// /x on Mac and Linux; C:\x, C:/x or \\server\share on Windows
export function isAbsolute(path) {
  return path.startsWith('/') || /^[A-Za-z]:[\\/]/.test(path) || path.startsWith('\\\\')
}

// The repositories a command's git calls run in: each `git -C <dir>`, and the
// session's own repository for a plain `git`
function gitDirs(cmd) {
  const dirs = new Set()
  for (const m of cmd.matchAll(/\bgit((?:[ \t]+-c[ \t]+\S+|[ \t]+-C[ \t]+(?:"[^"]*"|'[^']*'|\S+))*)/g)) {
    const c = m[1].match(/-C[ \t]+("[^"]*"|'[^']*'|\S+)/g)
    if (!c) dirs.add('')
    else dirs.add(c.at(-1).replace(/^-C[ \t]+/, '').replace(/^["']|["']$/g, ''))
  }
  return [...dirs]
}

// Why a Bash command must be blocked: it stages or commits a .env file. A
// .env file of pointers may go in (holdsNoKey): it names Keychain items and
// holds no key. Any file that can't be read and checked is blocked as before.
async function commitBlockReason($, vault, cmd, cfg, memo) {
  // Why a .env file can't go in, or '' when it can; one that can't be read can't
  const keyOf = async (read) => {
    let text
    try {
      text = await read()
    } catch {
      return 'it could not be read'
    }
    return keyIn(vault, text, cfg, memo)
  }
  if (/\bgit\b[^;&|]*\badd\b/.test(cmd) && /\.env\b(?!\.(example|sample|template|dist))/.test(cmd)) {
    // Only .env files named plainly, in the current folder's repository, can be checked
    const named = envFiles({ command: cmd })
    if (/\s-C[\s=]/.test(cmd) || named.length === 0) return 'staging a .env file is blocked.'
    const cwd = await $.session.cwd()
    for (const f of named) {
      const why = await keyOf(() => $.fs.read(isAbsolute(f) ? f : `${cwd}/${f}`))
      if (why) return `staging a .env file is blocked: ${why}. A .env file can be committed once every key in it is a keychain: pointer to an item ${vault.the} holds.`
    }
  }
  if (!/\bgit\b[^;&|]*\bcommit\b/.test(cmd)) return ''
  // The index is read before the command runs. If the same command stages
  // (git add ... && git commit, or commit -a), count what it could stage too:
  // every changed or untracked file git does not ignore.
  const stages = /\bgit\b[^;&|]*\b(add|stage)\b/.test(cmd) || /\bcommit\b[^;&|]*\s(-a|--all|-\w*a\w*)\b/.test(cmd)
  for (const dir of gitDirs(cmd)) {
    const git = (...args) => $.process.run(['git', ...(dir ? ['-C', dir] : []), ...args])
    const checks = [git('diff', '--cached', '--name-only')]
    if (stages) checks.push(git('ls-files', '--modified', '--others', '--exclude-standard'))
    const [index, tree] = await Promise.all(checks)
    for (const r of [index, tree].filter(Boolean)) {
      if (r.exitCode !== 0) return `could not check what this commit includes${dir ? ' in ' + dir : ''}, so it is blocked.`
    }
    // Staged: what the index holds. Paths are from the repository's top.
    for (const env of index.stdout.split('\n').filter(isEnvFile)) {
      const staged = async () => {
        const r = await git('show', `:${env}`)
        if (r.exitCode !== 0) throw new Error('unreadable')
        return r.stdout
      }
      const why = await keyOf(staged)
      if (why) return `this commit would include ${env}: ${why}. Unstage it with git rm --cached, or make every key in it a keychain: pointer to an item ${vault.the} holds.`
    }
    // Stageable: the working file. Paths are from the folder git ran in.
    const base = !dir ? await $.session.cwd() : isAbsolute(dir) ? dir : `${await $.session.cwd()}/${dir}`
    for (const env of (tree ? tree.stdout.split('\n') : []).filter(isEnvFile)) {
      const why = await keyOf(() => $.fs.read(`${base}/${env}`))
      if (why) {
        return `this command could stage and commit ${env}: ${why}. Add it to .gitignore, or stage named files in a separate step.`
      }
    }
  }
  return ''
}

// The field shows dots; the real text is kept in `p.value`, never drawn.
function drawBox($, e, p) {
  const { Box, Text, Input } = $.ui.resolve(e)
  return (
    <Box flexDirection="column" paddingX={1}>
      <Text bold>Claude is asking for <Text color="yellow">{p.name}</Text></Text>
      {p.reason ? <Text dimColor>{p.reason}</Text> : null}
      <Input
        key="secret"
        label="value "
        placeholder="paste it here, it stays masked"
        value={DOT.repeat(p.value.length)}
        submitLabel="save"
        autoFocus
        onInput={text => {
          // Everything up to the first non-dot is the part we already hold;
          // the rest is what was just typed or pasted. Backspace shortens the dots.
          let kept = 0
          while (kept < text.length && text[kept] === DOT) kept++
          p.value = p.value.slice(0, Math.min(kept, p.value.length)) + text.slice(kept)
          $.ui.invalidate('ui.render')
        }}
        onSubmit={() => { p.answer = p.value }}
      />
      <Text dimColor>{p.value.length ? `${p.value.length} characters · ` : ''}Enter saves · {p.isInBand ? 'ctrl+x tab to focus, Enter on empty cancels' : 'Esc cancels'} · Claude never sees the value</Text>
    </Box>
  )
}

async function saveToDotenv($, cwd, name, value) {
  const path = cwd + '/.env'
  const old = (await $.fs.exists(path)) ? await $.fs.read(path) : ''
  const line = `${name}=${quote(value)}`
  const lines = old.split('\n').filter((l, i, all) => !(i === all.length - 1 && l === ''))
  const at = lines.findIndex(l => l.startsWith(name + '='))
  if (at >= 0) lines[at] = line
  else lines.push(line)
  await $.fs.write(path, lines.join('\n') + '\n')

  const gi = cwd + '/.gitignore'
  const ignore = (await $.fs.exists(gi)) ? await $.fs.read(gi) : ''
  const isIgnored = ignore.split('\n').some(l => ['.env', '.env*', '*.env', '/.env'].includes(l.trim()))
  if (!isIgnored) await $.fs.write(gi, ignore + (ignore && !ignore.endsWith('\n') ? '\n' : '') + '.env\n')
  return '.env' + (isIgnored ? '' : ' (and added .env to .gitignore)')
}

// Plain values stay bare; anything with spaces, quotes or # gets double quotes.
function quote(v) {
  return /^[A-Za-z0-9_\-.\/:+=@]*$/.test(v) ? v : '"' + v.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n') + '"'
}
