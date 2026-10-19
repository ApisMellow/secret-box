import type { Register, PromptContextBlock } from 'claude-code'
import {
  makeConfig,
  scrubSecrets,
  scrubPii,
  restore,
  mint,
  walk,
  collect,
  escapeLiteralTags,
  type WalkState,
} from './detect.ts'

// transcript-redactor: keeps secrets (and, if asked, email addresses) out of
// the session transcript. Everything that decides what a secret is lives in
// ./detect.ts; this file only wires it to the events where text enters the
// conversation, and to the tools where a placeholder must become real again.
//
// Every hook fails closed. A hook that throws or runs past its budget is
// skipped by the engine, and for a redactor that would mean the raw text goes
// through. So each one has a `.catch` that withholds instead.

// The scan is linear, but a string past this size could still run past the
// hook's 10 s budget. It is withheld rather than passed on unscanned.
const SCAN_CAP = 16_000_000

const WITHHELD =
  'transcript-redactor could not scan this result in time, so it was withheld. Narrow the output (head, grep, offset) and retry.'
const BLOCK_WITHHELD = '[transcript-redactor withheld this text: the scan failed]'

// Tools whose answer carries live placeholders, so they are not turned into
// quoted (LITERAL) ones: the subagent tools, whose answer holds placeholders
// the subagent used. A mod built on this one can add its own tool here.
export const LIVE_TAG_TOOLS = new Set(['Agent', 'Task'])

// The name on the toast and the tool row, and what two refusals tell the
// model to do instead. A mod built on this one sets its own.
export const brand = {
  name: 'transcript-redactor',
  // A value holding shell characters can't go into a command as itself
  shellHint: 'Write it to a file with the Write tool and have the command read that file instead.',
  // A placeholder the vault no longer holds stands for nothing
  staleHint: 'Read the value again where it came from to get a fresh placeholder.',
}

// What a placeholder stands for, by name (a Keychain item, a .env variable),
// where a mod built on this one knows it. The approval prompt lists these.
export const tagNames = new Map<string, string>()

// The labels of the approval prompt (tool.check, below)
const ALLOW = 'Allow'
const DENY = 'Deny'

// Permission modes in which a call Claude Code would ask about must not run on
// this file's word. dontAsk refuses what no rule allows, with no dialog, so
// core's own verdict stands. Plan mode (nothing runs yet) is refused outright
// (tool.check, below): its ask would open Claude Code's dialog, real values in it.
const HOLD_MODES = new Set(['dontAsk'])
// The modes in which, ownPrompt off, such a call is allowed. A mode not seen
// yet, or one not named here, gets the prompt instead.
const ALLOW_MODES = new Set(['default', 'acceptEdits', 'auto', 'bypassPermissions'])

const SECRET_TAGS = /\[REDACTED-SECRET-[0-9a-f]{8}\]/g

// The words of an errored call's answer, as the model read them, without the
// wrapper a refusal is given again
export function errorText(text: unknown, result: unknown): string {
  const s = typeof text === 'string' ? text : typeof result === 'string' ? result.replace(/^Error: /, '') : 'The call failed.'
  const m = /^<tool_use_error>([\s\S]*)<\/tool_use_error>$/.exec(s)
  return m ? m[1]! : s
}

// The placeholders in a call's input that restore() can't resolve: minted
// before this mod last loaded (the vault lives in memory only), or never
// minted at all. Left in, one reaches the tool as its own text. One that
// already sits in the file the call edits is that file's text (a placeholder
// printed into it once), so it can still be edited away.
async function staleTags(e: Record<string, unknown>, read: (path: string) => Promise<unknown>): Promise<string[]> {
  const found = new Set<string>()
  const look = (s: string): string => {
    for (const t of s.match(SECRET_TAGS) ?? []) if (restore(t) === t) found.add(t)
    return s
  }
  // A command's description is never run
  walk(e.tool === 'Bash' ? { command: e.command } : argsOf(e), look)
  const path = e.file_path ?? e.notebook_path
  if (found.size > 0 && e.tool !== 'Bash' && typeof path === 'string') {
    let text = ''
    try {
      const got = await read(path)
      if (typeof got === 'string') text = got
    } catch {}
    for (const t of [...found]) if (text.includes(t)) found.delete(t)
  }
  return [...found]
}

// A tool call's own arguments: what the permission check reads (`{ command }`
// for Bash), without the call's envelope
function argsOf(e: Record<string, unknown>): Record<string, unknown> {
  const { tool: _tool, tool_use_id: _id, agentId: _agent, requestMeta: _meta, consent: _consent, ...args } = e
  return args
}

const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

// Attachments that carry text from outside the engine's own prose: a file,
// a diff of a file, a queued prompt. These get the full scrub, emails too.
const OUTSIDE_TEXT = new Set(['file', 'edited_text_file', 'queued_command'])

type Budget = { budget: { remainingMs: number } }

// Throws before a scan that cannot finish: the `.catch` then withholds.
function guard(text: string, next: Budget): void {
  if (text.length > SCAN_CAP) throw new Error('transcript-redactor: text too large to scan')
  const needMs = 300 + text.length / 4000
  if (next.budget.remainingMs < needMs) throw new Error('transcript-redactor: out of time')
}

// A Bash command that writes text into git history or posts it to GitHub.
// Its placeholders stay placeholders: a commit message or an issue body that
// quotes one must not carry the real key off the machine. The whole command
// is left as written, so a step that needs the key goes in its own call.
const PUBLISHES =
  /\bgit\b(?:[ \t]+-[cC][ \t]+\S+|[ \t]+--?[\w-]+(?:=\S+)?)*[ \t]+(?:commit|tag|notes|send-email)\b|\bgh[ \t]+(?:issue|pr|release|gist|discussion|api|repo[ \t]+(?:create|edit))\b/

// A restored value goes into Bash as shell source. One holding any of these
// (quotes, $, backticks, separators, globs) could run as code there, so it is
// never put into a command. Most keys are letters, digits and -_.+/=:
const SHELL_ACTIVE = /[\s$`"'\\;&|<>()*?[\]{}#~]|[\x00-\x1f\x7f]/

// @-mentioned files the engine attaches as media or a page reference, never
// as text. When one is too large for $.fs.read it holds no text to check.
const MEDIA_FILE = /\.(?:png|jpe?g|gif|webp|bmp|tiff?|heic|pdf)$/i

function looksBinary(text: string): boolean {
  const head = text.slice(0, 8192)
  return head.includes('\u0000') || (head.match(/�/g)?.length ?? 0) > 8
}

export const register: Register = (on, options) => {
  const cfg = makeConfig(options as Record<string, unknown>)

  const scrub = (text: string): string => {
    let out = text
    if (cfg.secrets) out = scrubSecrets(out, cfg)
    if (cfg.pii) out = scrubPii(out, cfg)
    return out
  }
  const secretsOnly = (text: string): string => (cfg.secrets ? scrubSecrets(text, cfg) : text)
  // An `allowUrlHosts` entry that is not a host name is said once, not dropped silently.
  let warnedHosts = cfg.allowUrlRejected.length === 0

  // Counts the values hidden, not the placeholders that stand for quoted text.
  const countHidden = (tags: Set<string>): number => [...tags].filter((t) => !t.startsWith('[REDACTED-LITERAL-')).length

  // ownApproval (on unless set off): the permission check of a call this file
  // filled with real values is answered on the call as Claude wrote it, so the
  // real values never reach the approval dialog or the auto-mode classifier.
  const ownApproval = ![false, 'false'].includes((options as Record<string, unknown>).ownApproval as never)
  // ownPrompt (off unless set on): such a call that the user's rules don't
  // decide gets this file's own Allow/Deny prompt. Off, it is allowed.
  const ownPrompt = [true, 'true'].includes((options as Record<string, unknown>).ownPrompt as never)
  // The calls running now with real values put in, by tool_use_id: the call
  // as Claude wrote it (placeholders and all) and the placeholders put back.
  const filled = new Map<string, { input: Record<string, unknown>; tags: string[] }>()

  // 1. What the user types. A pasted key never reaches the model as itself,
  //    and neither does the context a hook above attached to the prompt.
  on('prompt.submit', async ($, e, next) => {
    const { value, tags } = collect(() => {
      guard(e.text, next)
      return { text: scrub(e.text), context: e.context?.map((c) => (guard(c, next), scrub(c))) }
    })
    const n = countHidden(tags)
    if (!warnedHosts) {
      warnedHosts = true
      $.ui.toast(`${brand.name}: allowUrlHosts ignored ${cfg.allowUrlRejected.join(', ')} (not a host name)`)
    }
    if (n > 0 && cfg.notify) $.ui.toast(`${brand.name}: hid ${n} value(s) from the prompt`)
    if (tags.size === 0) return next(e)
    return next({ ...e, text: value.text, ...(value.context ? { context: value.context } : {}) })
  }).catch(($, e, next) => (next.called ? next(e) : { drop: 'transcript-redactor failed to scan this prompt, so it was not sent.' }))

  // 2. Every tool call. On the way in, a placeholder becomes its real value,
  //    but only for a tool that runs on this machine. On the way out, the
  //    result, the text the model reads and any attached context are scanned.
  on('tool.call', async ($, e, next) => {
    const command = (e as { command?: unknown }).command
    const publishes = e.tool === 'Bash' && typeof command === 'string' && PUBLISHES.test(command)
    const isLocal = cfg.restore && cfg.restoreTools.has(e.tool) && !publishes
    // A placeholder the vault no longer holds would run as its own text, with
    // no error: the call is refused before anything runs
    const stale = isLocal ? await staleTags(e as Record<string, unknown>, (path) => $.fs.read(path)) : []
    if (stale.length > 0) {
      const one = stale.length === 1
      return {
        deny:
          `${brand.name}: ${stale.join(', ')} ${one ? 'is a placeholder' : 'are placeholders'} ${brand.name} no longer holds: ` +
          `${one ? 'it is' : 'they are'} from before ${brand.name} last reloaded, so the call would have used the placeholder text itself. ` +
          `Nothing ran. ${brand.staleHint}`,
      }
    }
    // The real values this call was handed. Whatever the tool prints of them
    // comes back hidden, even bare and short, where no detector would fire.
    const handed = new Set<string>()
    // The placeholders put back, for the permission check (tool.check, below)
    const used = new Set<string>()
    const restoreTracked = (s: string): string =>
      restore(s) === s
        ? s
        : s.replace(/\[REDACTED-SECRET-[0-9a-f]{8}\]/g, (t) => {
            const v = restore(t)
            if (v !== t) {
              handed.add(v)
              used.add(t)
            }
            return v
          })
    const rehideHanded = (text: string): string => {
      let out = text
      for (const v of [...handed].sort((a, b) => b.length - a.length)) if (v.length >= 4 && out.includes(v)) out = out.split(v).join(mint('SECRET', v))
      return out
    }
    const input = isLocal ? (walk({ ...e }, restoreTracked) as typeof e) : e
    if (e.tool === 'Bash' && [...handed].some((v) => SHELL_ACTIVE.test(v))) {
      return {
        deny: `${brand.name}: a key in this command holds a space, a quote or another character the shell reads, so it was not put into the command, where the shell would change it. Nothing ran. ${brand.shellHint}`,
      }
    }
    // The permission check runs inside next(): it is told of this call until
    // the call ends or is refused
    const id = e.tool_use_id
    const isFilled = ownApproval && used.size > 0 && typeof id === 'string'
    if (isFilled) filled.set(id, { input: argsOf(e), tags: [...used] })
    let r: Awaited<ReturnType<typeof next>>
    try {
      r = await next(input)
    } finally {
      if (isFilled) filled.delete(id)
    }
    if (r.deny !== undefined) {
      // A refusal from beneath may quote the input it refused, real values
      // and all, and the model reads it as the tool's answer.
      const d = collect(() => (guard(r.deny, next), rehideHanded(scrub(escapeLiteralTags(r.deny)))))
      return d.tags.size === 0 ? r : { deny: d.value }
    }

    const escape = !LIVE_TAG_TOOLS.has(e.tool)
    const st: WalkState = { incomplete: false }
    // The result and the text often hold the same string: scan it once.
    const memo = new Map<string, string>()
    const clean = (s: string): string => {
      const done = memo.get(s)
      if (done !== undefined) return done
      guard(s, next)
      const out = rehideHanded(scrub(escape ? escapeLiteralTags(s) : s))
      memo.set(s, out)
      return out
    }
    const { value, tags } = collect(() => ({
      result: walk(r.result, clean, st),
      text: r.text === undefined ? undefined : clean(r.text),
      context: r.context?.map(clean),
    }))
    if (tags.size === 0) return r
    // Something was hidden, and part of the result could not be rewritten:
    // that part may hold the same secret, so the whole result is withheld.
    if (st.incomplete) return { deny: 'transcript-redactor: a secret sits in a part of this result it cannot rewrite (too deep, or not plain data). Narrow the call and retry.' }

    const n = countHidden(tags)
    if (cfg.notify && n > 0) $.ui.notice(e.tool_use_id, `${brand.name}: hid ${n} value(s)`)
    // An errored call can be answered only as core answered it or as a
    // refusal: any other answer is checked against the tool's output shape,
    // which an error's text never fits ("expected object, received string"),
    // and that check's failure replaces the answer. So a rewritten error goes
    // back as a refusal holding it. (A refusal carries no context; core gives
    // an errored call none.)
    if (r.isError) return { deny: errorText(value.text, value.result) }
    const context = value.context ? { context: value.context } : {}
    return { result: value.result, ...context } as typeof r
  }).catch(() =>
    // Nothing ran yet: the call is refused. The tool answered: its answer is
    // withheld (an errored one can only be withheld this way, as above).
    ({ deny: WITHHELD }),
  )

  // 2b. The permission check of a call that tool.call above filled with real
  //     values. Claude Code checks the call as it will run, real values and
  //     all, so its dialog would show them and the auto-mode classifier would
  //     read them. Only for such a call (a query, with no tool_use_id, passes):
  //       1. Core's verdict first. Its allow or deny stands.
  //       2. On ask: the user's own rules, asked about the call as written.
  //       3. Plan mode: refused, so Claude Code's dialog never opens with
  //          the real values in it. The step waits for the plan to end.
  //       4. No one to ask (-p): core's verdict goes on unchanged. In
  //          dontAsk mode too: the mode settles it as it would any call.
  //       5. ownPrompt off, in a mode known to allow asking: allowed, so the
  //          user isn't asked about every command that uses a key. The
  //          auto-mode classifier then doesn't read the command at all.
  //       6. Otherwise (ownPrompt on, or the mode not known yet): the person,
  //          shown the call as written, picks Allow or Deny. Anything but
  //          Allow (a dismissal, typed text) is a deny.
  //     A hook that fails leaves core's verdict.
  if (ownApproval && cfg.restore && cfg.restoreTools.size > 0) {
    // The permission mode each loop runs in, by agentId ('' for the main
    // one), as the last classic hook event from that loop gave it: tool.check
    // itself isn't told the mode. SubagentStart and SubagentStop are left
    // out, since they may give the parent's.
    const modes = new Map<string, string>()
    const noteMode = (e: unknown): void => {
      const { permission_mode: mode, agent_id: agent } = e as { permission_mode?: unknown; agent_id?: unknown }
      if (typeof mode === 'string') modes.set(typeof agent === 'string' ? agent : '', mode)
    }
    on('classic.SessionStart', ($, e, next) => (noteMode(e), next(e)))
    on('classic.UserPromptSubmit', ($, e, next) => (noteMode(e), next(e)))
    on('classic.PostToolUse', ($, e, next) => (noteMode(e), next(e)))
    on('classic.PostToolUseFailure', ($, e, next) => (noteMode(e), next(e)))

    const tools = new RegExp(`^(?:${[...cfg.restoreTools].map(escapeRe).join('|')})$`)
    on('tool.check', { tool: tools }, async ($, e, next) => {
      const call = e.tool_use_id === undefined ? undefined : filled.get(e.tool_use_id)
      const core = await next(e)
      if (!call || core.decision !== 'ask') return core
      try {
        const rules = await $.tool.check({ tool: e.tool, input: call.input })
        if (rules.decision === 'allow' || rules.decision === 'deny') return rules
      } catch {}
      const mode = modes.get(e.agentId ?? '')
      if (mode === 'plan') {
        const what = e.tool === 'Bash' ? 'a command' : 'a file change'
        return { decision: 'deny', reason: `${brand.name}: ${what} that uses a key waits until plan mode ends. Put this step in the plan instead of running it.` }
      }
      if ((await $.session.surfaces()).length === 0) return core
      if (mode !== undefined && HOLD_MODES.has(mode)) return core
      const many = call.tags.length > 1
      if (!ownPrompt && mode !== undefined && ALLOW_MODES.has(mode)) {
        return { decision: 'allow', reason: `${brand.name}: allowed; it fills in ${many ? 'the keys' : 'the key'} from ${many ? 'their placeholders' : 'its placeholder'} only while the call runs` }
      }
      const names = call.tags.map((t) => (tagNames.has(t) ? `${tagNames.get(t)} (${t})` : t)).join(', ')
      const isBash = e.tool === 'Bash' && typeof call.input.command === 'string'
      const shown = isBash ? String(call.input.command) : JSON.stringify(call.input, null, 2)
      const how = isBash
        ? `The ${many ? 'keys are' : 'key is'} filled in only while it runs, and no one sees ${many ? 'them' : 'it'}. Allow this command?`
        : `The ${many ? 'keys go' : 'key goes'} into the file; the chat only ever shows the placeholder. Allow this ${e.tool}?`
      const question = `${shown}\n\nIt uses ${names}. ${how}`
      let answer = ''
      try {
        answer = await $.ui.ask(question, { options: [ALLOW, DENY], header: brand.name.slice(0, 12) })
      } catch {}
      if (answer === ALLOW) return { decision: 'allow', reason: `${brand.name}: the user allowed this call in its approval prompt` }
      // No placeholder in the reason: the model reads it as the call's error
      return { decision: 'deny', reason: `${brand.name}: the user did not allow this call. Ask them what to do; don't retry it in another form.` }
    }).catch(($, e, next) => next(e))
  }

  // 3. The blocks attached to the first message (CLAUDE.md and friends).
  //    Secrets only: the email in there is the user's own, and the engine
  //    puts it there so the model knows who it is talking to.
  on('prompt.context', async ($, e, next) => {
    const r = await next(e)
    if (!cfg.secrets) return r
    const blocks: PromptContextBlock[] = r.blocks.map((b) => {
      guard(b.text, next)
      return { ...b, text: secretsOnly(b.text) }
    })
    // The raw files behind a rewritten CLAUDE.md would carry the key on to
    // the hooks above, so they are left out once any block changed.
    if (blocks.every((b, i) => b.text === r.blocks[i].text)) return r
    return { blocks }
  }).catch(async ($, e, next) => {
    // Keep the blocks, so the model sees that something was held back.
    const r = await next(e)
    return { blocks: r.blocks.map((b) => ({ ...b, text: BLOCK_WITHHELD })) }
  })

  // 4. What the engine injects on its own after the first message: a file
  //    named with @, a diff of a file that changed on disk, a nested
  //    CLAUDE.md, a settings hook's context. None of it passes tool.call.
  on('prompt.attachment', async ($, e, next) => {
    const r = await next(e)
    if (r.text == null) return r
    const text = r.text
    guard(text, next)
    const isOutside = e.origin.kind !== 'engine' || OUTSIDE_TEXT.has(e.type)
    const isFile = e.type === 'file' || e.type === 'edited_text_file'
    const out = isOutside ? scrub(isFile ? escapeLiteralTags(text) : text) : secretsOnly(text)
    return out === text ? r : { text: out }
  }).catch(() => ({ text: BLOCK_WITHHELD }))

  // 5. A file named with @ is read with no tool call, and its raw text is
  //    stored in the transcript whatever the model is shown. So a file that
  //    holds a secret is refused here, before it is read, and the model is
  //    told to use the Read tool, whose result is scrubbed.
  on('prompt.mention', async ($, e, next) => {
    if (!cfg.secrets) return next(e)
    let text: string
    try {
      const read = await $.fs.read(e.path)
      if (typeof read !== 'string') return next(e)
      text = read
    } catch {
      // Missing: the engine attaches nothing. An image or a PDF too large to
      // read is attached as media, not text. A text file that is present
      // but unreadable (too large, say) cannot be checked, so it is refused.
      if (!(await $.fs.exists(e.path))) return next(e)
      if (MEDIA_FILE.test(e.path)) return next(e)
      return { deny: 'transcript-redactor: could not check this file for secrets; ask Claude to Read it instead' }
    }
    if (looksBinary(text)) return next(e)
    guard(text, next)
    const { tags } = collect(() => scrubSecrets(text, cfg))
    if (tags.size > 0) return { deny: 'transcript-redactor: this file holds a secret; ask Claude to Read it instead, so the value is replaced by a placeholder' }
    return next(e)
  }).catch(($, e, next) => (next.called ? next(e) : { deny: 'transcript-redactor: could not check this file for secrets' }))

  // 6. A subagent's task. The model only ever holds placeholders, and the
  //    Agent tool gets no restore, so this is a second layer: a value that
  //    slipped into the prompt some other way still reaches the subagent as
  //    a placeholder. A workflow agent's prompt cannot be rewritten, only
  //    refused, so one that holds a secret is not started.
  on('agent.spawn', async ($, e, next) => {
    if (!cfg.secrets) return next(e)
    if (e.workflow) {
      guard(e.prompt, next)
      const { tags } = collect(() => secretsOnly(e.prompt))
      if (tags.size === 0) return next(e)
      return { deny: "transcript-redactor: this workflow agent's prompt holds a secret, and a workflow prompt cannot be rewritten. Pass the value by a file or an env var instead." }
    }
    guard(e.prompt, next)
    const prompt = secretsOnly(e.prompt)
    const description = secretsOnly(e.description)
    return prompt === e.prompt && description === e.description ? next(e) : next({ ...e, prompt, description })
  }).catch(($, e, next) => (next.called ? next(e) : { deny: 'transcript-redactor failed to scan this task, so the subagent was not started.' }))
}
