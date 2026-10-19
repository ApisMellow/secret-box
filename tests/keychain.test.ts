import { expect, mock, test } from 'claude-code/testing'

import { boxBackend, keychainReads, SECURITY, SHELL_ACTIVE } from '../hooks/keychain'
import { unmaskable } from '../hooks/register'
import {
  BOX, call, gLine, hex, hexOf, HOME, LIST, mac, MIGRATE, OTHER, registered, securityCalls, TAG, USE, wOutput,
  type Item, type Opts,
} from './fake-mac'

// What a Mac session registers
const MAC_TOOLS = ['request_secret', 'use_secret', 'list_key_names', 'migrate_env_to_keychain']

test('the fake prints exactly what the real security printed for the same values', async () => {
  expect(wOutput('plainvalue123')).toBe('plainvalue123\n')
  expect(gLine('plainvalue123')).toBe('password: "plainvalue123"\n')
  expect(wOutput('line1\nline2')).toBe('6c696e65310a6c696e6532\n')
  expect(gLine('line1\nline2')).toBe('password: 0x6C696E65310A6C696E6532  "line1\\012line2"\n')
  expect(wOutput('abc\n')).toBe('6162630a\n')
  expect(gLine('a\tb')).toBe('password: 0x610962  "a\\011b"\n')
  expect(wOutput('caf\u00e9-\u00fc')).toBe('636166c3a92dc3bc\n')
  expect(gLine('caf\u00e9-\u00fc')).toBe('password: 0x636166C3A92DC3BC  "caf\\303\\251-\\303\\274"\n')
  expect(wOutput('he said "hi" \\ back')).toBe('he said "hi" \\ back\n')
  expect(gLine('he said "hi" \\ back')).toBe('password: 0x686520736169642022686922205C206261636B  "he said "hi" \\134 back"\n')
  expect(wOutput('')).toBe('\n')
  expect(gLine('')).toBe('password: \n')
})

// use_secret's tag for `service`, then what a Write of that tag hands the tool
async function restored($: any, seen: Record<string, unknown>[], input: Record<string, unknown>) {
  const tag = String((await call($, { tool: USE, ...input })).result).match(TAG)![0]
  await call($, { tool: 'Write', file_path: '/repo/k.txt', content: tag })
  return seen.at(-1)!.content
}

// ------------------------------------------------------------------ use_secret

test('use_secret answers with a placeholder, never the value', async ($, on) => {
  const VALUE = hex(1)
  const argvs: string[][] = []
  mac(on, { items: [{ s: 'OPENAI_API_KEY', a: 'tester', value: VALUE }], argvs })
  const r = await call($, { tool: USE, service: 'OPENAI_API_KEY' })
  expect(JSON.stringify(r)).not.toContain(VALUE)
  expect(String(r.result)).toMatch(TAG)
  // No account given: -a is left out, so an item matches by its service alone
  expect(securityCalls(argvs)).toEqual([[SECURITY, 'find-generic-password', '-s', 'OPENAI_API_KEY', '-g']])
})

test('use_secret with an account loads that item, not the first one with the service', async ($, on) => {
  const argvs: string[][] = []
  const seen: Record<string, unknown>[] = []
  mac(on, { items: [{ s: 'shared', a: 'first', value: hex(2) }, { s: 'shared', a: 'second', value: hex(3) }], argvs, seen })
  expect(await restored($, seen, { service: 'shared', account: 'second' })).toBe(hex(3))
  expect(securityCalls(argvs)[0]).toEqual([SECURITY, 'find-generic-password', '-s', 'shared', '-a', 'second', '-g'])
})

test('the placeholder from use_secret becomes the value in Bash, and comes back hidden', async ($, on) => {
  const VALUE = hex(4)
  const seen: Record<string, unknown>[] = []
  mac(on, { items: [{ s: 'svc', value: VALUE }], seen, output: VALUE })
  const tag = String((await call($, { tool: USE, service: 'svc' })).result).match(TAG)![0]
  const r = await call($, { tool: 'Bash', command: `printf '%s' ${tag} | tee out.txt` })
  // The command that ran got the real value: the tag is live and the vault is the redactor's
  expect(String(seen.at(-1)!.command)).toBe(`printf '%s' ${VALUE} | tee out.txt`)
  expect(String(r.result)).toBe(tag)
})

// Each shape security really prints, decoded back to the exact value
const VALUES: [string, string][] = [
  ['plain', 'plain-' + hex(5)],
  ['a newline inside', 'line1-' + hex(6) + '\nline2'],
  ['a trailing newline', hex(7) + '\n'],
  ['a tab', 'a\t' + hex(8)],
  ['UTF-8', 'caf\u00e9-\u00fc-' + hex(9)],
  ['a quote and a backslash', 'he said "hi" \\ ' + hex(10)],
]
// No shell character: a placeholder, restored exactly
for (const [name, VALUE] of [VALUES[0]!, VALUES[4]!]) {
  test(`use_secret gives a value with ${name} a placeholder, restored exactly`, async ($, on) => {
    const seen: Record<string, unknown>[] = []
    mac(on, { items: [{ s: 'svc', value: VALUE }], seen })
    const r = await call($, { tool: USE, service: 'svc' })
    expect(String(r.result)).toMatch(TAG)
    expect((r.context ?? []).join('\n')).toContain('Never write the value into a file')
    expect(await restored($, seen, { service: 'svc' })).toBe(VALUE)
  })
}

// A printable value with a space or a shell character: the redactor would
// refuse its placeholder in Bash and steer Claude to write it to a file, so
// use_secret hands out no placeholder, only the command that reads it
const SHELLY: [string, string][] = [
  ['a space', 'pass word ' + hex(25)],
  ['a $', 'pa$$-' + hex(26)],
  ['an &', 'a&b-' + hex(27)],
  ['a #', 'a#b-' + hex(28)],
  ['a *', 'a*b-' + hex(29)],
  ['quotes and a backslash', VALUES[5]![1]],
]
for (const [name, VALUE] of SHELLY) {
  test(`use_secret gives a value with ${name} no placeholder, only the command that reads it`, async ($, on) => {
    mac(on, { items: [{ s: "Bob's site", a: 'bob x', value: VALUE }] })
    const answer = await call($, { tool: USE, service: "Bob's site", account: 'bob x' })
    const r = String(answer.result)
    const guide = (answer.context ?? []).join('\n')
    const command = `"$(${SECURITY} find-generic-password -s 'Bob'\\''s site' -a 'bob x' -w)"`
    const inString = `-H "Authorization: Bearer ${command.slice(1, -1)}"`
    expect(r + guide).not.toMatch(TAG)
    expect(JSON.stringify(answer)).not.toContain(VALUE)
    // The row the user sees holds the form to write; the context, how to place it
    expect(r).toBe(`Loaded Bob's site (account bob x) from the Keychain. Use it in Bash as ${command}.`)
    // Both ways to place it: quoted as a whole argument, bare inside a quoted string
    expect(guide).toContain(`As a whole argument of its own, write exactly: ${command}.`)
    expect(guide).toContain(`Inside a string that is already in double quotes, write it without the outer quotes`)
    expect(guide).toContain(inString)
    expect(guide).toContain('Never write the value into a file')
    // Each is a read the pre-load pins to this very item
    const read = [{ kind: 'generic', criteria: [['-s', "Bob's site"], ['-a', 'bob x']], keychains: [] }]
    expect(keychainReads(`printf '%s' ${command} | tee out.txt`, ENV)).toEqual(read)
    expect(keychainReads(`curl ${inString} https://api.example.com`, ENV)).toEqual(read)
  })
}

test('the command use_secret gives runs with the value out of the command and out of the output', async ($, on) => {
  const VALUE = 'pass word ' + hex(30)
  const argvs: string[][] = []
  const seen: Record<string, unknown>[] = []
  mac(on, { items: [{ s: 'site', value: VALUE }], argvs, seen, output: VALUE })
  const command = String((await call($, { tool: USE, service: 'site' })).result).match(/"\$\(.*? -w\)"/)![0]
  const r = await call($, { tool: 'Bash', command: `printf '%s' ${command} | tee out.txt` })
  expect(r.deny).toBeUndefined()
  expect(String(seen.at(-1)!.command)).not.toContain(VALUE)
  expect(String(r.result)).not.toContain(VALUE)
  expect(String(r.result)).toMatch(TAG)
  // use_secret's read, then the pre-load's read of the same item
  expect(securityCalls(argvs)).toEqual([[SECURITY, 'find-generic-password', '-s', 'site', '-g'], [SECURITY, 'find-generic-password', '-s', 'site', '-g']])
})

// A newline, a tab, or a non-ASCII letter beside a shell character: -w prints
// hex, so no command can read it either; it is not handed out for Bash at all
for (const [name, VALUE] of [VALUES[1]!, VALUES[2]!, VALUES[3]!, ['short lines', 'abcd\nefgh'], ['a non-ASCII letter and a space', 'café x-' + hex(31)]] as [string, string][]) {
  test(`use_secret won't hand out a value with ${name} for Bash, and still hides it exactly`, async ($, on) => {
    mac(on, { items: [{ s: 'svc', value: VALUE }], output: VALUE })
    const answer = await call($, { tool: USE, service: 'svc' })
    const r = String(answer.result)
    const guide = (answer.context ?? []).join('\n')
    expect(r).toBe("Loaded svc from the Keychain, but its value can't go into a Bash command.")
    expect(guide).not.toMatch(TAG)
    expect(guide).not.toContain('$(')
    expect(guide).toContain('Never write the value into a file')
    expect(guide).toContain('base64')
    // Decoded exactly: printed whole, the value comes back hidden
    expect(String((await call($, { tool: 'Bash', command: 'cat x' })).result)).not.toContain(VALUE)
  })
}

test("SHELL_ACTIVE is the redactor's rule: a value it flags is exactly one Bash refuses", async ($, on) => {
  const values = Array.from({ length: 127 }, (_, i) => `pin-${hex(40).slice(0, 10)}${String.fromCharCode(i + 1)}tail`)
  mac(on, { items: values.map((value, i) => ({ s: `pin${i}`, value })), output: (command) => (/-s pin(\d+)/.test(command) ? values[Number(RegExp.$1)]! + '\n' : '') })
  for (const [i, value] of values.entries()) {
    const tag = String((await call($, { tool: 'Bash', command: `security find-generic-password -s pin${i} -w` })).result).match(TAG)![0]
    const r = await call($, { tool: 'Bash', command: `printf '%s' ${tag}` })
    expect(r.deny !== undefined, `char ${i + 1}`).toBe(SHELL_ACTIVE.test(value))
  }
})

test('after use_secret, the hex security prints for the value comes back hidden too', async ($, on) => {
  const VALUE = 'line1-' + hex(12) + '\nline2'
  mac(on, { items: [{ s: 'pem', value: VALUE }], output: wOutput(VALUE) + gLine(VALUE) })
  await call($, { tool: USE, service: 'pem' })
  const out = String((await call($, { tool: 'Bash', command: 'cat dump.txt' })).result)
  expect(out).not.toContain(hexOf(VALUE))
  expect(out).not.toContain(hexOf(VALUE).toUpperCase())
  expect(out).not.toContain(hex(12))
})

test('a missing item answers with the command to add it, and nothing security printed', async ($, on) => {
  mac(on)
  const plain = String((await call($, { tool: USE, service: 'NEW_KEY' })).result)
  expect(plain).toContain('security add-generic-password -U -s NEW_KEY -a tester -w')
  expect(plain).not.toContain('SecKeychainSearchCopyNext')
  expect(plain).not.toMatch(TAG)
  const named = String((await call($, { tool: USE, service: "Bob's key", account: 'work' })).result)
  expect(named).toContain(`security add-generic-password -U -s 'Bob'\\''s key' -a work -w`)
})

test('an empty item asks for a value', async ($, on) => {
  mac(on, { items: [{ s: 'svc', value: '' }] })
  const r = String((await call($, { tool: USE, service: 'svc' })).result)
  expect(r).toContain('holds no value')
  expect(r).toContain('security add-generic-password -U -s svc -a tester -w')
  expect(r).not.toMatch(TAG)
})

test('a read security refuses asks to unlock or allow, and never shows what it printed', async ($, on) => {
  mac(on, { fail: { exitCode: 51, stdout: 'LEAKED-STDOUT', stderr: 'LEAKED-STDERR' } })
  const r = JSON.stringify(await call($, { tool: USE, service: 'svc' }))
  expect(r).toContain('exited 51')
  expect(r).toContain('security unlock-keychain')
  expect(r).not.toContain('add-generic-password')
  expect(r).not.toContain('LEAKED')
})

test('a cut-off answer from security is a failure, not a value', async ($, on) => {
  mac(on, { items: [{ s: 'svc', value: hex(13) }], truncated: true })
  const r = JSON.stringify(await call($, { tool: USE, service: 'svc' }))
  expect(r).toContain('cut off')
  expect(r).not.toMatch(TAG)
  expect(r).not.toContain(hex(13))
})

test('use_secret refuses a missing, multi-line or overlong name before running security', async ($, on) => {
  const argvs: string[][] = []
  mac(on, { items: [{ s: 'svc', value: hex(14) }], argvs })
  for (const input of [{}, { service: '' }, { service: 'a\nb' }, { service: 'svc', account: 'x\u0007' }, { service: 'x'.repeat(257) }]) {
    expect(String((await call($, { tool: USE, ...input })).result)).toContain('Nothing was loaded')
  }
  expect(securityCalls(argvs)).toEqual([])
})

test('use_secret says so when security cannot run at all', async ($, on) => {
  mac(on, { deny: "Command '/usr/bin/security' not found" })
  expect(await call($, { tool: USE, service: 'svc' })).toEqual({
    result: 'secret-box could not read the Keychain: /usr/bin/security is missing: the Keychain backend needs macOS. Nothing was loaded.',
  })
})

// ------------------------------------------------------- direct reads in Bash

const ENV = { USER: 'tester', HOME }
const g = (criteria: string[][], keychains: string[] = []) => ({ kind: 'generic', criteria, keychains })
const U = 'unknown'
const READS: [string, string, unknown[]][] = [
  ['bare -s', 'security find-generic-password -s OPENAI_API_KEY -w', [g([['-s', 'OPENAI_API_KEY']])]],
  ['double-quoted -s', 'security find-generic-password -s "my key" -w', [g([['-s', 'my key']])]],
  ['single-quoted -s keeps its $', "security find-generic-password -w -s 'my $key'", [g([['-s', 'my $key']])]],
  ['-a before -s, with -g', 'security find-generic-password -a david -s svc -g', [g([['-a', 'david'], ['-s', 'svc']])]],
  ['-a "$USER"', 'security find-generic-password -s svc -a "$USER" -w', [g([['-s', 'svc'], ['-a', 'tester']])]],
  ['-a ${USER}', 'security find-generic-password -s svc -a ${USER} -w', [g([['-s', 'svc'], ['-a', 'tester']])]],
  ['a label', 'security find-generic-password -s svc -l "Work token" -w', [g([['-s', 'svc'], ['-l', 'Work token']])]],
  ['every generic match option', 'security find-generic-password -a A -c aapl -C note -D kind -G gen -j "a note" -l L -s S -w', [g([['-a', 'A'], ['-c', 'aapl'], ['-C', 'note'], ['-D', 'kind'], ['-G', 'gen'], ['-j', 'a note'], ['-l', 'L'], ['-s', 'S']])]],
  ['bundled -wa NAME', 'security find-generic-password -s svc -wa acct', [g([['-s', 'svc'], ['-a', 'acct']])]],
  ['attached -sNAME', 'security find-generic-password -ssvc -w', [g([['-s', 'svc']])]],
  ['a keychain file after the options', 'security find-generic-password -s svc -w ~/Library/Keychains/other.keychain-db', [g([['-s', 'svc']], [OTHER])]],
  ['-- before a keychain file', 'security find-generic-password -s svc -- /tmp/k.keychain-db', [g([['-s', 'svc']], ['/tmp/k.keychain-db'])]],
  ['the same flag twice is passed on twice', 'security find-generic-password -s A -s B -w', [g([['-s', 'A'], ['-s', 'B']])]],
  ['a trailing comment', 'security find-generic-password -s REAL -w # was -s OTHER', [g([['-s', 'REAL']])]],
  ['a # inside a word is text', 'security find-generic-password -s a#b -w', [g([['-s', 'a#b']])]],
  ['redirections', 'security find-generic-password -s svc -w 2>/dev/null >&2 &>log | pbcopy', [g([['-s', 'svc']])]],
  ['2>&1', 'security find-generic-password -s svc -g 2>&1', [g([['-s', 'svc']])]],
  ['a line continuation', 'security find-generic-password \\\n  -s svc -w', [g([['-s', 'svc']])]],
  ['tabs', 'security find-generic-password\t-s\tsvc\t-w', [g([['-s', 'svc']])]],
  ['a ; inside quotes', 'security find-generic-password -s "a;b" -w', [g([['-s', 'a;b']])]],
  ['one word across quotes', `security find-generic-password -s "my"' 'key -w`, [g([['-s', 'my key']])]],
  ['an escaped space', 'security find-generic-password -s my\\ key -w', [g([['-s', 'my key']])]],
  ['the full path, a global option', '/usr/bin/security -q find-generic-password -s svc -w', [g([['-s', 'svc']])]],
  ['inside $( ) in double quotes', 'curl -H "Authorization: Bearer $(security find-generic-password -s svc -w)" https://api.example.com', [g([['-s', 'svc']])]],
  ['inside backticks', 'K=`security find-generic-password -s svc -w`', [g([['-s', 'svc']])]],
  ['two reads', 'security find-generic-password -s one -w; security find-generic-password -s two -w', [g([['-s', 'one']]), g([['-s', 'two']])]],
  ['the same read twice is one', 'security find-generic-password -s svc -w && security find-generic-password -s svc -w', [g([['-s', 'svc']])]],
  ['internet, protocol and port', 'security find-internet-password -s github.com -r htps -P 443 -w', [{ kind: 'internet', criteria: [['-s', 'github.com'], ['-r', 'htps'], ['-P', '443']], keychains: [] }]],
  ['no match option at all', 'security find-generic-password -w', [g([])]],
  // Reads it can't pin down to one item
  ['a variable it does not hold', 'security find-generic-password -s "$SVC" -w', [U]],
  ['a bare variable', 'security find-generic-password -s $SVC -w', [U]],
  ['$USER the command sets', 'USER=bob; security find-generic-password -s svc -a "$USER" -w', [U]],
  ['a word before -s, where getopt stops', 'security find-generic-password login.keychain -s svc -w', [U]],
  ['a relative keychain file', 'security find-generic-password -s svc -w other.keychain-db', [U]],
  ['an option the subcommand does not take', 'security find-generic-password -s svc -P 443 -w', [U]],
  ['-h', 'security find-generic-password -h', [U]],
  ['-s with nothing after it', 'security find-generic-password -s', [U]],
  ['an env prefix', 'FOO=1 security find-generic-password -s svc -w', [U]],
  ['sudo', 'sudo security find-generic-password -s svc -w', [U]],
  ['inside sh -c', "sh -c 'security find-generic-password -s svc -w'", [U]],
  ['inside an echo', 'echo "security find-generic-password -s svc -w"', [U]],
  ['zsh =cmd', 'security find-generic-password -s =ls -w', [U]],
  ['~name', 'security find-generic-password -s ~svc -w', [U]],
  ['a brace', 'security find-generic-password -s {a,b} -w', [U]],
  ['a glob', 'security find-generic-password -s svc* -w', [U]],
  ["$'...'", "security find-generic-password -s $'svc' -w", [U]],
  ['an unterminated quote', 'security find-generic-password -s "svc -w', [U]],
  ['not a read', 'security add-generic-password -s svc -a me -w', []],
  // The command changes a variable it names, or the shell would change the value
  ['a for loop that sets USER', 'for USER in a b\ndo\nsecurity find-generic-password -s x -a "$USER" -w\ndone', [U]],
  ['while read USER', 'while read USER; do security find-generic-password -s x -a "$USER" -w; done < users', [U]],
  ['unset USER', 'unset USER; security find-generic-password -s x -a "$USER" -w', [U]],
  ['export HOME, then ~/', 'export HOME=/tmp/h; security find-generic-password -s x -w ~/k.keychain-db', [U]],
  ['a zsh modifier', 'security find-generic-password -s x -a $USER:u -w', [U]],
  ['a zsh subscript', 'security find-generic-password -s x -a "$USER[1,3]" -w', [U]],
  ['an unquoted $USER with IFS set', 'IFS=e; security find-generic-password -s x -a $USER -w', [U]],
  ['a quoted $USER with IFS set', 'IFS=e; security find-generic-password -s x -a "$USER" -w', [g([['-s', 'x'], ['-a', 'tester']])]],
  ['a keyword before security', 'if true; then security find-generic-password -s x -w; fi', [g([['-s', 'x']])]],
  // security run so that what it prints can't be pinned down
  ['dump-keychain', 'security dump-keychain -d', [U]],
  ['dump-keychain after a global option', 'security -q dump-keychain', [U]],
  ['sudo dump-keychain', 'sudo security dump-keychain -d', [U]],
  ['security -i reading commands', 'security -i < commands.txt', [U]],
  ['security with no command', 'security', [U]],
  ['a subcommand spelled around', 'security find-generic-pass\\word -s svc -w', [g([['-s', 'svc']])]],
  // Only naming the subcommand reads nothing
  ['a comment that names the subcommand', 'ls -la # security find-generic-password -s svc -w', []],
  ['grep for the subcommand', 'grep -rn find-generic-password hooks/', []],
]
for (const [name, command, reads] of READS) {
  test(`keychainReads: ${name}`, async () => {
    expect(keychainReads(command, ENV).map((r: any) => (r.unknown ? U : r))).toEqual(reads)
  })
}

test('a direct Keychain read in Bash is loaded before it runs, and its output comes back hidden', async ($, on) => {
  const VALUE = hex(15)
  const argvs: string[][] = []
  const log: string[] = []
  mac(on, { items: [{ s: 'secret-box-test', value: VALUE }], argvs, log, output: wOutput(VALUE) })
  const r = await call($, { tool: 'Bash', command: 'security find-generic-password -s secret-box-test -w' })
  expect(String(r.result)).not.toContain(VALUE)
  expect(String(r.result)).toMatch(TAG)
  expect(securityCalls(argvs)).toEqual([[SECURITY, 'find-generic-password', '-s', 'secret-box-test', '-g']])
  // uname, then the item, then the command
  expect(log).toEqual(['process.run /usr/bin/uname -s', `process.run ${SECURITY} find-generic-password`, 'tool Bash'])
})

// Two items share a service; the command reads the SECOND one. Each of these
// fetched the first one before the pre-load passed on every match option.
const SHARED: [string, Item[], string, string[]][] = [
  ['-a "$USER"', [{ s: 'shared', a: 'first', value: hex(16) }, { s: 'shared', a: 'tester', value: hex(17) }],
    'security find-generic-password -s shared -a "$USER" -w', ['-s', 'shared', '-a', 'tester']],
  ['a label', [{ s: 'shared', l: 'Work token', value: hex(16) }, { s: 'shared', l: 'Home token', value: hex(17) }],
    'security find-generic-password -s shared -l "Home token" -w', ['-s', 'shared', '-l', 'Home token']],
  ['bundled -wa', [{ s: 'shared', a: 'first', value: hex(16) }, { s: 'shared', a: 'second', value: hex(17) }],
    'security find-generic-password -s shared -wa second', ['-s', 'shared', '-a', 'second']],
  ['a keychain file', [{ s: 'shared', value: hex(16) }, { s: 'shared', keychain: OTHER, value: hex(17) }],
    'security find-generic-password -s shared -w ~/Library/Keychains/other.keychain-db', ['-s', 'shared', OTHER]],
  ['a comment naming the other account', [{ s: 'shared', a: 'first', value: hex(16) }, { s: 'shared', a: 'second', value: hex(17) }],
    'security find-generic-password -s shared -a second -w # -a first', ['-s', 'shared', '-a', 'second']],
  ['an internet port', [{ kind: 'internet', s: 'github.com', r: 'htps', P: '443', value: hex(16) }, { kind: 'internet', s: 'github.com', r: 'htps', P: '8443', value: hex(17) }],
    'security find-internet-password -s github.com -r htps -P 8443 -w', ['-s', 'github.com', '-r', 'htps', '-P', '8443']],
]
for (const [name, items, command, args] of SHARED) {
  test(`two items share a service: a direct read by ${name} hides the second`, async ($, on) => {
    const argvs: string[][] = []
    const second = items[1]!
    mac(on, { items, argvs, output: wOutput(second.value) })
    const r = String((await call($, { tool: 'Bash', command })).result)
    expect(r).not.toContain(second.value)
    expect(r).toMatch(TAG)
    const fetched = securityCalls(argvs)[0]!
    expect(fetched.filter((a) => a !== '-g').slice(2)).toEqual(args)
  })
}

// Whatever form security prints the value in (text, -w hex, -g hex and its
// escaped copy), none of it comes back, not even the hex run inside the value
for (const [name, VALUE] of VALUES.slice(1)) {
  for (const flag of ['-w', '-g']) {
    test(`a direct ${flag} read of a value with ${name} comes back hidden`, async ($, on) => {
      mac(on, { items: [{ s: 'svc', value: VALUE }], output: flag === '-w' ? wOutput(VALUE) : gLine(VALUE) })
      const r = String((await call($, { tool: 'Bash', command: `security find-generic-password -s svc ${flag}` })).result)
      for (const shown of [VALUE, hexOf(VALUE), hexOf(VALUE).toUpperCase(), VALUE.match(/[0-9a-f]{48}/)![0]]) expect(r).not.toContain(shown)
      expect(r).toMatch(TAG)
    })
  }
}

test('bare hex is left alone by the detector, so the pre-load is what hides a direct read', async ($, on) => {
  const VALUE = hex(19)
  mac(on, { output: VALUE + '\n' })
  expect(String((await call($, { tool: 'Bash', command: 'cat digest.txt' })).result)).toContain(VALUE)
})

test('a read spelled around find-generic-password is still loaded and hidden', async ($, on) => {
  const VALUE = hex(32)
  mac(on, { items: [{ s: 'svc', value: VALUE }], output: wOutput(VALUE) })
  const r = String((await call($, { tool: 'Bash', command: 'security find-generic-pass\\word -s svc -w' })).result)
  expect(r).not.toContain(VALUE)
  expect(r).toMatch(TAG)
})

test('a command that prints one line of a multi-line value gets that line hidden', async ($, on) => {
  // Each line is bare hex, which the detector alone leaves alone
  const VALUE = hex(33) + '\n' + hex(34)
  mac(on, { items: [{ s: 'pem', value: VALUE }], output: hex(34) + '\n' })
  const r = String((await call($, { tool: 'Bash', command: 'security find-generic-password -s pem -w | xxd -r -p | tail -1' })).result)
  expect(r).not.toContain(hex(34))
  expect(r).toMatch(TAG)
})

test('keychainReads: $USER, $LOGNAME and $HOME as the shell would hand them over', async () => {
  const env = { USER: 'tester', LOGNAME: 'tlog', HOME: '/Users/Jane Doe' }
  const reads = (command: string) => keychainReads(command, env).map((r: any) => (r.unknown ? U : r))
  expect(reads('security find-generic-password -s x -a "$LOGNAME" -w')).toEqual([g([['-s', 'x'], ['-a', 'tlog']])])
  // A HOME with a space: whole when quoted or as ~, split by bash when bare
  expect(reads('security find-generic-password -s x -w "$HOME/k.keychain-db"')).toEqual([g([['-s', 'x']], ['/Users/Jane Doe/k.keychain-db'])])
  expect(reads('security find-generic-password -s x -w ~/k.keychain-db')).toEqual([g([['-s', 'x']], ['/Users/Jane Doe/k.keychain-db'])])
  expect(reads('security find-generic-password -s x -w $HOME/k.keychain-db')).toEqual([U])
})

// Every read the pre-load can't promise to hide goes to unmaskable(): the
// refuseUnmaskable option refuses it, and by default it runs
const UNMASKABLE: [string, Opts, string][] = [
  ['a read it cannot parse', {}, 'security find-generic-password -s "$SVC" -w'],
  ['a variable the command sets', {}, 'unset USER; security find-generic-password -s x -a "$USER" -w'],
  ['dump-keychain', {}, 'security dump-keychain -d'],
  ['security -i', {}, 'security -i < commands.txt'],
  ['a read inside sh -c', {}, "sh -c 'security find-generic-password -s svc -w'"],
  ['a value too short to hide', { items: [{ s: 'pin', value: 'abc12' }] }, 'security find-generic-password -s pin -w'],
  ['a fetch that fails', { deny: 'timed out' }, 'security find-generic-password -s svc -w'],
  ['a locked keychain', { fail: { exitCode: 36, stdout: '', stderr: 'User interaction is not allowed.' } }, 'security find-generic-password -s svc -w'],
]
for (const [name, opts, command] of UNMASKABLE) {
  test(`refuseUnmaskable on: ${name} is refused before it runs`, { options: { refuseUnmaskable: true } }, async ($, on) => {
    const seen: Record<string, unknown>[] = []
    mac(on, { ...opts, seen })
    expect(String((await call($, { tool: 'Bash', command })).deny)).toContain("so what it prints can't be hidden")
    expect(seen).toEqual([])
  })
  test(`refuseUnmaskable off (default): ${name} runs`, async ($, on) => {
    mac(on, opts)
    expect(await call($, { tool: 'Bash', command })).toEqual({ result: 'ran' })
  })
}

test('refuseUnmaskable on: reads it can pin down and hide, missing items, and mere mentions all run', { options: { refuseUnmaskable: true } }, async ($, on) => {
  mac(on, { items: [{ s: 'svc', value: hex(35) }] })
  for (const command of [
    'security find-generic-password -s svc -w',
    'security find-generic-password -s missing -w',
    'grep -rn find-generic-password hooks/',
    'ls # security dump-keychain -d',
  ]) {
    expect(await call($, { tool: 'Bash', command })).toEqual({ result: 'ran' })
  }
})

test('unmaskable(): undefined when off, a refusal naming why when on', async () => {
  expect(unmaskable('it dumps the keychain', false)).toBeUndefined()
  expect(unmaskable('it dumps the keychain', true)).toEqual({ deny: "secret-box: this command reads the Keychain, but it dumps the keychain, so what it prints can't be hidden. Use use_secret instead." })
})

// ------------------------------------------------------------------ platforms

const UPSTREAM_DESCRIPTION =
  'Ask the user for a secret (API key, token, password) without it ever entering the conversation. ' +
  'The user pastes it into a masked box and the mod saves it to the project .env. You get back the ' +
  'variable name and a placeholder like [REDACTED-SECRET-1a2b3c4d]. Write that placeholder in a command ' +
  'or file and it becomes the real value when the tool runs. Use this INSTEAD of asking the user to ' +
  'paste a secret into chat.'


test('off macOS only request_secret is registered, exactly as upstream', async ($, on) => {
  const specs = await registered($, on, { platform: 'Linux' })
  expect(specs.map((s) => s.name)).toEqual(['request_secret'])
  expect(specs[0]!.description).toBe(UPSTREAM_DESCRIPTION)
  expect(specs[0]!.inputSchema.properties.name.description).toBe('Environment variable name, e.g. STRIPE_SECRET_KEY')
})

test('on macOS use_secret is registered too, in the prompt', async ($, on) => {
  const specs = await registered($, on, {})
  expect(specs.map((s) => [s.name, s.isDeferred])).toEqual([['request_secret', false], ['use_secret', false], ['list_key_names', false], ['migrate_env_to_keychain', undefined]])
  expect(specs[0]!.description).toContain('macOS Keychain')
})

test('on macOS with backend dotenv, use_secret is still registered and the box is upstream', { options: { backend: 'dotenv' } }, async ($, on) => {
  const specs = await registered($, on, {})
  expect(specs.map((s) => s.name)).toEqual(MAC_TOOLS)
  expect(specs[0]!.description).toBe(UPSTREAM_DESCRIPTION)
})

test('off macOS the pre-load does nothing and use_secret says it needs macOS', async ($, on) => {
  const argvs: string[][] = []
  mac(on, { platform: 'Linux', argvs, items: [{ s: 'svc', value: hex(20) }] })
  expect(await call($, { tool: 'Bash', command: 'security find-generic-password -s svc -w' })).toEqual({ result: 'ran' })
  expect(String((await call($, { tool: USE, service: 'svc' })).result)).toContain('needs macOS')
  expect(securityCalls(argvs)).toEqual([])
})

test('boxBackend: auto and unknown values follow the platform; a named backend is kept', async () => {
  expect(['mac', 'other', 'unknown'].map((p) => boxBackend('auto', p))).toEqual(['keychain', 'dotenv', 'unknown'])
  expect([boxBackend(undefined, 'mac'), boxBackend('Keychain ', 'mac'), boxBackend('weird', 'other')]).toEqual(['keychain', 'keychain', 'dotenv'])
  expect([boxBackend('keychain', 'other'), boxBackend('dotenv', 'unknown')]).toEqual(['keychain', 'dotenv'])
})

test('uname runs by its full path', async ($, on) => {
  const argvs: string[][] = []
  mac(on, { argvs, items: [{ s: 'svc', value: hex(36) }] })
  await call($, { tool: USE, service: 'svc' })
  expect(argvs[0]).toEqual(['/usr/bin/uname', '-s'])
})

test('with no /usr/bin/uname, /bin/uname answers', async ($, on) => {
  const specs = await registered($, on, { uname: 'bin-only' })
  expect(specs.map((s) => s.name)).toEqual(MAC_TOOLS)
})

test("Windows says so in OS, uname never runs, and the tools are Credential Manager's", async ($, on) => {
  const argvs: string[][] = []
  const specs = await registered($, on, { env: { OS: 'Windows_NT', USER: 'tester' }, argvs })
  expect(specs.map((s) => s.name)).toEqual(MAC_TOOLS)
  expect(specs[0]!.description).toContain('Windows Credential Manager')
  expect(specs[0]!.description).not.toContain('macOS')
  expect(argvs.filter((a) => a[0]!.endsWith('uname'))).toEqual([])
})

test("with no uname, macOS's version file says it is a Mac", async ($, on) => {
  const toasts: string[] = []
  const specs = await registered($, on, { uname: 'none', versionFile: 'present', toasts })
  expect(specs.map((s) => s.name)).toEqual(MAC_TOOLS)
  expect(specs[0]!.description).toContain('macOS Keychain')
  expect(toasts).toEqual([])
})

test('with no uname and no macOS version file (NixOS, Termux), it is the upstream mod', async ($, on) => {
  const toasts: string[] = []
  const specs = await registered($, on, { uname: 'none', versionFile: 'absent', toasts })
  expect(specs.map((s) => s.name)).toEqual(['request_secret'])
  expect(specs[0]!.description).toBe(UPSTREAM_DESCRIPTION)
  expect(toasts).toEqual([])
})

test('with no uname and no macOS version file, backend auto is the upstream box', async ($, on) => {
  await expectUpstreamBox($, on, { uname: 'none', versionFile: 'absent' })
})

test("when neither uname nor the version file can be checked, use_secret stays on and a toast says why", async ($, on) => {
  const toasts: string[] = []
  const specs = await registered($, on, { uname: 'none', versionFile: 'fails', toasts })
  expect(specs.map((s) => s.name)).toEqual(MAC_TOOLS)
  expect(toasts.join('\n')).toContain("couldn't tell whether this is a Mac")
})

test("when neither can be checked, the box with backend auto writes nothing", async ($, on) => {
  const opened: string[] = []
  const writes: { path: string; text: string }[] = []
  const argvs: string[][] = []
  mac(on, { uname: 'none', versionFile: 'fails', opened, writes, argvs })
  const r = String((await call($, { tool: BOX, name: 'STRIPE_SECRET_KEY', reason: 'x' })).result)
  expect(r).toContain("couldn't tell whether this is a Mac")
  expect(r).toContain('nothing was written')
  expect([opened, writes, securityCalls(argvs)]).toEqual([[], [], []])
})

// ------------------------------------------------------------------- the box

// Claude calls request_secret, the box opens, the person types `value` and
// presses Enter. Resolves with what Claude is answered.
async function fillBox($: any, on: any, value: string, opts: Opts) {
  const clock = mock.clock(on)
  mac(on, { ...opts, clock })
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

test('on macOS the box saves to the Keychain by default, and leaves .env alone', async ($, on) => {
  const VALUE = hex(21)
  const argvs: string[][] = []
  const writes: { path: string; text: string }[] = []
  const r = await fillBox($, on, VALUE, { argvs, writes })
  expect(securityCalls(argvs)).toEqual([[SECURITY, 'add-generic-password', '-U', '-s', 'STRIPE_SECRET_KEY', '-a', 'tester', '-j', 'secret-box', '-w', VALUE]])
  expect(writes).toEqual([])
  expect(JSON.stringify(r)).not.toContain(VALUE)
  expect(String(r.result)).toMatch(TAG)
  expect((r.context ?? []).join('\n')).toContain('call use_secret with service STRIPE_SECRET_KEY and account tester')
})

test("the box's row is one line with the placeholder; the context, scanned like any answer, keeps the pointer line readable", async ($, on) => {
  const VALUE = hex(38)
  const r = await fillBox($, on, VALUE, {})
  const tag = String(r.result).match(TAG)![0]
  expect(r.result).toBe(`The user entered STRIPE_SECRET_KEY, saved to the macOS Keychain (account tester) as ${tag}.`)
  const guide = (r.context ?? []).join('\n')
  expect(guide).toContain(`write ${tag} in a Bash command`)
  // The detector takes a pointer for a password; it is put back as written
  expect(guide).toContain('write the line ENV_NAME=keychain:STRIPE_SECRET_KEY?account=tester there')
  expect(JSON.stringify(r)).not.toContain(VALUE)
})

test('the box saves under the keychainAccount setting', { options: { keychainAccount: 'work' } }, async ($, on) => {
  const argvs: string[][] = []
  await fillBox($, on, hex(22), { argvs })
  expect(securityCalls(argvs)[0]!.slice(0, 7)).toEqual([SECURITY, 'add-generic-password', '-U', '-s', 'STRIPE_SECRET_KEY', '-a', 'work'])
})

test('a Keychain save that fails says so, and hands out no placeholder', async ($, on) => {
  const r = await fillBox($, on, hex(23), { fail: { exitCode: 45, stdout: '', stderr: 'LEAKED-STDERR' } })
  expect(r).toEqual({ result: 'Saving STRIPE_SECRET_KEY failed: security exited 45' })
})

// Upstream's box: .env and .gitignore written, upstream's answer word for word
async function expectUpstreamBox($: any, on: any, opts: Opts) {
  const VALUE = hex(24)
  const argvs: string[][] = []
  const writes: { path: string; text: string }[] = []
  const r = await fillBox($, on, VALUE, { ...opts, argvs, writes })
  expect(securityCalls(argvs)).toEqual([])
  expect(writes).toEqual([
    { path: '/repo/.env', text: `STRIPE_SECRET_KEY=${VALUE}\n` },
    { path: '/repo/.gitignore', text: '.env\n' },
  ])
  const tag = String(r.result).match(TAG)![0]
  expect(r.result).toBe(
    `The user entered STRIPE_SECRET_KEY. It was saved to .env (and added .env to .gitignore). You can't see the value. To use it in a command or a file, write ${tag}: it becomes the real value when the tool runs and is hidden again in the output. Code should read it from the environment.`,
  )
}

test('backend dotenv on macOS is the upstream box', { options: { backend: 'dotenv' } }, async ($, on) => {
  await expectUpstreamBox($, on, {})
})

test('off macOS the box defaults to dotenv: the upstream box', async ($, on) => {
  await expectUpstreamBox($, on, { platform: 'Linux' })
})

test("when uname can't answer, backend dotenv set by hand is still the upstream box", { options: { backend: 'dotenv' } }, async ($, on) => {
  await expectUpstreamBox($, on, { uname: 'none', versionFile: 'fails' })
})

test('a value with a space typed into the box gets the read-it command, not a placeholder', async ($, on) => {
  const VALUE = 'pass word ' + hex(37)
  const answer = await fillBox($, on, VALUE, {})
  const r = String(answer.result)
  expect(r).not.toMatch(TAG)
  expect(JSON.stringify(answer)).not.toContain(VALUE)
  expect(r).toContain(`"$(${SECURITY} find-generic-password -s STRIPE_SECRET_KEY -a tester -w)"`)
  expect((answer.context ?? []).join('\n')).toContain('Never write the value into a file')
})

test('backend keychain off macOS is refused before the box opens', { options: { backend: 'keychain' } }, async ($, on) => {
  const opened: string[] = []
  mac(on, { platform: 'Linux', opened })
  const r = String((await call($, { tool: BOX, name: 'STRIPE_SECRET_KEY', reason: 'x' })).result)
  expect(r).toContain('needs macOS')
  expect(opened).toEqual([])
})
