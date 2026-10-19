// .env text and the pointers in it, as both parsers must read it: the mod's
// envPointers (hooks/keychain.js), which decides what is loaded before the
// runner runs, and bin/keychain-env, which decides what is resolved.
// keychain-v2.test.ts checks the first; runner-parity.test.mts runs the
// runner with `security` stubbed out and checks the second.
export type Found = [name: string, service: string, account?: string]

export const ENV_CASES: { name: string; text: string; pointers: Found[] }[] = [
  { name: 'plain', text: 'OPENAI_API_KEY=keychain:openai\n', pointers: [['OPENAI_API_KEY', 'openai']] },
  { name: 'with an account', text: 'K=keychain:svc?account=work\n', pointers: [['K', 'svc', 'work']] },
  { name: 'export, tabs and spaces', text: '\texport\tK =  keychain:svc\t\n', pointers: [['K', 'svc']] },
  { name: 'double quotes and a comment', text: 'K="keychain:svc" # a note\n', pointers: [['K', 'svc']] },
  { name: 'single quotes', text: "K='keychain:svc'\n", pointers: [['K', 'svc']] },
  { name: 'bare, with a comment', text: 'K=keychain:svc # a note\n', pointers: [['K', 'svc']] },
  { name: 'CRLF lines', text: 'K=keychain:svc\r\nL=keychain:other\r\n', pointers: [['K', 'svc'], ['L', 'other']] },
  { name: 'a CR inside a comment', text: 'API_KEY=keychain:svc # a\rb\n', pointers: [['API_KEY', 'svc']] },
  { name: 'U+2028 inside a comment', text: 'API_KEY=keychain:svc # a b\n', pointers: [['API_KEY', 'svc']] },
  { name: 'U+2029 inside a comment', text: 'API_KEY=keychain:svc # a b\n', pointers: [['API_KEY', 'svc']] },
  { name: 'U+2028 inside the value', text: 'API_KEY=keychain:svc x\n', pointers: [] },
  { name: 'U+2029 before the value', text: 'API_KEY= keychain:svc\n', pointers: [] },
  { name: 'a no-break space before #', text: 'API_KEY=keychain:svc # c\n', pointers: [] },
  { name: 'VT and FF are blanks', text: 'K=\vkeychain:svc\f\n', pointers: [['K', 'svc']] },
  { name: 'a CR before the value', text: 'K=\rkeychain:svc\n', pointers: [['K', 'svc']] },
  { name: 'percent-encoded', text: 'K=keychain:my%20svc?account=a%40b\n', pointers: [['K', 'my svc', 'a@b']] },
  { name: 'a space inside a pointer', text: 'K=keychain:my svc\n', pointers: [] },
  { name: 'a quote that closes on the next line', text: 'K="keychain:svc\nrest"\n', pointers: [] },
  { name: 'not pointers', text: 'PORT=3000\nNAME=keychainy\n', pointers: [] },
  { name: 'the last line with no newline', text: 'A=keychain:a\nK=keychain:svc', pointers: [['A', 'a'], ['K', 'svc']] },
]
