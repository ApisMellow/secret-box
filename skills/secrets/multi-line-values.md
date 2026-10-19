# Multi-line values

Read this when `use_secret` reports a value that can't go into a Bash command, or the key is multi-line (a PEM private key, a JSON credential).

- Such a value can't go into a Bash command, and `keychain-env` refuses it: `security -w` prints it as hex.
- Do not write it to a file with Write or Edit: Claude Code copies every file it edits into `~/.claude/file-history/`.
- Have the user store it base64-encoded. Give the user this command; it reads the file, so the value never passes through the chat:
  ```
  security add-generic-password -U -s SERVICE -a "$USER" -j secret-box -w "$(base64 -i path/to/key.pem)"
  ```
- Then call `use_secret SERVICE` and decode the placeholder straight into what needs it, never to the terminal:
  `printf '%s' PLACEHOLDER | base64 -d | ssh-add -`
- A `.env` pointer to that item gives the app the base64 text. The app decodes it.
- Only the base64 text is hidden in output. Never let the decoded value print.
- On Windows the `security` commands above do not exist. The user saves the base64 text with the `credman.ps1 add` command (see `windows.md`), pasting it at the hidden prompt; a value holds at most 2560 bytes, so a large PEM key may not fit. Decoding works the same in the Bash tool.
