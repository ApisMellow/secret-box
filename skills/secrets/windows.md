# secret-box on Windows

Read this on Windows, where secret-box keeps keys in Windows Credential Manager (the `use_secret` description says so). Everything in SKILL.md holds; these are the differences.

- **Run every command that uses a key in the Bash tool (Git Bash), never PowerShell.** A placeholder becomes the real value only in Bash. secret-box refuses a PowerShell command that holds a placeholder, since it would run with the placeholder's own text. `keychain-env` and `bin/credman` are Git Bash scripts too.
- The read-it-in-the-command form `use_secret` gives for a value with a space or a shell character is `"$(C:/…/bin/credman get -s SERVICE)"`. Put it in the command exactly as given, with forward slashes. Inside a string already in double quotes, drop the outer quotes.
- Never run `bin/credman get` (or `credman.ps1 get`) to see or check a key. Call `use_secret`. `cmdkey /list` shows names only and is fine.
- An item is a generic credential: its target name is the service, its user name is the account. The default account is the user's Windows login name (`%USERNAME%`).
- Credential Manager holds one account per service. For variants of one key (personal, work), use different services (`openai`, `openai/work`), not different accounts.
- To add a key by hand, give the user this command to run in their own terminal window. It prompts for the value with the typing hidden and tags the item for `list_key_names`:
  ```
  powershell -NoProfile -ExecutionPolicy Bypass -File "C:\…\secret-box\bin\credman.ps1" add -Service myapp/STRIPE_SECRET_KEY
  ```
  `use_secret` and `list_key_names` give the exact path. Do not suggest running it at this prompt with `!` or through a tool: it needs a terminal to prompt in, and refuses without one. `request_secret` does the same through the masked box.
- An item made with `cmdkey /generic:NAME /user:ACCOUNT /pass` works too, but has no `secret-box` tag, so `list_key_names` shows it only if the user adds its prefix to the plugin's `listPrefixes` option.
- Credential Manager holds at most 2560 bytes per value. A larger key (a long service-account JSON, a PEM key once base64-encoded) does not fit; tell the user so rather than splitting it.
- A multi-line value can't go into a command or through `keychain-env`. Have the user store it base64-encoded on one line, then decode the placeholder straight into what needs it: `printf '%s' PLACEHOLDER | base64 -d | ssh-add -`. Never let the decoded value print.
- In a `settings.local.json` allow rule for the runner, use the path `use_secret` or `list_key_names` gives: `Bash(C:/…/secret-box/bin/keychain-env:*)`.
