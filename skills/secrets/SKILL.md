---
name: secrets
description: Rules for API keys, tokens, passwords, credentials and .env files when secret-box is installed. Use before any task that sets up, reads, uses, rotates or commits a key or a .env file. Invoked as /secret-box:secrets, sets up a project's keys as pointers to the macOS Keychain or Windows Credential Manager.
argument-hint: "[setup]"
---

# secret-box: use keys without their values

A key's value never enters the conversation, a file, or a command's text. Keys live in the system's vault, the macOS Keychain or Windows Credential Manager; files and commands hold names that point at them. Below, "the Keychain" means whichever of the two this machine has.

If the `use_secret` tool is not available, read `other-platforms.md` instead of the rest of this file.

## On Windows

When the `use_secret` description names Windows Credential Manager:

- Run every command that holds a placeholder, a `bin/credman get` read or `keychain-env` in the Bash tool (Git Bash), never PowerShell. secret-box refuses a PowerShell command with a placeholder in it. Reading files and running other commands in PowerShell is fine.
- Paths secret-box gives use forward slashes (`C:/…/bin/keychain-env`). Use them exactly as given.
- To add a key by hand, the user runs this in their own terminal window (not with `!`, not through a tool); it prompts with the typing hidden. `credman.ps1` sits beside the `bin/credman` path named in the `use_secret` description:
  `powershell -NoProfile -ExecutionPolicy Bypass -File "C:\…\secret-box\bin\credman.ps1" add -Service SERVICE`
- One account per service: for variants of a key, use different services (`openai/work`), not accounts.
- A value holds at most 2560 bytes.
- `windows.md` has the rest (cmdkey items, multi-line values, allow rules).

## Rules

1. Never ask the user to paste a key into the chat. Call `request_secret`; the user types the key into a masked box.
2. Never write a key's value into any file. In a `.env` file, write a pointer (below).
3. Never run `security find-generic-password` with `-w` or `-g` (on Windows, `bin/credman get`) to see or check a key. Call `use_secret`.
4. To find which keys exist, call `list_key_names`. It returns key names only and never fetches or returns any key's value.
5. To use a key in a Bash command, call `use_secret` and put exactly the form it returns into the command: a placeholder, or a `"$(/usr/bin/security … -w)"` read (`"$(C:/…/bin/credman get -s …)"` on Windows). Never retype, transform or print the value.
6. To run an app that reads `.env`, run it through `keychain-env`. Take its absolute path from the `use_secret` or `list_key_names` result: `/…/bin/keychain-env -- npm start`.
7. If secret-box refuses a command, rewrite it with literal names: no shell variables, `sudo`, `cd` before `keychain-env`, or quoted `sh -c` script around a Keychain read.

## .env pointers

A pointer stands in a `.env` file where the value would:

```
OPENAI_API_KEY=keychain:openai
STRIPE_SECRET_KEY=keychain:myapp/STRIPE_SECRET_KEY?account=work
```

- Syntax: `NAME=keychain:SERVICE` or `NAME=keychain:SERVICE?account=ACCOUNT`.
- Printable ASCII only. Percent-encode every character other than `A-Z a-z 0-9 . _ ~ : @ / + , ; = ! * -` (a space is `%20`).
- Without `?account=`, the first item with that service is used.
- `keychain-env` reads each pointer from the Keychain, sets it as `NAME`, and runs the command. secret-box hides the values in the command's output.
- `use_secret NAME` resolves the pointer `NAME` in the project's `.env` files.
- A `.env` file whose keys are all pointers can be committed. A `.env` file with any plaintext key cannot.

## Naming

- A key used by one project: service `PROJECTDIR/ENV_NAME` (`myapp/STRIPE_SECRET_KEY`).
- A key shared across projects: a short service name (`openai`).
- Variants of one key (personal, work): the same service with a different account, `keychain:openai?account=work`. The default account is the user's login name, `$USER` (`%USERNAME%` on Windows). Credential Manager holds one account per service, so on Windows use different services instead (`openai/work`).
- Variable names follow the vendor's convention (`OPENAI_API_KEY`, `GITHUB_TOKEN`).
- Every item secret-box creates carries the comment `secret-box`, so `list_key_names` finds it. If `list_key_names` does not show an existing item, either give the user this command, which re-saves it with the tag and prompts for its value:
  `security add-generic-password -U -s SERVICE -a ACCOUNT -j secret-box -w`
  (on Windows, the `credman.ps1 add` command above), or ask the user to add the item's service prefix to the plugin's `listPrefixes` option.

## Approval and permission rules

- A call that uses a placeholder is approved on the call as written, with placeholders, so no dialog shows a key: the user's permission rules first, then secret-box allows it (or, with its `ownPrompt` setting on, asks the user). In plan mode such a call is refused: put the step in the plan instead of running it. In dontAsk mode Claude Code's own answer stands. Never put a key's value into a command to get past a check. If a call is refused, ask the user what to do; don't retry it in another form.
- If secret-box says a placeholder is from before it reloaded, call `use_secret` (or `request_secret`) for that key again and use the new placeholder.
- An app run through `keychain-env` is checked like any other command, and auto mode may refuse it as credential access. Offer the user one allow rule for the runner, for the project's `.claude/settings.local.json` (machine-specific, since it holds the runner's absolute path). Give them the exact line, with the absolute path from `use_secret` or `list_key_names` filled in:
  ```json
  { "permissions": { "allow": ["Bash(/absolute/path/to/bin/keychain-env:*)"] } }
  ```
  It covers every command run through the runner, so the user isn't asked again for each one. Let the user add the rule.

## When to read the other files

- A `.env` file holds a plaintext key (`list_key_names` or a secret-box note says so): read `migrating.md`, then offer `migrate_env_to_keychain`.
- `use_secret` reports a value that can't go into a Bash command, or the key is multi-line (a PEM key, a JSON credential): read `multi-line-values.md`.

## Setting up a project (`/secret-box:secrets setup`)

When invoked as a command, or asked to set up a project's keys:

1. Find the variables the project needs: `.env.example`, the README, config code. Call `list_key_names`.
2. For each variable, choose a service and account by the naming rules. Reuse an item `list_key_names` already shows.
3. Write the pointer lines into `.env`, creating it if it does not exist. Write pointers only.
4. For each item `list_key_names` does not show, give the user this command to run in their own terminal window, one line per key, with the service and account filled in. Tell them `security` will prompt for the value, so the value never passes through the chat or the shell history:
   ```
   security add-generic-password -U -s myapp/STRIPE_SECRET_KEY -a "$USER" -j secret-box -w
   ```
   On Windows, give the `credman.ps1 add` line from "On Windows" above instead, one per key, with the full path filled in.
   Do not suggest running it at this prompt with the `!` prefix: Claude Code runs `!` commands without terminal input, so `security` saves an empty value. For one key at a time, `request_secret` with the service as its name does the same through the masked box.
5. When the user says the keys are added, call `list_key_names` and check that every item exists. Then run the app through `keychain-env`.
