# Moving plaintext keys out of a .env file

Read this before calling `migrate_env_to_keychain`.

- Inputs: `file` (default `.env`) and `names` (default: every secret-named entry with a plaintext value).
- For each entry it saves the value to the Keychain as service `PROJECTDIR/NAME`, account `$USER` (`%USERNAME%` on Windows, or the plugin's `keychainAccount` option), tagged `secret-box`. It then reads the value back, and only if it matches, rewrites that line as `NAME=keychain:PROJECTDIR/NAME?account=ACCOUNT`. Any failure leaves that line as it was.
- It asks the user to confirm before changing anything, unless a permission rule already allows or denies it.
- It rewrites the file itself, never through Write or Edit, so no copy of the old values lands in `~/.claude/file-history/`. It writes no backup file.
- It never returns a value. Its result lists the moved names and their pointers, and any entry it left unchanged with the reason.
- If an entry was left because its service already holds a different value, report that to the user. Do not overwrite the item.
- Afterwards, run the app through `keychain-env`. Do not read the `.env` file to check the values; `list_key_names` shows the pointers.
