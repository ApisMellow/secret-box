# secret-box off macOS and Windows

Read this when the `use_secret` tool is not available: on Linux and other systems that are neither macOS nor Windows.

- The vault features do not exist here: no `use_secret`, `list_key_names`, `migrate_env_to_keychain`, `keychain-env` or `.env` pointers. Do not write `keychain:` pointers.
- `request_secret` (the masked box) saves the key to the project's `.env` file and returns a placeholder. Call it instead of asking the user to paste a key into the chat.
- Put the placeholder into commands; it becomes the real value when the command runs. Never write a value into a file yourself.
- secret-box hides keys in every tool result and refuses to stage or commit a `.env` file.
- If the backend option is set to `keychain`, the box refuses to save; ask the user to set it to `auto` or `dotenv`.
