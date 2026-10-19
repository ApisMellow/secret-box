# secret-box

A Claude Code mod that lets Claude use a secret without seeing it. Keys are saved to the macOS Keychain or Windows Credential Manager (or `.env`), Claude works with placeholders, and any key a tool prints comes back hidden.

## Install

```
claude plugin marketplace add ApisMellow/secret-box
claude plugin install secret-box@secret-box
```

## Credits

secret-box began as a mod in [claude-code-mods](https://github.com/ray-amjad/claude-code-mods) by Ray Amjad (MIT). The detector, the masked box and the original design are his. This project starts from that code and goes its own way, beginning with the macOS Keychain and Windows Credential Manager backends.

## License

MIT. See [LICENSE](LICENSE): copyright Ray Amjad and David Whitlock.

## TODO

Full documentation is being written.
