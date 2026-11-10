# derm cu

Computer use on macOS: an agent drives one app you granted, through a helper app that holds the Accessibility and Screen Recording permissions so no agent and no terminal does.

```
derm cu status [--json]
derm cu stop (--chat <id> | --all)
derm cu revoke --chat <id> --app <bundle id>
```

- `status` prints the helper (`missing` until it is installed), the grants per chat and any pending request, one `field: value` line each.
- `stop` ends computer use for one chat or all; `revoke` takes one app back from one chat.

An app is granted per chat, by its bundle id, after you approve it. Some are never granted: derm's own ids, MonoCode, the helper, Cua's own app, the login window and screen saver, and password managers.

**Not in this release.** The helper app is not shipped: it waits for the open approver finding S2, because an approver outside a chat could grant itself an app. `derm cu status` works and says `helper: missing`.

**Linux, GNOME under Wayland.** There a program cannot list or capture other windows; cua-driver does it through its own GNOME Shell extension, `winrects@cua`, which cua-driver 0.38.0 builds for GNOME Shell 45 to 49 and refuses on 50 and newer for now. When no copy of that extension is installed, or none lists the running GNOME Shell's version, `derm cu status` prints a `desktop:` line saying so, and an agent's request for an app is refused before any card. derm reads the version with `/usr/bin/gnome-shell --version` and the extension's `metadata.json` in `~/.local/share` (or `$XDG_DATA_HOME`), `/usr/local/share` and `/usr/share`.
