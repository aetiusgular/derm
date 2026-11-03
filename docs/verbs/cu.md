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
