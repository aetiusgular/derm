# Registry and OSV replies for the pre-install check (lane X)

Recorded 4 Nov 2026 from the workspace and trimmed to the fields the check reads:

- `npm-left-pad.json`: `GET https://registry.npmjs.org/left-pad` (200), only `name`, `dist-tags` and five `time` entries kept.
- `npm-missing.json`: `GET https://registry.npmjs.org/derm-made-up-name-x7q2z9` (404), whole body.
- `pypi-six.json`: `GET https://pypi.org/pypi/six/json` (200), `info.name`, `info.version` and the upload times of 1.16.0 and 1.17.0 kept.
- `pypi-missing.json`: `GET https://pypi.org/pypi/derm-made-up-name-x7q2z9/json` (404), whole body.
- `crates-itoa.txt`: `GET https://index.crates.io/it/oa/itoa` (200), three of its lines, fields cut to `name`, `vers`, `cksum`, `yanked` and `pubtime` where present. `index.crates.io/de/rm/derm-made-up-name-x7q2z9` gave 404.

Written by hand, because the hosts were not reachable from the workspace (`proxy.golang.org` and `api.osv.dev`, connection refused by the egress allowlist):

- `go-text-v0.20.0.info`: the shape of Go 1.24.7's `RevInfo` (`Version`, `Time`); the time is made up.
- `osv-querybatch.json`: the shape on https://google.github.io/osv.dev/post-v1-querybatch/ (one result per query, in order; `vulns` with `id` and `modified`; an empty object for no record). The ids are made up.
