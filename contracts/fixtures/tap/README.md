# Tap fixtures (the wave 5 base, 4 Nov 2026)

Hand-written, not recorded: no tap exists yet. Lane S replaces or adds recorded cases (a streamed Anthropic response, the Responses API over WebSocket, Chat Completions, Gemini, a stream cut mid-call for case 115) and may only add files in this folder.

- `anthropic.response.json` and `anthropic.next-request.json`: a non-streamed Messages response with one `tool_use` block, then the next request carrying its `tool_result`. Shapes from https://platform.claude.com/docs/en/agents-and-tools/tool-use/overview, read 4 Nov 2026 (V); the values are made up.
- `openai-responses.response.json` and `openai-responses.next-request.json`: a Responses API `function_call` item and the `function_call_output` that answers it. Shapes from https://developers.openai.com/api/docs/guides/function-calling, read 4 Nov 2026 (V); the values are made up.
- `*.expected.json`: the `tap.call` record each pair gives (`events.md` section 5, `wave5-records.schema.json`).
- `records.json`: one example of each other wave 5 record kind.

The base's reading of the hashes, for lane S to keep or change through integration:

- `argsSha256` is the sha256 of the arguments as canonical JSON (object keys sorted, no whitespace), so a streamed and a whole response give the same hash. The Responses API's `arguments` string is parsed first. Arguments that do not parse (a cut stream) hash as their raw text, with `incomplete: true`.
- `resultSha256` is the sha256 of the result's text when the harness sends a string, else of its canonical JSON.
- `paths` holds the string values of arguments named `path`, `file_path`, `filePath` or `paths` (an inference; lane S decides whether command text is read for paths too).
