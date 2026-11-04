// `mcp_<server>_<tool>` with single underscores (Crush, Kiro): a server
// name may hold `_` itself, so `mcp_exa_evil_t` could be server `exa` with
// tool `evil_t` or server `exa_evil` with tool `t`. Integration w2's
// re-review (W2-R1) left this class of name to the agent's own server list:
// the split is taken from the MCP server names the agent is configured with,
// and a name more than one of them, or none, could start is ambiguous, so an
// allow asks. A name that can split only one way needs no list.

export type ServerNames = { names: string[]; complete: boolean; why?: string };

/** The core's `mcp__<server>__<tool>` when the split is plain; else the name as it came, marked ambiguous. */
export function splitSingleUnderscore(raw: string, names: ServerNames, agent: string): { tool: string; ambiguous?: string } {
  if (!raw.startsWith("mcp_") || raw.startsWith("mcp__")) return { tool: raw };
  const rest = raw.slice(4);
  const canonical = (server: string) => ({ tool: `mcp__${server}__${rest.slice(server.length + 1)}` });
  const splits: number[] = [];
  for (let i = 1; i < rest.length - 1; i++) if (rest[i] === "_") splits.push(i);
  if (splits.length === 1) return canonical(rest.slice(0, splits[0]));
  const fits = names.names.filter((s) => s !== "" && rest.startsWith(`${s}_`) && rest.length > s.length + 1);
  if (fits.length === 1 && names.complete) return canonical(fits[0] as string);
  const why =
    fits.length === 0
      ? `no configured ${agent} MCP server name fits`
      : fits.length > 1
        ? `more than one configured ${agent} MCP server name fits`
        : (names.why ?? `${agent}'s server list could not be read whole`);
  return { tool: raw, ambiguous: `ambiguous server name: ${why}` };
}
