# AI and MCP decoys

Reviewed **2026-11-23**. Primary route: hosted **MCP Configuration Canarytoken** for detecting use of a planted MCP configuration. Advanced alternative: a single-service Beelzebub MCP bait tool for controlled agent testing. Neither is a general prompt-injection detector or a substitute for tool permissions.

## First determine what should be observed

Ask: “Are you worried someone will find and use a private tool configuration, or that your own agent might call an inappropriate tool after reading untrusted content?” Reuse known context. “I don't know” → explain the difference with one example, then recommend a configuration token if artifact theft/use is their goal.

- **Configuration use:** a planted JSON file points to a remote decoy. Hosted receiver can alert on MCP connection or tool call; merely opening/copying the file does not fire.
- **Unexpected tool invocation:** add a harmless, clearly designated bait tool to an isolated agent's available toolset, with approval and logging. An unexpected call is evidence of that call. It may arise from an authorized test, agent error, or injected instructions; investigate surrounding context before attributing cause.
- **Reading private prompts, secret exfiltration through other channels, or malicious calls to real tools:** neither decoy guarantees this coverage. Add audit/instrumentation at the actual tool/secret boundary; do not make production tools dangerous just to create a tripwire.

## Hosted MCP Configuration token: supported guided route

Load [route-canarytokens.md](route-canarytokens.md) for private email, storage and receipt steps. This route needs no new server, local listener, root or production cloud permissions. Allow approximately 15–30 minutes plus client troubleshooting (estimate, not a measured SLA). Thinkst's endpoint receives connection/tool event metadata; do not send real project prompts, secrets, customer content or production credentials to it.

| Step / purpose | Action | Expected / recovery |
|---|---|---|
| Preflight | Choose a private decoy-artifact location and a clean test client/workspace with no production MCP connections. Record user authorization, client/version, internet access and delivery channel. Check existing token profile first. | Existing production settings remain intact. If client isolation or data-handling is unacceptable, stop this route and explain missing capability. |
| Create | In the observed [Canarytokens UI](https://canarytokens.org/) choose **MCP configuration**. The reviewed form labels are **Alert on**, **Connection**, **MCP Tool Call**. Choose connection for first-use detection; tool call only if discovery/initialization should not alert. Configure private email and memo, create once. | Downloadable JSON with a server URL and a decoy bearer capability. If absent, verify current service availability; do not invent an MCP endpoint. |
| Store / place | Save management access separately in protected storage. Save generated JSON as an inert artifact in the approved private location. Do not overwrite or merge over an active `.mcp.json`, user settings, or another agent's connections. Record only alias, trigger mode and placement in the nonsecret profile. | File exists. Reading it is deliberately **not** an acceptance trigger. Do not claim a read proves use. |
| Controlled client test | Record UTC window and local test ID. Use a **separate** temporary test client and load the generated JSON from a protected local file. Confirm the client lists only the intended decoy server before issuing any tool call. | For Connection mode, establish an MCP session; find matching event. For Tool Call mode, initialize/list tools, inspect the actual advertised schema, and invoke one harmless synthetic operation with synthetic arguments. Do not guess a tool name or send real AWS keys. |
| Confirm delivery | Find the matching provider history event and recipient alert; correlate mode, alias, time and source. Record `destination-read` or `user-confirmed`, else `configured, delivery unverified`. | Initialization success or tool result alone cannot pass recipient acceptance. Check selected mode, URL/auth entry, client HTTP transport, egress, enabled email/webhook and spam filtering. |
| Clean test / maintain | Close the test client and remove only its temporary configuration. Keep the planted inert artifact. Document monthly self-test, expected authorized scanners and path to management secret. | Normal app agents do not constantly connect to the bait by accident. For an active bait-tool experiment, record the narrower test scope and legitimate trigger baseline instead. |

Source: [MCP token mechanism](https://docs.canarytokens.org/guide/mcp-token), [current form](https://github.com/thinkst/canarytokens/blob/61f3e0c7790f08f1be09a947cb0d68e6152cde6a/frontend_vue/src/components/tokens/mcp/GenerateTokenForm.vue), [config construction](https://github.com/thinkst/canarytokens/blob/61f3e0c7790f08f1be09a947cb0d68e6152cde6a/canarytokens/mcp.py). The generated file currently uses `mcpServers`, `type: http`, `url` and `headers.Authorization`; this format is not automatically accepted by every agent.

For a **terminal Claude Code** lab, current [official MCP documentation](https://code.claude.com/docs/en/mcp) supports a config file with `--mcp-config` and `--strict-mcp-config`. Check `claude --help` on the installed version first. From an empty disposable directory, use:

```sh
claude --strict-mcp-config --mcp-config '/absolute/private/path/to/generated-mcp.json'
```

The command contains only a path, no credential. Inspect `/mcp` and any managed/connector configuration before proceeding; do not assume strict MCP config disables every other non-MCP capability or desktop-supplied connector. If only a desktop client is available, follow its current documented isolated profile/import mechanism. Do not use `mcp add-json` with a secret inline in shell history. Codex users can run the skill and follow this same guided test, but generated JSON is not promised to be a native Codex configuration; inspect that client's current MCP documentation before translating fields locally.

Provider documentation gives possible decoy filenames; those suggestions do not establish each client's actual config discovery path. Deliberately placing an inert bait file avoids accidental live registration. A browser GET of `/mcp` is not a valid substitute for a handshake/tool call. MCP Streamable HTTP has its own session and content-negotiation rules ([protocol](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)).

To move/remove this token use the verified identity and replacement/delete procedure in [route-canarytokens.md](route-canarytokens.md). Remove the exact registered test server first if one was added, preserving all unrelated entries and original settings backups.

## Advanced alternative: Beelzebub single MCP service

Use only if the user needs a self-operated bait tool and can maintain an isolated persistent runtime **and** its alert adapter. This package reviewed the implementation but did not deploy it or integrate native logs with its helper. Until the missing bridge and real receipt test are completed, it is **not an accepted deployment route**. Hosted MCP token is the simpler recommendation when its coverage fits.

Pinned source reviewed: `3f20be5355c7d6f144329e39c478cdd7ff98184c`; latest release at review `v3.10.0`. Review an update before changing the pin. Upstream source, Go 1.26.0 toolchain per that revision's `go.mod`, Git and build dependencies are needed for the local build. Docker/Helm are alternatives. There is no verified total resource minimum; size and monitor actual memory/log usage. Do not confuse the CLI's Go soft memory target with a hard limit.

Before setup inspect [installer](https://github.com/beelzebub-labs/beelzebub/blob/3f20be5355c7d6f144329e39c478cdd7ff98184c/install.sh), Dockerfile, dependencies/plugins and chosen configuration. The stock installer/Compose can expose many privileged ports and Linux host networking; do not run it wholesale for a single MCP test. Use an isolated host/container without production network access or metadata credentials, unprivileged loopback listener, restrictive egress and private persistent logs. LLM/Cloud/RabbitMQ are optional; a static MCP tool needs none.

Prepare a new deployment-owned directory and review, without overwriting existing files, this original minimal **service** config:

```yaml
apiVersion: "v1"
protocol: "mcp"
address: "127.0.0.1:8000"
description: "Controlled decoy tool"
tools:
  - name: "decoy-record"
    description: "Record a synthetic security-test action. No real operation is performed."
    params:
      - name: "test_marker"
        description: "Nonsecret controlled test identifier."
    handler: '{"result":"synthetic-only"}'
```

Use a separate core config with logging to a private persistent path, Cloud/RabbitMQ/Prometheus disabled, no plugins and no model credentials. Resolve port conflicts before starting. Source CLI exposes `--conf-core` and `--conf-services`; after an independently reviewed build, the commands are:

```sh
./beelzebub --conf-core /absolute/deployment/core.yaml --conf-services /absolute/deployment/services validate
./beelzebub --conf-core /absolute/deployment/core.yaml --conf-services /absolute/deployment/services run
```

Expected: validation succeeds, one MCP listener at `http://127.0.0.1:8000/mcp`. If validation fails, fix the indicated schema field without enabling unrelated services. If listener fails, inspect private startup logs and occupied port. An initialized listener is only acceptance outcome 1. Don't expose it publicly without a concrete ingress/auth/TLS/egress review and existing authorization or required approval.

A controlled client calls `decoy-record` with one synthetic `test_marker`. The inspected [MCP handler](https://github.com/beelzebub-labs/beelzebub/blob/3f20be5355c7d6f144329e39c478cdd7ff98184c/internal/protocols/strategies/MCP/mcp.go) emits an event with UUID `ID`, `Protocol=MCP`, `Msg=New MCP tool invocation`, source and combined tool/arguments, then returns synthetic text. Handshake/listing alone does not execute that handler. Keep raw arguments out of notifications and out of any AI summarizer's instructions.

Native outputs are local JSON logging, optional RabbitMQ `event` queue and optional Beelzebub Platform reporting ([observability](https://docs.beelzebub.ai/operations/observability/)). Implement/validate a small adapter to normalize only timestamp, UUID, static alias/environment, fixed invocation description and valid source address into the chosen email/webhook mechanism. Do not pass `Command`, `CommandOutput`, headers, bodies, credentials or environment fields. Configure durable buffering, bounded retries, health and secret handling; inspect actual emitted schema before wiring it. This adapter is **remaining environment-specific work**, not a built-in promise of `decoyctl.py`.

Acceptance requires the invocation event **and** matching destination receipt. Stop on missing logs or receipt; mark configured/unverified and troubleshoot. Shut down with Ctrl-C/service stop, confirm listener removal, remove exact test client registration, archive necessary sanitized evidence, and delete only deployment-owned files. For updates back up config/state, validate at the new pin, run the same synthetic call and recipient test, then switch; restore prior executable/config if the test fails.
