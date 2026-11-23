# Research brief and routing rationale

Research snapshot: **2026-11-23**. The result is an installable Claude Code/Codex Agent Skill, not a universal honeypot installer. The portable entrypoint interviews the future user, chooses a feasible mechanism, guides or assists setup, and requires separate detector, trigger and recipient evidence. The build did not provision customer infrastructure or publish anything.

## Project comparison

Each row summarizes documented/source-inspected behavior. Effort/cost judgments are estimates; executed behavior is isolated in [validation](validation-report.md). Details, exact revisions, license obligations, advisories and source links are in [server evidence](server-research.md), [token/AI evidence](token-ai-research.md), and [community audit](community-audit.md).

| Candidate / category | Exact useful trigger and placement | Access / operation | Alerts, data and burden | Decision |
|---|---|---|---|---|
| [Canarytokens hosted](https://docs.canarytokens.org/) — honeytoken | Request unique URL, resolve unique DNS name, supported document callback, use issued AWS keys, or selected MCP connect/tool call. Plant where unwanted access would lead to **that action**. | Browser + placement access; no local daemon/ports/root. Hosted service documented free; verify terms during setup. | Native private email/webhook; provider sees token/destination/event metadata. Native notifications may include management URLs. Low upkeep but callbacks/notifications need periodic tests. | **Primary no-server route**. Copying/reading bytes does not universally fire. AWS is credential use, not theft detection at copy time. |
| [Canarytokens self-hosted](https://github.com/thinkst/canarytokens) — callback infrastructure | Same supported mechanisms only when each backend is configured. | Linux Docker/Compose, authoritative DNS/domain, exposed required listeners, Redis and durable storage; no universal resource minimum verified. | Operator owns receiver plus mail/webhook dependencies. Hosted AWS/MCP infrastructure is not automatically included. VM/domain/mail/ops costs. | Advanced privacy/control option; not turnkey here. |
| [OpenCanary](https://github.com/thinkst/opencanary) — server honeypot | Selected protocol activity on this sensor; packaged HTTP GET `/index.html` generates event3000. Place on the relevant reachable owned segment. | Persistent daemon; Linux Docker VM for shipped recipe; selected TCP port, root-controlled config, privilege drop, private persistent logs. | Native SMTP/webhooks/log outputs; shipped adapter sanitizes/retries. Operator + configured destination see data. Low resource compared with multi-sensor stacks, ongoing VM/patch costs. | **Primary isolated VM route**, single service first. Not app/database monitoring or evidence that a public scan breached an app. |
| [Cowrie](https://github.com/cowrie/cowrie) — interactive SSH/Telnet honeypot | Session/auth/commands directed at Cowrie, not another SSH service. | Dedicated non-root runtime, default2222/2223, persistent logs/keys/tty/downloads; optional proxy/LLM adds containment needs. | Native output plugins include chat/SIEM; plugin-specific event coverage. Host/storage and optional model costs. | Specialist alternative when shell/session telemetry is necessary. Not packaged deployment. |
| [T-Pot](https://github.com/telekom-security/tpotce) — multi-sensor platform | Enabled sensors' interactions; extensive analysis infrastructure. | Dedicated admin-managed Linux; current Hive16GB/256GB, Sensor8GB/128GB; many ports, changed management SSH port. | Dashboards are not recipient alerts; connectors need validation/licensing. Default community data submission requires explicit privacy review. Larger host/storage/ops burden. | Advanced research/security-team option, excessive for most founders. |
| [Beelzebub](https://github.com/beelzebub-labs/beelzebub) — service/AI/MCP decoy | Configured service interaction; inspected MCP handler logs tool invocation. Mere listing is not that event. | Persistent Go/container/Helm runtime; service-specific port; static MCP needs no model. | Local JSON/RabbitMQ/optional Cloud; email/chat bridge still required. Optional LLM receives inputs and may incur costs. | Advanced self-operated AI alternative. Hosted MCP token is simpler for config-use goals. |
| Original local watcher — monitored decoy file | File metadata change/deletion/replacement at a chosen local path. | Python3.10+, private state, persistent scheduler, outbound alert transport; no listening port/root needed. | Shipped SMTP/webhook/Slack/Discord outbox; local source content never read. Existing-machine cost plus destination fees. | **Supported narrow local route**. Does not detect reads/copies or identify ransomware. |
| Original app-decoy recipe — application decoy | Request actually reaches an exact handler and event is persisted. | Existing supported HTTP runtime + durable queue/consumer; no assumption of root/arbitrary ports. | Reuse app's notification sink with redaction/retries. Invocation/log/queue costs and public-scan noise. | **Integration-required route** for web probing; project implementation and hosted tests remain mandatory. |

## Platform routing matrix

Verify the exact product/plan at runtime. Current capabilities are documented with primary links in [platforms.md](platforms.md); service names alone do not determine process/network/storage support.

| Environment | Practical default | Constraints that change the recommendation |
|---|---|---|
| Vercel + Supabase / Netlify + Firebase | Hosted token + private email for artifact-use goal; HTTP decoy through existing functions for probing | Standard functions have bounded lifetimes; local disk not durable. New Vercel Daemons beta / Netlify Server early-access capabilities do not make OpenCanary a drop-in app function. Do not weaken auth/RLS. |
| Cloudflare | Hosted token or Worker HTTP handler + durable Queue | Standard fetch handler differs from long-lived Linux daemon; inbound TCP beta/Spectrum is a separate product/engineering decision, not generic SSH hosting. |
| Render | Existing web app route; private service only when its actual protocol/network placement fits | Public web ingress is HTTP, free services can sleep; private services/disks have distinct plan/access rules. |
| Railway | Existing app route or explicitly scoped TCP sensor when proxy constraints fit | TCP Proxy supports assigned TCP host/port; not generic UDP/public multiport assumptions. Verify persistent volume/network behavior. |
| AWS / Azure / GCP / VPS Linux VM | Isolated OpenCanary sensor, restricted ingress/egress, private alert path | Dedicated boundary, cloud role/metadata controls, billable VM/disk/IP, protected management and logs required. |
| Local machine | Issued credential token for **use** of a copied key; watcher for file **changes** | Sleep/offline time and missing scheduler create gaps. No blanket file-read detection. |
| AI/MCP | Hosted MCP configuration token, selected connect vs tool-call mode | Client format/transport must match; use clean test profile and synthetic arguments. Beelzebub needs runtime plus alert bridge. |
| Shared/limited hosting | Hosted callback token if placement and outbound use fit | If third-party telemetry is forbidden and no local detector/sink can execute, there is no honest no-infrastructure solution. Smallest change: approved internal log sink/monitor or isolated host. |

## Why these choices

Hosted tokens satisfy a meaningful subset of goals without requiring founders to operate a server. OpenCanary provides a smaller isolated service surface when a network sensor is actually necessary. The custom helper solves the concrete gaps in safe notification formatting, durable retries, deduplication and receipt bookkeeping; it does not duplicate a honeypot engine or pretend to offer a cloud service. Full interactive stacks and LLM deception remain optional because they add containment, cost and alert integration work.

The community repository was treated as untrusted research input. All four requested paths still exist; related entries were inspected for successors, but none was declared a replacement. Findings include deprecated Slack API token creation, stale public API routes/response assumptions, incorrect OpenCanary codes, files falsely described as read monitors, uninstrumented fake credentials, raw credential logging and incomplete notification/containment implementations. The package copies none of those scripts. See the [entry-by-entry audit](community-audit.md).

## Revision and maintenance snapshot

| Source | Observed revision / release | Why it matters |
|---|---|---|
| OpenCanary | HEAD `ece4a855587de1127d76b0d6188916908361b7cd`; deployment v0.9.10 at `fb12e4fefbdb1b9acd1e5561a2614f827ab639ff` | Current security fixes; root-controlled configuration and precise event mappings. |
| Cowrie | `183a3b1bc361bb941e1d54874922399baac42af0`; latest v3.1.8 | Active releases; prior outbound-request abuse advisory still informs egress controls. |
| T-Pot | `9c3ae4aea976a63ef1f655598a4383c0cb7e140c`; latest published release24.04.1 | Ongoing HEAD/image updates despite older release tag; inspect image digests and telemetry defaults. |
| Canarytokens | `61f3e0c7790f08f1be09a947cb0d68e6152cde6a`; no release/tag entries returned | Current types/deprecations, notification weaknesses and special license terms. |
| Canarytokens Docker | `6db74151995cc52cc919b7c27480c4aa95de8afa` | Separate deployment configuration; self-hosted feature parity cannot be presumed. |
| Beelzebub | `3f20be5355c7d6f144329e39c478cdd7ff98184c`; latest v3.10.0 | Current MCP implementation, source/docs toolchain drift and optional data processors. |
| Community skills | `54a798831d2266a3ca61ce68a7acb80b81160d57`; latest v1.3.0 | Audited instructions are evidence, not automatic execution authority. |

License summaries and advisory URLs are in the detailed evidence; absence of public advisories is not a clean security scan. No dependency vulnerability scan or hosted-service security audit is claimed. Source/readme popularity was not used as reliability evidence.

Packaging was checked against [Claude Code skills](https://code.claude.com/docs/en/skills), [Agent Skills specification](https://agentskills.io/specification), and [current Codex skill guide](https://learn.chatgpt.com/docs/build-skills). One shared folder works as the instruction-format package for both; tool permissions, live client discovery and every provider remain environment-specific. See [installation](../README.md) and the [dated validation report](validation-report.md).
