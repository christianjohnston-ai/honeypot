# Validation report — 2026-11-23

Package version **1.0.0**. Primary target Claude Code; portable Codex instruction-format package. Build environment: macOS/ARM64, Python3.10.4, Node24.5.0, Docker client27.3.1 with **no reachable Docker daemon**. Windows ACL validation environment: Windows 11, Python 3.13.14. This report distinguishes execution, simulation, documentation/source review and untested work. No customer infrastructure was provisioned, public service exposed, live token created, real malware used, external alert sent or package published.

## Executed local verification

| Check | Result and scope |
|---|---|
| Python helper suite | **22 tests passed** with `python3 -m unittest discover -s tests -v`. Disposable local files and loopback HTTP only. |
| Actual local mechanism → event → receiver | Created a harmless file, registered baseline, modified it, observed file-change event, delivered JSON over an actual loopback HTTP connection, matched event ID at receiver and recorded `destination-read`. This proves the local chain to a disposable receiver, not email/Slack/cloud delivery. |
| Secret/injection redaction | Passwords, management URLs, request/logdata and arbitrary text absent from stored/sent envelope. Invalid/scoped IPs and numeric IP input rejected. Labels reject mentions/newlines/markup. Test claims explicitly labeled untrusted. |
| Reruns / safe failure | Same input dedupes; same watch registration preserves baseline; path mismatch/symlink rejected; read-only file access produces no change alert; no registered watches fails clearly. Malformed input rolls back whole batch; unfinished final line waits. Queue capacity error visible. |
| Retry / transport behavior | Real HTTP429 and redirect rejection exercised on loopback. Simulated503/backoff, permanent401, 8-attempt exhaustion, per-outbox rate limit and Retry-After gate tested. Transport acceptance never automatically creates receipt evidence. |
| Retention / concurrency | Export preserves null receipt, new-file creation refuses overwrite, pruning does not invent delivery proof, pending records retained. Concurrent dispatcher cannot alter the locked export/delete snapshot. Independent probe confirmed this behavior. |
| Secret configuration | Private modes/symlink restrictions, missing/invalid fields, HTTPS requirement, explicit test-only loopback exception and destination-change refusal checked. Malformed URL diagnostic probes did not print embedded sentinel secret. |
| SMTP | **Mocked only**: STARTTLS called, stable Message-ID and recipient-refusal handling tested. No SMTP server or mailbox delivery was exercised. |
| OpenCanary templates | JSON/PyYAML parsing, single-HTTP/loopback/capability/mount invariants, rotation/privilege permission review and `docker compose ... config --quiet` passed. No image build/container run. |
| Application handler recipe | Extracted inline JavaScript and ran with Node against local mock queue: exact route match, generated event, no headers/query/secret propagation, 404/no-store behavior and persistence-failure signal passed. Mock queue is not evidence of durable cloud enqueue. |
| n8n transform recipe | Extracted JavaScript executed with synthetic n8n inputs in Node: allowlist, sensitive-field removal, hostile-field fallback, malformed-body rejection passed. No workflow installed or n8n runtime tested. |
| Skill/package | Local skill-creator validator passed required frontmatter/name/scaffold checks. Optional Agent Skills `compatibility` metadata was moved to prose because this local validator uses a narrower field set. JSON/YAML parsing, local reference resolution, Python compilation and archive safety/integrity checked during final assembly. |

The tests can be rerun from the skill directory: `python3 -m unittest discover -s tests -v` and, optionally with Node20+, `node tests/test_reference_snippets.mjs`. They create only disposable files/loopback listeners and do not depend on secrets, network accounts or third-party packages. `decoyctl.py` is Python standard library; PyYAML was used only by build-time package checks, not the runtime helper.

## Independent review and fixes

An independent agent evaluated the skill and code without editing implementation files. It reproduced seven issues/ambiguities that were corrected and rechecked:

1. Python's IP parser accepted attacker-supplied IPv6 scope text; now scoped/non-string sources are rejected.
2. Routine accepted-but-unconfirmed events could fill the retained outbox; explicit private export/prune now preserves evidence without inventing receipt.
3. Incoming `test` field looked authoritative; emitted field is now `test_claimed_untrusted` and cannot authorize suppression.
4. Receipt vocabulary differed across guides; now consistently `destination-read` / `user-confirmed` / unverified.
5. Provider-first routing could obscure an explicit SSH goal; the goal/protocol now takes precedence.
6. Export/prune could race a dispatcher; an immediate SQLite transaction now locks the snapshot through export/delete.
7. Moving to a new outbox could lose file-watch registration; migration/re-baseline and its observation gap are explicit, and empty watch polling fails.

A separate source review found the initial container permission plan would fail when root lacked DAC override before dropping UID. The revised log directory/file group permissions, setgid inheritance, startup umask and PID tmpfs account for startup, rotation and shutdown. These corrections were source/config validated; actual Linux execution is still required.

## Simulated usability and routing

All six required scenarios were evaluated through simulated user/agent exchanges. These are not unattended live-agent onboarding experiments and not cloud deployments. [Examples](examples.md) show the beginner, server and MCP paths in detail.

| Required scenario | Demonstrated decision | Remaining acceptance |
|---|---|---|
| Nontechnical Vercel + Supabase founder | Private hosted callback token + native email when link-use goal fits; no assumed SSH/daemon; explains database-read boundary and third-party metadata. | Real token, actual UI, private placement, trigger history and inbox receipt. |
| Render / Railway developer | Checks exact product/network/protocol; distinguishes Render HTTP/private services from Railway TCP Proxy and volume constraints; explicit SSH goal does not get silently replaced by a web token. | Chosen host/container, supported port/reachability, persistence, service event and destination receipt. |
| AWS Linux VM + Docker | Isolated OpenCanary plan, root-controlled config, loopback before approved private ingress, egress/metadata protections, sanitized Slack outbox and exact `/index.html` trigger. | Linux build/start, source-IP behavior, rotation/reboot, actual private-network path and Slack receipt. |
| Local developer / secret theft | Uses genuine issued credential mechanism for subsequent AWS use; identifies copying/read gap; file watcher only for changes. | Real token and isolated credential-use test plus delayed provider event/receipt; read-audit integration if copy detection is required. |
| AI/MCP builder | Hosted MCP token's connection vs invocation mode, clean client config, no production prompts/keys, synthetic operation and explicit receipt. | Installed client compatibility, live hosted token, connection/tool event and final recipient evidence. |
| Limited hosting permissions | Hosted token if acceptable and meaningful; if privacy/execution constraints prohibit it, states missing detector/sink and smallest infrastructure change. | Capability change before any claimed deployment; no fictitious coverage. |

Interview review confirmed one-to-three questions at a time, reuse of supplied information, “I don't know,” protected secret entry, guided/assisted choices and nonsecret resume state. The build commissioner was not asked for their personal stack.

## Documentation and source review

All required projects, Canarytokens docs, four community entries and related possible successors, Claude Code/Agent Skills/Codex packaging and relevant platform docs were inspected. Revisions, access date, license terms, maintenance and advisories appear in [research brief](research-brief.md) and linked evidence. Current platform exceptions were retained (Vercel Daemons, Netlify Server, Cloudflare TCP beta), rather than repeating outdated blanket limitations.

No upstream community/installer script was executed. OpenCanary source and locked Twisted startup behavior were inspected to validate command/config assumptions. Native integration schemas were source-reviewed. Public advisory results are not a dependency/security audit; no vulnerability scanner/SBOM validation was executed.

## Readiness and remaining work

| Route | Build readiness | What is unverified / unsupported |
|---|---|---|
| Hosted HTTP/DNS/document/AWS Canarytokens | Guided instructions ready for runtime use; current docs/source cross-checked | No created token, actual viewer callback, AWS API use or received provider email. Document reader/egress differences and AWS delay/gaps must be tested. No brittle automated free-service creation API shipped. |
| Hosted MCP token | Guided instructions ready; current official mechanism and client-isolation options reviewed | No live MCP handshake/tool invocation or client-version compatibility test. Generated JSON is not promised to import unchanged into every agent. |
| OpenCanary HTTP on isolated Linux | Reviewed pinned-source recipe and validated Compose/config | Container startup, filesystem permissions under real Linux, networking, reboot/recovery, native events and external delivery still require disposable runtime test. No claim of production readiness. |
| Local file watcher + generic HTTP | Local code and actual disposable receiver chain tested; Windows DACL inspection for state directory, database and alert configuration tested | Linux scheduling and macOS launchd unattended setup not executed; Windows scheduler and lifecycle behavior remain unverified. No reads/copies/ransomware identification. |
| SMTP / Slack / Discord outputs | Implemented; SMTP mocked, HTTP machinery locally exercised, destination schemas reviewed | No actual provider delivery, rate-limit policy, bot/workspace approval or recipient receipt tested. |
| App HTTP decoy | Original handler pattern locally tested | Durable queue and consumer implementation, framework integration, auth preservation and provider deployment are environment-specific remaining work. |
| n8n adapter | Transformation locally tested and workflow recipe documented | No live workflow, durable queue, retry/error path or final channel delivery. Native token transport has no reliable upstream retry; downstream durability cannot repair lost intake. |
| Cowrie / T-Pot / self-hosted Canarytokens / Beelzebub | Research-backed advanced alternatives | No turnkey deployment automation or complete bespoke alert bridge shipped; extra integration, licensing/privacy review and live acceptance required. |

The package does not claim guaranteed detection, zero false positives, universal platform support or exactly-once messages. The outbox is intentionally small and needs supervision/retention; it is not a high-volume public sensor pipeline. A quiet installation is not health evidence.

Before calling any real deployment complete, run the selected mechanism's harmless trigger, correlate its source event, and verify the matching notification at the user's destination. If the recipient cannot be checked, record **configured, delivery unverified**. This live acceptance is necessarily performed when a future user chooses and authorizes their environment, not fabricated in this build.
