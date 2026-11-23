# Independent validation of honeypot-setup

Reviewed 2026-11-23 by a separate agent. This is an independent review, not a deployment certificate. The reviewed working tree was still being authored; findings below identify the inspected behavior and can be amended after fixes. No cloud resources, hosted tokens, live email/chat messages, or public listeners were created.

**Final recheck status:** **F1–F7 are resolved within this review's scope.** The final **22** bundled tests passed without the earlier socket warning. Additional independent probes confirmed the corrected export/prune transaction and failure on an empty watch database. The six scenario paths were rechecked against the newly added AI, local-file, alerts, and operations references. Final package assembly/link validation and real deployment acceptance remain separate work.

## Scope and evidence

Read the available `SKILL.md`, README, platform matrix, application/OpenCanary/Canarytokens routes, token/AI and server research, templates, Python helper, and bundled tests. The six conversations below are simulated policy/selection walkthroughs, not interactions with actual customers or services. Route references added after the first pass need a final link/completeness check by the package author.

Executed:

```sh
python3 -m unittest discover -s honeypot-setup-skill/honeypot-setup/tests -v
```

Result at initial review: **19 tests passed** in 1.241 seconds. Tests exercised disposable files, mocked transports, and HTTP bound to `127.0.0.1` only. A non-fatal `ResourceWarning` for a closed/unclosed socket appeared during the SMTP-mock test; the preceding HTTP-error response cleanup merits inspection. No live SMTP, Slack, Discord, OpenCanary daemon, Docker image, or cloud behavior was established by this run.

Additional independent Python probes used temporary directories and a no-op sender. They reproduced the scope-ID and retention findings below. Setting `MAX_EVENTS=2` in the probe made the production 10,000-record limit reachable without generating thousands of records. No production configuration was touched.

On recheck, independent normalization probes rejected scoped IPv6 and non-string inputs while preserving normal IPv4/IPv6. Subprocess CLI tests of malformed destination ports and control characters returned fixed safe error messages without the injected private URL material. Updated HTTP-error cleanup eliminated the warning in the 21-test and final 22-test runs. The new `ConfigError` distinction avoids displaying arbitrary library-generated `ValueError` text as a safe diagnostic. Final bundled run: **22 passed in 1.849 seconds**.

## Concrete findings

### F1 — High: IPv6 scope IDs bypass the sanitized alert contract

At initial review, `scripts/decoyctl.py:112`–116 emitted `str(ipaddress.ip_address(source))`. Python accepts arbitrary strings after an IPv6 percent scope delimiter, including line breaks. The following input survived normalization verbatim:

```text
source_ip = "fe80::1%privatevalue\n@everyone"
normalized source_ip = "fe80::1%privatevalue\n@everyone"
```

This allows text/secrets from a generic input field to leave the supposedly IP-only allowlist, and can place attacker-controlled lines in email/webhook content. Discord disables mentions and Slack uses a plain-text block, which mitigate some presentation effects but do not satisfy the no-raw-text/no-secret-forwarding promise. OpenCanary normally obtains socket source addresses itself; exploitability is more direct for arbitrary generic producers than ordinary OpenCanary connections.

Recommendation: reject scoped IP input or explicitly emit only the address bytes without the scope; add regression coverage for `%`, newline, long scope text, and normal IPv4/IPv6 addresses. This issue was reported to the parent immediately.

**Resolved/retested:** updated normalization rejects any `%` scope and non-string input, emitting `unavailable`. Independent probes confirmed newline-bearing scope data no longer appears anywhere in the serialized envelope; normal IPv4/IPv6 still work.

### F2 — Medium: normal successful alerts cannot age out without per-event receipt confirmation

At initial review, `enqueue()` counted every row toward `MAX_EVENTS=10000`, while `prune` deleted only old `accepted` records with non-null `received`. Runtime receipt confirmation is correctly separate from transport acceptance, but ordinary subsequent notifications will normally remain unconfirmed individually. Once enough events accumulate, successful delivery still leads to permanent ingestion refusal until records are individually confirmed or the database is manipulated outside the supported CLI.

Independent reproduction with a temporary outbox and no-op sender:

```text
before prune: {"accepted": 2}
all created timestamps: 31 days old
prune output: {"pruned": 0, ...}
new enqueue: Outbox full; inspect status, export evidence and prune acknowledged records
```

Recommendation: add a deliberate retention/export mechanism for transport-accepted records that does not falsely claim recipient receipt; preserve a sufficient deduplication window. Keep pending/failed records protected. If retaining the current policy, make the required per-event acknowledgement workflow and finite capacity explicit and operationally practical. An independent queue-capacity alarm helps but does not replace a supported recovery path. This issue was reported early.

**Resolved/retested:** `prune --include-unconfirmed --export` now requires a new evidence file in a private directory, preserves null receipt status, refuses overwriting, and removes only eligible accepted events. The new path resolves the original capacity dead end. Its initially introduced concurrent-dispatch export/delete race was separately found and corrected as F6 below.

### F3 — Medium: untrusted generic `test` input becomes a trusted-looking test label

`normalize()` initially copied `raw.get("test") is True` into the output. An independent probe showed an arbitrary generic event becoming `"test": true`. No bundled suppression exists, so this is not currently a demonstrated dropped-alert bug. It nevertheless conflicts with the skill's good rule that attacker-supplied flags are not evidence of an authorized test and could mislead a downstream consumer or reader.

Recommendation: only mark tests created by the CLI's own `delivery-test` command or by a trusted out-of-band correlation source. Otherwise omit the field, make it false, or clearly label it an untrusted assertion. Keep actual test windows/IDs in protected state.

**Resolved/retested:** the output is now `test_claimed_untrusted`, and the alerts contract explicitly calls it untrusted. Independent normalization confirmed there is no trusted-looking `test` field. This does not authorize suppression.

### F4 — Low: receipt vocabulary differs between route and helper

The initially reviewed Canarytokens route used `tool-confirmed`, while the shared skill/helper use `destination-read` and `user-confirmed`. A human can infer the intent, but a consistent state vocabulary makes resumed workflows and machine-readable evidence less error prone. Use the shared vocabulary and separately describe which tool read the message.

**Resolved/rechecked:** the updated Canarytokens and MCP routes no longer use `tool-confirmed`; they use the shared `destination-read` vocabulary.

### F5 — Selection emphasis deserves a clear SSH exception

The selection table's Render/Railway row says “Hosted token first; app decoy for HTTP goals.” The platform matrix correctly distinguishes Render public HTTP ingress, Render private services, and Railway TCP Proxy. However, an agent that follows the short table too literally could substitute a callback token when the user explicitly wants SSH connection/authentication telemetry. A callback token does not meet that goal.

Recommendation: make the protocol requirement controlling: for explicit SSH, use the platform-specific capability/isolation checks and explain any missing infrastructure. A hosted token is an alternative only after the user accepts its different coverage. The simulations below make this distinction.

**Resolved/rechecked:** the selection table now explicitly says to match the goal first and that SSH requires a reachable TCP sensor. It no longer establishes hosted tokens as the default substitute for an SSH requirement.

### F6 — Medium: export/prune can delete a record absent from its evidence export

The first implementation of unconfirmed-event export entered `with conn`, selected eligible rows, wrote/fsynced the export, then deleted rows by the same predicate. In Python SQLite, the SELECT does not start a write transaction. Another dispatcher can change an old pending event to accepted during export; the final DELETE then matches it even though it was absent from the SELECT/export.

Independent disposable-file reproduction started with one old accepted event and one old pending event. A hook at the export's `fsync` used a second SQLite connection to mark the pending event accepted, simulating concurrent delivery. Result: **2 records pruned, 1 exported, 0 remaining**. The newly accepted event lost its promised retained evidence.

Recommendation: acquire an explicit `BEGIN IMMEDIATE` before selecting/exporting/deleting and roll back on export failure, or delete precisely the exported event IDs while preserving appropriate status constraints. Add a concurrent-state-change regression. This was reported immediately on recheck.

**Resolved/retested:** prune now issues `BEGIN IMMEDIATE` before its SELECT. A new bundled concurrent-connection regression passes. Repeating the independent `fsync`-time probe showed the competing update blocked; exactly one eligible event was exported and pruned, the pending event remained, and exported receipt status stayed null. Export errors remain inside the transaction rollback context.

### F7 — Low: webhook cutover needs a file-watch-specific step

The alerts/operations docs correctly require a new outbox when webhook identity changes. File registrations and baselines also live in that same outbox database, but the common cutover instructions only say to switch ingestion. Merely changing the file watch scheduler's `--state` to the new empty outbox makes `watch-poll` return zero while monitoring no files.

Recommendation: explicitly carry over or deliberately re-register verified watch identities, reconcile the last pre-cutover snapshot, document any observation gap, and perform a fresh file-change plus destination-receipt acceptance check. Do not imply that a new outbox inherits registered watches.

**Resolved/rechecked:** cutover instructions now require verified registration/baseline migration or explicit re-registration with a recorded blind interval, followed by a fresh controlled file test. An empty `watch-poll` now raises `No watches registered; verify the state directory and resource identity`; an independent disposable-state probe confirmed this behavior.

## Six simulated conversations

These are example next turns and expected decision boundaries. Quoted user follow-ups are synthetic. They are not evidence that a token was created, an alert was sent, or receipt was verified.

### 1. Nontechnical Vercel + Supabase founder; private-access email; no server

**Input:** “My app is on Vercel and Supabase. I don't know servers. I want an email if somebody gets into private stuff, without running another server.”

**Appropriate next turn:** “Which private item should act as bait: an unused internal document, a copied cloud credential, or a specific private page? A decoy only notices its own interaction. May the hosted detector receive the trigger's network metadata?”

**Synthetic follow-up:** “An unused note in our private repo is fine. The service can receive metadata. Email only to me.”

**Decision:** hosted Web bug/HTTP token in that private note, owner-only email, guided mode. Explain that requesting the planted URL is the trigger; opening the repo, copying the note, reading Supabase rows, or viewing unrelated private pages does not necessarily trigger it. A compatible generated document callback is a separate mechanism, not an assumed feature of arbitrary text. Do not ask again which hosting provider they use or introduce Docker.

**Setup progression:** establish exact private placement and who normally reads/previews it; inspect the current token form; create once; save the management capability privately; place only the artifact; execute one recorded request; match provider history and private email. Do not paste the URL, recipient address, or management URL into reusable state.

**Acceptance:** resource/placement exists; matching provider history event; owner confirms the specific alias/time (or authorized inbox tool reads it). Without the last gate, status remains configured, delivery unverified. If the user instead requires every private database read, this route is not sufficient; investigate the application's authorized audit capability before claiming a solution.

**Assessment:** good fit once “private access” is narrowed. The skill is appropriately explicit about fake rows and RLS. Its universal opening question should be interpreted as conditional so known stack information is reused.

### 2. Render/Railway developer; SSH honeypot

**Input:** “I use Render/Railway and want an SSH honeypot.”

**Appropriate next turn:** “Which exact service is the target, and should it be reachable publicly or only over its private network? Do you need connection/login-attempt alerts, or an interactive fake shell?”

**Synthetic follow-up:** “Railway, public, connection and failed-login telemetry. An assigned nonstandard port is fine.”

**Decision:** inspect the actual Railway TCP Proxy, persistence, sleep, source-IP behavior, and isolation/egress controls. A single SSH detector may be feasible; the packaged OpenCanary HTTP recipe is not already an SSH deployment. Select and configure an appropriate SSH service and exact logged interaction, or explain why an isolated VM is required if safe isolation cannot be established. Do not silently convert the request to an HTTP token. Interactive-shell requirements may justify Cowrie, but that advanced route is additional work rather than packaged turnkey support.

**Render branch:** a public Render HTTP web service is not evidence of public SSH ingress. A Render private service may carry the protocol, subject to the documented plan/network and isolation checks. For a public SSH requirement that cannot be served there, prepare a concrete separate-host option and its costs; obtain any authorization not already present before provisioning.

**Acceptance:** validate the actual SSH listener/port and installation identity; generate the selected connect/version/auth event using harmless test values; correlate the sanitized recipient notification. An HTTP health response or TCP Proxy creation alone passes neither mechanism nor receipt gates. Record proxy source-IP limitations honestly.

**Assessment:** platform details are strong; the corrected selection table now explicitly defers to the protocol goal (F5 resolved).

### 3. AWS Linux Docker administrator; private-network decoy; Slack

**Input:** “I administer AWS Linux with Docker. I want a decoy on our private network and alerts in Slack.”

**Appropriate next turn:** “Which owned subnet should reach the decoy, and is there an existing dedicated VM with no production role or data? Which private Slack channel should receive sanitized alerts?”

**Synthetic follow-up:** “There is a disposable dedicated VM; the app subnet should reach it. Use the private security channel. Routine configuration is authorized.”

**Decision:** one OpenCanary HTTP decoy is a reasonable simple default for private-network exploration, assuming HTTP access is a relevant lure. Inspect the VM, compose/daemon versions, port conflicts, assigned interface, security groups, routes, metadata protections, and controlled outbound path. Begin on loopback; record the reviewed source/image/config identity. Do not repeatedly ask permission for routine already-authorized setup.

**Alerts:** private local log plus sanitized durable outbox, protected Slack webhook secret, real ingestion/flush supervision and health owner. Raw submitted passwords, request headers, and log text stay out of Slack. The helper findings identified by this review are resolved; real Slack receipt and ongoing supervision still require environment-specific validation.

**Acceptance:** loopback `/index.html` generates documented event 3000; correlate outbox ID and Slack receipt. Then bind the approved private interface and repeat from the intended app-network location after controls are ready. Verify prohibited egress and management exposure. Loopback success alone cannot establish lateral-movement coverage. Reboot/scheduler persistence and independent health checks remain runtime checks, not package test achievements.

**Assessment:** the concrete OpenCanary route is the most complete installation path reviewed. Its separate network-placement test, image identity, log rotation, and receipt requirements are unusually clear. The initial HTTP service observes access to itself, not all network activity or the real app.

### 4. Local developer; copied-secret detection

**Input:** “I want to know if somebody copies a secret from my local development files.”

**Appropriate next turn:** “Do you need an alert at the moment a file is read/copied, or when a copied credential is later used? What kind of credential is it?”

**Synthetic follow-up A:** “The moment of copying, even if it is never used.”

**Decision A:** neither a plain honeytoken nor the bundled metadata watcher meets that requirement. Reading/copying may leave size, mtime and inode unchanged. Inspect authorized OS/file-audit capabilities or an existing endpoint agent; avoid inventing a universal file-read watcher. If only dashboard/file access is available, record the missing detection capability and smallest feasible addition.

**Synthetic follow-up B:** “Later use is enough; I can plant a separate decoy AWS key.”

**Decision B:** provider-issued AWS credential token in a separate decoy-only file, no privileges, no production default-profile replacement. Follow the supported isolated identity-call test and documented event delay. A random fake Supabase/API string does not become a monitored credential just because it looks secret.

**Acceptance:** reading the file is a negative control, not successful token validation. The AWS branch requires supported credential use, provider event, and recipient receipt. The file-change branch, if the user independently changes the goal, requires a deliberate modification/deletion plus receipt and must retain its writes-only coverage label.

**Assessment:** the skill and helper tests correctly reject read/copy coverage claims. A successful interview may legitimately conclude that the initial requested signal cannot be implemented with the available capabilities.

### 5. AI/MCP builder; misuse alerts

**Input:** “I build AI agents and MCP tools and want misuse alerts.”

**Appropriate next turn:** “Do you want to notice a copied MCP configuration being used, a client connecting, or invocation of a particular tool that the normal workflow never needs? Which test client and private alert destination can we use?”

**Synthetic follow-up:** “A particular forbidden-by-our-workflow tool invocation. Hosted metadata is okay. Use a disposable development client.”

**Decision:** a tool-call-mode MCP configuration token is a reasonable low-operations option if its actual discovery and invocation behavior fits that client. Connection mode is a different signal and can fire on routine startup/discovery. A connection/list-tools action must not be presented as proof of invocation mode. Put the lure where the intended client can discover it without replacing production connections or granting real privileges. Use an empty test profile and synthetic inputs.

**Alternative boundary:** if the user wants a local/custom MCP service and refuses hosted processing, Beelzebub may be investigated as an advanced implementation. The reviewed source/log/RabbitMQ capabilities are not a shipped email/Slack integration, and the generic CLI is not a native parser for every project. Build and test the required adapter before claiming support.

**Acceptance:** exact token/resource and trigger mode; a controlled call of the intended harmless bait tool; provider event and matching recipient notification. Record tool/listing/connection noise. The alert establishes invocation of the bait, not proof of prompt injection, malicious intent, or detection of every misuse of all legitimate tools. Logs and external model providers must not receive production tool arguments or credentials by default.

**Assessment:** the completed AI route and research accurately distinguish connection, invocation, copied bytes, and broader AI misuse. The route now provides an isolated client-config test, warns that generated formats differ by client, and identifies the remaining Beelzebub adapter work. These are documentation checks, not live MCP tests.

### 6. Shared-host dashboard-only user; no third-party event data

**Input:** “I only have a shared-host dashboard, no terminal or code deployment. I forbid third-party event data.”

**Appropriate next turn:** “Does the existing dashboard provide an approved internal access-log alert or audit rule, and is delivery to an existing company-controlled mailbox allowed? I can inspect the available capabilities if the dashboard is connected.”

**Synthetic follow-up:** “No log alerts or internal sink, and I cannot add code, agents, or a server.”

**Decision:** the requested constraints currently leave no authorized detector execution and no alert sink. Do not create hosted Canarytokens, claim that an unmonitored fake credential is functioning, suggest self-hosting as if dashboard access were shell access, or infer that generic email is necessarily allowed. Explain the smallest capability change: approved host-native/internal audit alert, an authorized existing collector, or a permitted isolated runtime. Prepare a design only; record not configured and the exact missing capability.

**Acceptance:** no gates pass merely because a bait file was uploaded. No external event delivery occurs unless the user changes the data-flow constraint. If the hosting provider already processes access logs as an approved processor, establish that interpretation explicitly rather than treating “third-party” as resolved by assumption.

**Assessment:** the skill's explicit “privacy forbids hosted tokens and no detection execution/sink” row handles this case correctly. Successful behavior is a truthful capability boundary, not a forced installation.

## Overall assessment

The interview and route boundaries generally avoid false coverage claims. The strongest features are exact mechanism definitions, product-specific runtime caveats, private placement, narrow forwarding, no automatic incident response, and the requirement for detector evidence, a real controlled trigger, and independently matched recipient receipt. The original tests are useful behavioral tests rather than assertions that repeat implementation text.

The principal weaknesses found were in the helper's input allowlist and steady-state retention rather than the overall route architecture. All identified helper defects and documentation ambiguities were corrected and rechecked. The accepted-event retention path now preserves evidence under concurrent delivery without inventing receipt. SSH selection and watch-state cutover are explicit. No unresolved high/medium issue from this independent review remains; this is not a claim that exhaustive security or platform testing occurred.

The completed local-file reference describes polling gaps, reads/copies as a negative control, dedicated harmless files, manual-only status without supervision, and actual post-scheduler acceptance. Alerts and operations document native-vs-custom integrations, delivery limits, independent health checks, identity-safe removal, and retention. At the final link scan in this review, all six scenario route targets existed; package authoring still had four missing relative targets: `LICENSE`, `references/research-brief.md`, `references/validation-report.md`, and `references/examples.md`. Recheck these after final authoring rather than treating this transient state as an accepted archive.

Passing this review does not establish live hosted-provider behavior, a newly installed Claude/Codex session's discovery, a Linux OpenCanary container's operation, cloud firewall effectiveness, SMTP TLS delivery, Slack/Discord compatibility, or any real recipient's receipt. Those remain the selected deployment's explicit runtime acceptance work.
