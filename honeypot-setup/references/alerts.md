# Alerts and the local outbox

Choose a private destination the user controls. Native provider integrations and this package's adapters have different capabilities. The helpers never choose a recipient or create a subscription.

| Route | Email | Generic webhook | Slack / Discord / n8n |
|---|---|---|---|
| Hosted Canarytokens | Native private email | Native, provider-controlled payload/retry limits | Native formats where current UI supports them; use private destination or a sanitizing n8n workflow. Read [token route](route-canarytokens.md). |
| OpenCanary | Native SMTP handler, or this outbox | Native handler, or this outbox | Outbox adapters below; native integrations may expose raw logdata and lack durable retries. |
| Local file watcher | This outbox via authenticated TLS SMTP | This outbox | This outbox Slack/Discord; generic HTTPS to an existing n8n workflow. |
| App decoy | Existing app consumer/provider | Existing durable queue + consumer | Project-specific consumer; Python helper does not run in a serverless request. |
| Beelzebub | No turnkey email route shipped | Custom normalized log/event consumer required | Integration-required; do not claim delivery based on a running MCP service. |

Telegram/SMS are not implemented in `decoyctl.py`. An existing n8n workflow can bridge to them after verifying that destination's API, permissions, billing and actual receipt. Do not create billable accounts or send messages to unrelated parties. Native email contents are controlled by the upstream provider and can include management links; keep them private.

## Local outbox: scope and contract

`scripts/decoyctl.py` uses Python 3.10+ standard library and SQLite. It opens no listener. It stores sanitized events and delivery status in a private persistent directory. It does not provision a server, create tokens, parse arbitrary provider webhook payloads or install a scheduler. Commands are safe to rerun for the same inputs; `delivery-test` intentionally creates a new sender test every time.

Supported inputs:

- `ingest --format opencanary`: one complete JSON object per line from the pinned OpenCanary PyLogger. Requires `utc_time` and integer `logtype`; parses UTC even though upstream timestamps lack an offset. `src_host` is optional. Startup/lifecycle codes 1000–1005 are skipped. HTTP code 3000 is an interaction; event significance still needs context.
- `ingest --format generic`: JSONL objects with ISO-8601 `timestamp` including timezone, one allowed `interaction` (`http_request`, `tool_call`, `client_connect`, `file_changed`, `file_deleted`, `file_replaced`, `file_restored`, `delivery_test`), optional IP `source_ip`, and optional Boolean `test`. Include your producer's `event_id` or unique nonce to distinguish otherwise identical events; the helper derives its own stable digest over the full input and fixed labels for correlation. Record both in a protected producer ledger if needed.
- `watch-add` / `watch-poll`: dedicated regular decoy file metadata only; see [local files](route-local-files.md).

Only event digest, normalized UTC time, friendly labels, fixed interaction code, validated IP, explicitly untrusted test-claim Boolean (`test_claimed_untrusted`) and fixed explanatory text enter notifications. Bodies, request headers/query strings, passwords, token strings, management URLs, `logdata`, tool arguments/output and arbitrary messages are omitted. Source IP is still potentially personal data: choose access/retention accordingly. Test flags are descriptive, never an instruction to suppress evidence.

## Configure one destination

Deliver these steps individually in guided mode. Set `SKILL_DIR` to the verified installed skill directory. Use a different private `DECOY_STATE` per destination/deployment. The examples use a neutral local directory; do not commit it.

1. **Purpose: separate reusable code from runtime data.** Run:

   ```sh
   umask 077
   DECOY_STATE="$HOME/.local/state/honeypot-setup/lab-decoy"
   mkdir -p "$DECOY_STATE"
   chmod 700 "$DECOY_STATE"
   ```

   Expected: a private directory. Recovery: choose a writable private path; don't loosen it to world-readable. Copy the chosen template to `$DECOY_STATE/alert.json` only if it does not already exist. `SKILL_DIR` points to `honeypot-setup`, not its parent.

   ```sh
   test ! -e "$DECOY_STATE/alert.json" && cp "$SKILL_DIR/templates/alert-webhook.json" "$DECOY_STATE/alert.json"
   chmod 600 "$DECOY_STATE/alert.json"
   ```

   Choose `alert-slack.json`, `alert-discord.json` or `alert-smtp.json` instead as appropriate. If the file already exists, inspect its nonsecret fields and resume; do not overwrite. Back up existing config before editing.

2. **Purpose: supply the real destination privately.** Edit `alert.json` locally. Set a friendly `destination_label`. For generic HTTPS, keep `bearer_env` only when the receiving endpoint accepts that Bearer token; remove it if authentication is solely the secret URL, and document that choice. Enter secrets in a local secret manager or protected service environment. For a temporary terminal session, this avoids putting the secret value in command history or tool arguments:

   ```sh
   # Run this yourself in a local interactive terminal, not through chat.
   export DECOY_WEBHOOK_URL="$(python3 -c 'import getpass; print(getpass.getpass("Webhook URL: "))')"
   export DECOY_WEBHOOK_BEARER="$(python3 -c 'import getpass; print(getpass.getpass("Webhook bearer: "))')"
   ```

   Use the variable names in the chosen template (`DECOY_SLACK_WEBHOOK`, `DECOY_DISCORD_WEBHOOK`, `DECOY_SMTP_PASSWORD`). Agents should prefer a tool's secure secret-entry capability; do not ask the user to paste these values. The helper does not auto-load `.env`. A supervised service needs an explicitly configured protected environment; cron does not inherit your interactive exports. The destination's secret URL remains a credential even though no password is visible.

3. **Purpose: validate before sending.** Run:

   ```sh
   python3 "$SKILL_DIR/scripts/decoyctl.py" --state "$DECOY_STATE" validate --config "$DECOY_STATE/alert.json"
   ```

   Expected `valid: true`, `network_tested: false`. This does not send a message. Recovery: fix private permissions, required fields and secret environment references. HTTPS is required; an explicit loopback-only HTTP exception exists solely for disposable tests. Redirects are refused. SMTP requires TLS (`starttls` or `ssl`) and validates server certificates.

4. **Purpose: test the delivery adapter separately.** Run `delivery-test --name "Lab decoy" --environment lab`, then `flush --config "$DECOY_STATE/alert.json"`, each with the same script and `--state` prefix. Expected: a test event ID and `accepted` or an explicit pending/failed status. Recovery: inspect `status`; fix auth/permissions/network/rate limits. **This does not test the decoy mechanism.** Perform the route-specific controlled trigger afterward and confirm its own matching notification.

5. **Purpose: confirm the chosen destination.** Read the delivered message via authorized destination access or get an explicit user confirmation of the event ID/name/time. Only then run:

   ```sh
   python3 "$SKILL_DIR/scripts/decoyctl.py" --state "$DECOY_STATE" confirm --event-id VERIFIED_EVENT_ID --method user-confirmed
   ```

   Use `destination-read` only when you inspected the matching destination message. The script records an attestation; it cannot independently prove that the operator actually looked. If receipt is not confirmed, leave it unconfirmed and continue troubleshooting.

## Destination specifics

**SMTP/email:** use the user's existing authenticated SMTP service, its documented host/port, sender authorization and recipient. `starttls` commonly uses 587; `ssl` commonly uses 465, but verify the actual service. Username and addresses are local protected config; password comes from an environment reference. The helper calls `starttls` before authentication and treats refused recipients as failure. SMTP acceptance means the server took responsibility, not that the inbox received it. Check bounce mail, spam/quarantine, sender authentication and mailbox rules. Native hosted-token email is generally easier for beginners because no SMTP account setup is needed.

**Slack adapter:** create or select the user's authorized Slack app and enable **Incoming Webhooks**, then **Add New Webhook to Workspace** and select the intended private channel according to the current official page. Store its secret URL locally. The adapter posts JSON, uses plain-text blocks, disables unfurls and requires the expected `ok` response. This is an alert destination; **it is not Slack API Canarytoken creation**, which upstream deprecated for new tokens. [Slack incoming webhooks](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/) (accessed 2026-11-23).

**Discord adapter:** use a webhook for the chosen user-controlled channel, created by someone with Manage Webhooks permission. The adapter uses `content`, disables mentions with `allowed_mentions: {parse: []}`, and adds `wait=true` so the HTTP response waits for message creation. Confirm the message in the destination regardless. URLs are restricted to official Discord hosts. [Discord webhooks](https://docs.discord.com/developers/resources/webhook) (accessed 2026-11-23).

**Generic HTTPS / n8n:** JSON payload is the normalized event above. The helper sends `Idempotency-Key: <event_id>` and optionally `Authorization: Bearer ...`; the receiver must actually implement deduplication/verification for those to have effect. In an existing n8n workflow choose Webhook, POST, and appropriate Header Auth. Set header name Authorization and expected Bearer value if using that template. Use **Production URL** for the published workflow; a temporary Test URL expires when its listener stops. Preserve the event ID, use destination credentials from n8n's credential store and verify the final send node and actual inbox/channel. Configure retry/error handling at the workflow/queue layer; HTTP acceptance is not downstream delivery. [n8n Webhook](https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.webhook/) (accessed 2026-11-23). Native Canarytokens ingress has a different schema/auth limitation; follow its route-specific recipe.

## Reliability and health boundaries

- `flush` sends at most one due event per invocation, at most once per second per outbox. It uses a SQLite write transaction to serialize senders. Run it repeatedly under the selected supervisor; one invocation does not drain the queue. Do not run multiple outboxes to the same destination without a shared downstream rate limiter.
- HTTP 429/5xx and transport errors retry with bounded backoff; Retry-After seconds/date is honored up to one day and pauses that outbox. Permanent 4xx/redirects fail immediately. SMTP 4xx retries; 5xx fails. Eight attempts end in visible `failed` state; `retry --event-id ID` is an explicit operator action after remediation. Do not retry forever or keep triggering blind tests.
- Deduplication uses stable event digests. There is still a crash window after external acceptance and before SQLite commit; duplicate delivery is possible. Use event ID to correlate; Slack/Discord webhooks and SMTP do not promise this helper exactly-once delivery. The receiver must implement idempotency where possible.
- The outbox is bounded at 10,000 retained records; it fails visibly when full instead of dropping new events silently. Export evidence and use `prune --older-than-days 30` for old **receipt-confirmed** accepted records. Unconfirmed accepted, failed and pending records are not pruned automatically. For routine unconfirmed accepted records, `prune --older-than-days 30 --include-unconfirmed --export /private/new-evidence.jsonl` first saves sanitized evidence with its original null receipt status, then removes the eligible records. The export must be a new file in a private directory. This does not claim receipt and does not delete failed/pending records. Review retention and archive input logs before this explicit operation. Pruning removes deduplication history; archive input logs and never reingest older records after pruning. For high-volume public sensors use a production log pipeline instead of this small helper.
- Ingestion rescans a complete JSONL file up to 16 MiB, ignores an unfinished last line, rejects oversized/invalid records and rolls back the batch. Retain rotated files long enough to ingest them, including after downtime. Ingest each retained file before retiring it; the helper does not tail rotations automatically. Missing rotations can cause missed alerts. Rotate well below 16 MiB, monitor disk/queue age, and do not ship raw logs broadly.
- Supervise both **detector and dispatcher**. Check process/container health, ingest/flush exit status, malformed-line errors, oldest pending age, failed counts, disk capacity, and the actual destination with periodic mechanism-specific self-tests. An external uptime checker or existing operations monitor must notice a stopped host/dispatcher; a dead process cannot alert about its own death. `status` is local evidence, not an independent health monitor.
- Set an explicit latency target (for example 60 seconds) and observation interval; low urgency polling once per minute may be fine for a private low-volume sensor. High urgency needs a continuously supervised loop, queue-age alert and tested failover. This package does not silently install scheduled tasks. On systemd use a protected `EnvironmentFile`, absolute script/config paths, a dedicated non-root service user and persistence path with proper ownership; verify the actual unit/timer and reboot recovery before handoff.

Moving or rotating a webhook changes its identity. The helper refuses a destination change in an existing outbox. Stop the dispatcher, preserve/export the old pending/failed evidence, create a new private outbox, configure/test the new target, then switch ingestion deliberately. For file watches, they live in the old SQLite database: record each verified watch name/path, copy its exact registration and baseline into the new outbox under an exclusive stopped-dispatcher maintenance window, or explicitly re-register the dedicated files and record that changes during the re-baseline interval are not observed. Never assume a new outbox contains watches. Run a fresh controlled file test after cutover. Do not replay old inputs wholesale into the new outbox; record a cutover time and forward only reviewed unsent events. SMTP password rotation leaves its destination identity unchanged. Protect and revoke obsolete secrets after successful cutover; rollback can restore the prior dispatcher/config if still valid.

Implementation APIs reviewed: [Python smtplib](https://docs.python.org/3/library/smtplib.html), [urllib.request](https://docs.python.org/3/library/urllib.request.html), [SQLite transactions](https://docs.python.org/3/library/sqlite3.html), accessed 2026-11-23. Local tests exercise the HTTP transport; external SMTP/Slack/Discord services remain runtime acceptance requirements.
