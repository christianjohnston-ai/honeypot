# Hosted Canarytokens: private email first

Use when the goal is **use of a planted artifact** and the person cannot operate another server. This fits Vercel/Supabase, Netlify/Firebase, Cloudflare, shared hosting, private repos and local files without assuming SSH, root, background processes or arbitrary listening ports. A protected decoy does not require changing real authentication or database policies. For MCP use also load [route-ai-mcp.md](route-ai-mcp.md).

Evidence reviewed 2026-11-23: [getting started](https://docs.canarytokens.org/guide/getting-started), [HTTP](https://docs.canarytokens.org/guide/http-token), [AWS](https://docs.canarytokens.org/guide/aws-keys-token), [token/source limitations](token-ai-research.md). UI labels below are corroborated in [current upstream notification form](https://github.com/thinkst/canarytokens/blob/61f3e0c7790f08f1be09a947cb0d68e6152cde6a/frontend_vue/src/components/ui/GenerateTokenSettingsNotifications.vue); inspect the actual live page before acting because hosted deployment can differ.

## Recommendation contract

Say, for example: “We'll create one private decoy document containing a unique web link and send alerts to your email. Someone must follow that link for this to alert; copying the document or reading database rows alone won't alert. Thinkst operates the receiver and sees trigger metadata. The public token service is documented free; allow about 10–25 minutes plus testing. You need access to the private folder and your inbox.”

If they want every database read, arbitrary API-key theft, or ransomware detection, this alone does not meet that goal. Offer an application/audit mechanism, provider-issued credential token, monitored file, or isolated sensor as appropriate. Do not plant a public URL and call internet scans evidence of an app breach.

## One step at a time

Each row is one runtime step. In guided mode give just that row; in assisted mode perform its authorized action and report the observation.

| Step / purpose | Exact action | Expected evidence | Recovery |
|---|---|---|---|
| 1. Preflight / identity | Identify the exact private repo/folder/object to hold one decoy; confirm the user owns/administers it, intended legitimate readers, previews/indexers/backups, recipient control, outbound HTTP/DNS, and hosted-data preference. Check profile for an existing token alias and protected management-link location. | A precise placement and trigger, feasible transport, and no duplicate token. | If no appropriate private placement or external callbacks allowed, change route; do not widen real app access. |
| 2. Select mechanism | Open [Canarytokens](https://canarytokens.org/). Select **Web bug** for a link-request tripwire, **DNS** for resolver activity, **AWS keys** for credential use, or a supported document type. Select only one matching the goal. New Slack API tokens are deprecated. | Correct token-specific form; no token yet. | If label/type missing, inspect current docs; never substitute an invented type or commercial API. |
| 3. Configure delivery / create | Enter the user's private address in **Mail me here when the alert fires**. In **Remind me of this when the alert fires**, use a nonsecret alias, environment and placement summary, e.g. `repository-doc-decoy / development / unused internal note; unexpected use: review repo access`. Create once using the observed submission control. Optional **Add Webhook Notification** goes to a private sanitizing adapter described below. | Artifact and management/history access provided. Creation/validation email alone is not a decoy trigger. | Check form errors and rate limits. Before retrying creation, check the user's received management email/existing token list to avoid duplicates. |
| 4. Save / place | User saves management URL/auth in their password manager or protected local secret file, never shared chat/profile. Place only the generated artifact in the selected private location. Preserve unrelated files; if path exists, inspect and back up before changing it. Record alias, type, location category and secret reference, not the URL/key. | Decoy exists with intended access controls; owner can identify it without revealing its capability. | If scans/previews immediately fire, record benign cause and move to a less routinely accessed placement; do not broadly ignore internal networks. |
| 5. Controlled trigger | Record UTC start/end and local timezone, a unique local test ID, expected source and decoy alias. Perform one action from the table below. Keep test ID in the acceptance record; providers may not echo it. | Matching provider history event; event time/source/memo/type match test. | Wait beyond documented throttle/delay; inspect mechanism-specific egress/viewer issues. A successful network request is insufficient alone. |
| 6. Receipt / handoff | With authorized destination access, locate the matching alert; otherwise ask user to confirm its alias/time. Record provider event ID if present, else correlate timestamp window, alias and source. Mark receipt `destination-read`, `user-confirmed`, or `unverified`. | All three: mechanism operating, event generated, recipient received. | If absent, check junk/quarantine/rules, address, enabled alert settings, history and webhook failures. Status remains **configured, delivery unverified** until receipt is confirmed. |

A URL token is a capability that outsiders can trigger; management URL is an administrative capability. Neither belongs in the reusable package or broad notifications.

## Controlled triggers

- **Web bug:** user opens the generated URL once in a browser, or agent issues one GET using a locally protected URL without echoing it. Do not use link previews as the test. Match provider history; a GIF/empty response can be normal. Repeat future tests after the throttle interval.
- **DNS:** resolve the generated hostname once using the user's resolver. Record resolver visibility, not an invented attacker endpoint. Cache may prevent another upstream query; wait for TTL/observed policy. A successful lookup is not proof of mail delivery.
- **Document:** open the actual generated document in its documented application with permitted network callbacks. A byte read, checksum, ZIP inspection or incompatible preview is not equivalent. No macros or malware needed. If the viewer blocks the callback, record that limitation and choose a different mechanism.
- **AWS keys:** keep the provider-issued pair together in a **dedicated** local credentials file, never overwrite `~/.aws/credentials`. Confirm file exists and contains only the canary's `[default]` pair locally without printing values. Test one read-only `sts get-caller-identity` call. Use an isolated environment so real AWS credentials cannot win precedence:

  ```sh
  # Set this to the protected canary-only file path, never a production file.
  HONEYTOKEN_CREDENTIALS_FILE='/absolute/private/path/to/canary-credentials'
  # Confirm the file above exists and is the intended canary before this command.
  env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN \
      -u AWS_PROFILE -u AWS_DEFAULT_PROFILE -u AWS_ROLE_ARN \
      -u AWS_WEB_IDENTITY_TOKEN_FILE -u AWS_ENDPOINT_URL -u AWS_ENDPOINT_URL_STS \
      AWS_SHARED_CREDENTIALS_FILE="$HONEYTOKEN_CREDENTIALS_FILE" \
      AWS_CONFIG_FILE=/dev/null AWS_EC2_METADATA_DISABLED=true \
      AWS_REGION=us-east-1 AWS_PAGER='' \
      aws sts get-caller-identity --region us-east-1 \
      --endpoint-url https://sts.us-east-1.amazonaws.com --no-cli-pager >/dev/null
  ```

  This invokes [AWS identity lookup](https://docs.aws.amazon.com/cli/latest/reference/sts/get-caller-identity.html), which requires no IAM permission; do not add permissions to the token. Error/success of the CLI is separate from the alert. Allow the documented 2–30 minute pipeline delay, and continue troubleshooting if no event appears. Do not promise arbitrary AWS API calls are instantly or completely observable. Never paste the keys or command debug output into chat.

## Optional n8n adapter: generic webhook to a sanitized channel

Use only when the user already operates n8n or accepts its operational/billing burden. This is an **adapter design with tested transformation code**, not a shipped, deployed n8n workflow or guaranteed queue. Default to private email if they do not need it. Do not send native Canarytokens notifications directly to a broadly visible channel: current payloads contain `manage_url`, and some contain request data.

1. In a user-owned workflow add a **Webhook** node, HTTP method **POST**. Generate a dedicated unpredictable path with at least 32 random bytes; keep its Production URL secret. The public Canarytokens sender does not expose custom authentication headers, so do not select n8n Header/JWT/OAuth auth and expect it to work. Use TLS, owner-only workflow access, reverse-proxy request limits where available, and rotate the path if exposed. This authenticates possession of a URL, not cryptographic provenance. A localhost/private IP URL cannot receive hosted callbacks. [Webhook node documentation](https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.webhook/).
2. Add a **Code** node in JavaScript, run once for all items. Use this original allowlist transform, replacing the two static aliases with approved nonsecret values. It intentionally ignores memo, token, management links, credentials, headers, bodies, tool arguments and arbitrary additional fields:

   ```javascript
   const body = $input.first().json.body;
   if (!body || typeof body !== 'object' || Array.isArray(body)) {
     throw new Error('Expected a Canarytokens JSON object');
   }
   const mechanisms = {
     http: 'Token URL requested', dns: 'Token hostname resolved',
     aws_keys: 'Issued AWS canary credential used',
     msword: 'Word document callback observed',
     adobe_pdf: 'PDF DNS callback observed',
     mcp: 'Configured MCP trigger observed'
   };
   const kind = Object.prototype.hasOwnProperty.call(mechanisms, body.token_type)
     ? body.token_type : 'unknown';
   const time = typeof body.time === 'string' &&
     /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \(UTC\)$/.test(body.time)
       ? body.time : 'upstream time unavailable';
   const ip = typeof body.src_ip === 'string' &&
     /^[0-9a-fA-F:.]{3,45}$/.test(body.src_ip)
       ? body.src_ip : 'unavailable';
   const event = {
     event_id: 'n8n-' + String($execution.id).replace(/[^a-zA-Z0-9_-]/g, '').slice(0,64),
     timestamp: time,
     received_at: new Date().toISOString(),
     timezone: 'UTC',
     decoy_name: 'private-note-decoy',
     environment: 'development',
     interaction: mechanisms[kind] || 'Unrecognized provider event; inspect privately',
     source: ip,
     significance: 'Use of this decoy was observed; this alone does not establish a breach.',
     next_action: 'Check authorized tests and scanners, then review access near this time.'
   };
   event.message = [event.timestamp, event.decoy_name + ' / ' + event.environment,
     event.interaction, 'Reported source: ' + event.source, 'Event: ' + event.event_id,
     event.significance, event.next_action].join('\n');
   return [{json: event}];
   ```

3. Forward **only this output**. For a generic HTTPS receiver, an **HTTP Request** node uses POST, JSON body `={{ $json }}`, user-selected URL and protected credentials. For Slack use the user's existing incoming webhook or Slack credential, with body expression `={{ {text: $json.message, blocks: [{type: 'section', text: {type: 'plain_text', text: $json.message}}]} }}`. Never include the original `$node["Webhook"].json` or raw HTTP errors in messages. [HTTP Request](https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.httprequest/), [Slack incoming webhooks](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/).
4. Keep ingestion quick: the native sender has a short timeout and no retry loop. **Immediately** responding acknowledges intake, not durable delivery. For dependable operation, persist the sanitized event to the user's durable queue/outbox before acknowledgement, and run destination delivery from that queue. Without such a queue, explicitly document crash/outage loss risk and keep native private email enabled as an independent channel. n8n execution history may retain the **raw** incoming administrative URL; restrict it and set a reviewed retention policy, or use a separate intake workflow with execution saving disabled and a sanitized durable downstream workflow. The transform cannot erase upstream execution history.
5. Configure destination **Retry On Fail** for transient faults (e.g. three tries, 5000 ms); do not endlessly retry invalid credentials/400s. Current n8n caps it at five tries/5 seconds and does not automatically obey `Retry-After`. For longer 429 delays use a bounded **Wait** path honoring the returned delay and retaining the event, then error after the configured limit. Save failed downstream executions for recovery, set an **Error Trigger** workflow to a different private channel, and verify retry from saved data. [Rate limits](https://docs.n8n.io/integrations/builtin/handle-rate-limits/), [error workflow](https://docs.n8n.io/build/flow-logic/handle-errors-gracefully), [execution recovery](https://docs.n8n.io/workflows/executions/all-executions/).
6. For duplicate suppression use durable delivery state keyed by a stable event ID; preserve the normalized ID on retries. Canarytokens supplies no guaranteed unique event ID, so timestamp/source/type dedupe is only a heuristic and can merge genuine events. Native per-IP throttling is not retry dedupe. Do not mark delivered before the destination accepts the send; an ambiguous timeout may still duplicate a message. Label test IDs and document this at-least-once uncertainty rather than promising exactly-once delivery.
7. Publish the workflow and put its **Production URL**, not test URL, in the token. Test a synthetic adapter message first, then a real controlled token interaction; correlate recipient receipt separately. Disable the destination temporarily in a disposable test to verify a recorded failure and recovery. Monitor the outbox/failed executions and use a scheduled self-test; silence is not health evidence.

The package's `decoyctl.py` is **not** a hosted Canarytokens webhook receiver and does not parse its native schema. Do not connect the URL to that CLI.

## Resume, move destination, and remove

On resume verify alias, type, artifact placement, management secret reference and provider history before making a change. Reuse the existing token; never regenerate just because the chat restarted.

To move alerts, inspect the management UI's actual options. Current source exposes **Email alerts** and **Webhook reporting** enable/disable switches; it does not establish an editable recipient field for every token. If destination editing is unavailable, create one explicitly linked replacement, test it at the new destination, replace the old artifact atomically, then disable/delete the old token. Keep the old route working until new receipt is confirmed.

For removal identify the exact token and artifact, preserve required event evidence privately, remove only its planted artifact, then use the observed **Delete Canarytoken** action. It also deletes associated alerts in current UI; disclose that consequence before final approval if deletion was not already authorized. Remove only adapter workflow/credentials exclusively owned by this deployment. Revoke/rotate leaked destination URLs. Record removal and residual copies/backups that may continue trying callbacks. Never delete an unrelated repository, shared n8n instance, or user's AWS credentials file.
