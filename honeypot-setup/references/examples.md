# Example runtime conversations

These are **simulated conversations**, not records of deployments or received alerts. They illustrate pacing and acceptance decisions. Each actual session must inspect its real environment and collect its own evidence.

## Beginner: Vercel and Supabase, private email

**User:** `/honeypot-setup I built my app with an AI builder. It uses Vercel and Supabase. I want to know if someone gets into our private notes. I don't know servers.`

**Agent — discovery:** “I can help set up a tripwire. Do you want to notice someone following a link planted in a private note, or every time a note is read? Would a private email alert work?”

**User:** “Following a link is useful. Email is good.”

**Agent:** “Can you add a new note to the private area? Is it acceptable for the token service to receive the time and network information when the link is used? You can say ‘I don't know.’”

**User:** “Yes to both. I can use the dashboard and my email.”

**Agent — selection:** “We'll create one Web bug Canarytoken and put its link in a new private decoy note. A request to that link triggers the email. It covers use of this link; someone could read other notes without triggering it. The public service is documented free, and this usually takes about 10–25 minutes. You won't need to run a server. I'll guide you one step at a time.”

**Agent — setup, first step:** “First, open the private notes area and choose a new unused note name. Check that only the intended team can see it and whether your app previews links automatically. Expected result: an appropriate private location. If it's public or every link is automatically fetched, we'll choose another location.”

**User:** “It's private and no previews.”

**Agent — alerts:** “Open the verified Canarytokens site and select Web bug. Enter your email directly there. For the reminder, use a nonsecret label such as ‘private-note-decoy / development.’ Create it once and save the management link in your password manager. Don't paste that link here. Tell me whether the artifact and management access appeared.”

**User:** “Created and saved.”

**Agent — setup:** “Add the generated trigger link to the new private decoy note. Keep your normal notes and access settings as they are. Expected: only this decoy note contains the token. If the note already exists, check it before changing it.”

**User:** “Done.”

**Agent — validation:** “Record the current time, then follow the link once yourself. Check its private history for the matching event. Then look for the matching email, including spam. The initial token-creation email is a different message.”

**User:** “History shows my request. I don't have an alert email yet.”

**Agent:** “The token generated an event, but delivery is still unverified. We'll check the recipient, alert setting, spam/quarantine and timing before another test.”

**User:** “Found the alert in spam. The decoy label and time match.”

**Agent — handoff:** “I'll record receipt as user-confirmed, with the matching time and label. The setup covers requests to that private bait link. The handoff includes the protected management-reference location, future self-test, spam-rule check, data recipient, and how to delete this token and its decoy note.”

## Server: existing isolated AWS Linux VM and Slack

**User:** “I administer an isolated AWS Linux VM with Docker. Set up a private network decoy and alert our private Slack channel. The VM already exists; use assisted mode.”

**Agent — discovery:** “Which owned network should be able to reach the decoy, and what activity matters: visiting a fake web login page or trying SSH? Where is management access currently restricted?”

**User:** “The application subnet, HTTP is fine. Admin SSH is through our VPN. No instance role. The decoy has no production access.”

**Agent:** “I'll inspect the VM identity, Docker/Compose, existing listeners, routes, security groups, egress, storage and clock using the authorized tools. Please create or select the Slack incoming webhook privately; its secret stays in protected configuration.”

**Agent — selection:** “One OpenCanary HTTP service fits this goal. A GET to its login page at `/index.html` creates event3000; the sanitized alert includes name, UTC time, source and correlation ID. It observes traffic to this sensor on the application network. Expect VM/disk costs already associated with the host and ongoing updates and self-tests.”

**Agent — setup:** “The reviewed changes are an identified Compose project, root-controlled config, a private rotating log and a durable outbox. The first listener is loopback. Here is the concrete config/diff and the planned private ingress/egress change.”

**User:** “Those private network changes are authorized.”

**Agent:** Executes one reviewed step, checks the result, records it and continues; it does not repeatedly ask for the same authorization. It builds the reviewed source, records the image ID, validates configuration, starts the sensor and verifies the listener. If a port conflicts, it selects an agreed free port rather than stopping an unrelated service.

**Agent — alerts:** Configures the private Slack webhook adapter using secure local entry, validates it, sends a labeled adapter test, and inspects its receipt using the authorized Slack capability. It records that this test exercised only the sender.

**Agent — validation:** “I'll make one harmless request to `/index.html`, find the new source event, ingest it and correlate its alert ID in the private channel. After the approved private bind/firewall change, I'll repeat from the intended application network.”

**Simulated observations:** Loopback test generates event; matching Slack message is inspected. Private-network test generates a separate event/message. Supervisor, log rotation/restart and independent health checks are verified in this fictional scenario.

**Agent — handoff:** Records detector, controlled event and `destination-read` receipt separately, image/config identities, private placement and boundaries, costs, health owner, failure recovery and exact removal. It never calls a running container alone a successful deployment.

## AI/MCP: connect versus tool call

**User:** “I want alerts if someone uses an MCP config they steal from my private project.”

**Agent — discovery:** “Would you like an alert as soon as a client connects, or only after it calls a tool? Is a hosted receiver allowed, and which private alert destination should we use?”

**User:** “On connection. Hosted is fine. My email.”

**Agent — selection:** “A hosted MCP Configuration Canarytoken in connection mode fits. We'll plant its generated config as an inert decoy file in the private project and keep management access separately. A client must contact the configured server; reading or copying the JSON alone will not alert. The receiver gets connection metadata.”

**Agent — setup:** Checks whether a token/config already exists, verifies the current token UI and client CLI options, then guides creation of one token. It records a nonsecret alias and mode, and saves the generated artifact privately. It preserves active MCP connections and production settings.

**Agent — validation:** “We'll test from an empty disposable client directory with only this decoy config. The current Claude Code CLI supports `--mcp-config` and `--strict-mcp-config`; I'll verify your installed help first. Confirm the client lists only the intended decoy before connecting.”

**User:** “Connection succeeds. I see the matching event and email.”

**Agent:** “I'll record user-confirmed receipt with the event time and alias. I'll remove the temporary test registration and leave only the inert decoy artifact. This proves the connection tripwire, not whether a production agent was prompt-injected.”

**Variant — User:** “Actually I only want tool-call alerts.”

**Agent:** Verifies whether mode can be changed in the actual management UI; prepares a replacement if necessary, preserving the prior token until the replacement passes. In a clean test profile, initialization/tool listing alone is not sufficient. It inspects the advertised tool schema and invokes a harmless operation with synthetic arguments, then confirms the resulting recipient alert before retiring the old token.

## Additional routing simulations

| User input | Adaptive next question / result | Acceptance boundary |
|---|---|---|
| “I deploy on Render or Railway and want alerts when someone tries SSH.” | First determine exact provider/product and public vs private goal. Render public web service is not generic SSH ingress; Railway TCP Proxy may support a scoped TCP sensor after checking assignment/persistence/isolation. Recommend separate isolated VM when needed. A hosted URL token does not meet an explicit SSH goal. | A real harmless SSH-specific interaction must generate the selected sensor event and matching message. HTTP sender test is insufficient. |
| “I fear someone copying my local API secrets.” | Ask which provider and whether the goal is copying or subsequent use. For AWS use a provider-issued defanged token in a separate bait file; arbitrary keys are inert. For read/copy evidence need a real audit detector. | Supported AWS-use test may take documented minutes. Reading the file cannot pass the credential-use gate. |
| “Shared hosting, only dashboard, and no event data may leave our organization.” | Inspect whether an existing authorized internal app/log/audit path can observe the action. If none, explain the missing detector/sink and propose the smallest internal monitoring or isolated-host addition. | No fabricated deployment or guaranteed free/no-server option. Record recommendation and unresolved capability; don't mark accepted. |

These cases were independently evaluated during the build; see [validation-report.md](validation-report.md). Future runtime outcomes remain dependent on actual authorization, product capabilities, selected mechanism and observed receipt.
