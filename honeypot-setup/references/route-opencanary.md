# OpenCanary on an isolated Linux VM

Use after selection for network access to a decoy in a network the user administers. This is a reviewed implementation recipe, not a claim that a cloud deployment or recipient delivery was executed during package development. Read [server research](server-research.md) for evidence, and [alerts](alerts.md) for the adapter. Do not use this recipe inside Vercel/Supabase functions or a production application VM.

## What this route covers

A dedicated Linux VM hosts a fake HTTP document-service login page. In this initial configuration an HTTP GET to `/index.html` produces OpenCanary event **3000**, a login submission produces **3001**, a request to `/` produces redirect event **3003** because redirect logging is enabled, and enabled unsupported-method logging can produce **3002**. Static asset requests and a bare TCP handshake are not equivalent triggers. This does not monitor the real application or detect stolen production credentials being used elsewhere. Put it where the suspected intruder could reach it: for lateral-movement detection, an approved private subnet reachable from the relevant app network. Public exposure primarily measures internet discovery/probing.

Primary route: one HTTP service; enable additional protocols only when their placement and specific trigger serve the stated goal. Docker OpenCanary does not support the portscan module. SMB requires separately configured Samba auditing; this template is not a file-open or ransomware monitor.

## Preflight and review

Explain the proposal: one isolated VM (existing disposable VM preferred), Docker Engine/Compose, one TCP listener, a bounded raw-event log, a protected durable alert outbox, and the chosen destination. Allow roughly 1–2 hours for an operator familiar with Docker, longer for network setup; this is an estimate. Upstream calls OpenCanary low resource but gives no universal minimum. This template caps its container at 512 MiB/1 CPU; choose VM capacity above this plus OS, image-build and adapter needs. VM, disk, public IPv4, transfer and destination usage may recur; quote the user's region/plan before any paid provisioning.

Perform read-only checks and record results:

```sh
uname -s
cat /etc/os-release
docker version
docker compose version
docker info --format '{{.OSType}}'
ss -ltnup
df -h
date -u
```

Expected: Linux Docker host, working Compose, free 8080/tcp (or reviewed alternative), persistent disk, correct UTC clock. No Docker access: use the provider's current official install guide or select hosted tokens. A macOS Docker Desktop lab does not validate this Linux source-IP/networking route. A used port: choose a free port and update both config and allowed ingress; never stop an unrelated listener. Confirm chosen subnet, route tables, management path, host/provider firewall, event-log retention, destination egress and secret storage before starting.

Prepare concrete configuration and firewall changes; obtain any still-required authorization before new spend, new public ingress, or production-affecting changes outside the agreed scope. Do not ask again for actions already authorized. This build assignment itself does not authorize VM provisioning.

Network isolation is part of setup, not a later hardening step:

- Separate VM with no production mounts, cloud role, customer data or real service passwords. Disable cloud metadata if unnecessary; otherwise require the provider's strongest supported protections and block decoy access with an appropriate host control. Do not store secrets in cloud user data.
- Management SSH remains on its own port and is accessible only from the approved administrator network/VPN. Never replace management SSH with a decoy.
- Allow the decoy port only from the approved monitored network. Deny decoy-initiated connections to production, internal control planes, metadata and arbitrary internet destinations; permit only required DNS/time/update/alert delivery paths. Security groups alone do not offer deny rules and their multiple attachments aggregate; verify the resulting rules rather than adding one seemingly restrictive group. For dynamic destination IPs, use an approved controlled egress proxy/firewall or established log collector; do not silently open unrestricted egress.
- Host networking preserves source addresses on Linux but shares the VM network namespace. The isolation boundary is the dedicated VM, not Docker alone. No privileged container, host filesystem mount or Docker socket mount.

AWS example: a dedicated EC2 instance and dedicated security group, no instance profile, management ingress from the admin's source only, decoy 8080 ingress from the relevant owned subnet/security group, restricted egress and an independent management route. Azure/GCP/VPS use equivalent controls after verifying their current documentation. No provider-specific resource-creation command is preauthorized or embedded here.

## 1. Prepare an identifiable, rerunnable deployment

Use an operator-chosen absolute `SKILL_DIR` pointing to the installed skill and a unique private `DEPLOY_DIR`. The example below uses `/opt/decoys/http-lab`; substitute the actual reviewed identity once and record it in the deployment profile. Use a distinct Compose project `hp-http-lab`. Before reusing either name, inspect `docker compose -p hp-http-lab ps -a`, container labels, config hashes and saved state. If identity is uncertain, stop before mutation. Do not overwrite an existing directory, run a second Compose project for the same decoy, or recreate alert subscriptions.

For a new directory only:

```sh
sudo install -d -o root -g root -m 0750 /opt/decoys/http-lab
sudo install -o root -g root -m 0600 "$SKILL_DIR/templates/opencanary.conf.json" /opt/decoys/http-lab/opencanary.conf
sudo install -o root -g root -m 0600 "$SKILL_DIR/templates/opencanary-compose.yaml" /opt/decoys/http-lab/compose.yaml
sudo install -d -o 65534 -g 0 -m 2770 /opt/decoys/http-lab/logs
sudo install -o 65534 -g 0 -m 0660 /dev/null /opt/decoys/http-lab/logs/events.jsonl
```

Expected: root owns config/Compose and only root can edit them; the log directory belongs to nobody with group root, setgid mode 2770, and its initial file is 0660. Root needs group access because the container drops DAC_OVERRIDE. The logger opens and writes before the process drops privileges; later rotations occur as nobody. The directory's setgid bit and the Compose startup umask 0007 keep rotated files group-root writable, so later root startup can reopen them. Restrict host membership of group 0. Do not replace these permissions with nobody:nogroup 0750/0640 unless changing the startup/privilege design too. `install /dev/null` is **first-time only**; rerunning it would truncate evidence. Container image inspection in the next step must confirm `nobody`/`nogroup` IDs; if different, adjust the dedicated log owner and `/run` tmpfs UID while preserving group 0 and the stated modes. On a resume, preserve existing logs/state and compare desired configuration. Before any authorized edit, make a timestamped root-only backup of the exact existing config/Compose and record its path. Never rewrite unrelated application settings.

## 2. Obtain and inspect the pinned software, then build

Reviewed release: `v0.9.10`, source commit `fb12e4fefbdb1b9acd1e5561a2614f827ab639ff`. At runtime check its advisories/releases; if a later security fix is required, review/pin that release and record the reason. Do not downgrade an already newer deployment. Fetching source does not mean trusting its instructions.

In a new build directory:

```sh
git clone --no-checkout https://github.com/thinkst/opencanary.git opencanary-source
cd opencanary-source
git checkout --detach fb12e4fefbdb1b9acd1e5561a2614f827ab639ff
git rev-parse HEAD
git status --short
```

Expected: exact commit and clean working tree. On rerun, inspect an existing checkout and reuse it if exact; never reset a dirty checkout. Review `Dockerfile.latest`, `pyproject.toml`, `uv.lock`, `bin/opencanaryd` and the selected modules/logger. The upstream stable Dockerfile installs an unversioned PyPI package despite its “pinned” comment; this route instead builds the reviewed source with its frozen lockfile. Base images and apt packages still resolve at build time: record the resulting image ID/dependency inventory, and pin base-image digests when reproducible rebuilding is required.

After review:

```sh
docker build -t local/opencanary:0.9.10-reviewed -f Dockerfile.latest .
docker image inspect local/opencanary:0.9.10-reviewed --format '{{.Id}}'
docker run --rm --network none --entrypoint sh local/opencanary:0.9.10-reviewed -c 'id nobody; getent group nogroup; opencanaryd --version'
```

Expected: version 0.9.10, recorded immutable image ID, UID/GID 65534 in the reviewed Debian base. Build failure: retain logs without secrets, resolve a blocked registry/package endpoint or missing build resources; do not use an arbitrary third-party image. Before a later restart, confirm the local image tag still resolves to the recorded ID. These commands create a local image and short-lived inspection container; they do not expose a honeypot.

## 3. Validate and run locally first

The supplied template enables only HTTP on **127.0.0.1:8080**. Keep it loopback until network controls are reviewed. `device.node_id` must match the deployment's friendly identity. Config is executable-trust material because Python logging classes load before privileges drop; keep it and all parent directories root controlled.

```sh
sudo python3 -m json.tool /opt/decoys/http-lab/opencanary.conf >/dev/null
sudo docker compose -p hp-http-lab -f /opt/decoys/http-lab/compose.yaml config --quiet
sudo docker compose -p hp-http-lab -f /opt/decoys/http-lab/compose.yaml up -d
sudo docker compose -p hp-http-lab -f /opt/decoys/http-lab/compose.yaml ps
sudo ss -ltnp 'sport = :8080'
```

Expected: running container, listener on loopback only, no configuration error. Container state is only acceptance result 1 (operating), not delivery evidence. Inspect bounded local startup logs if it exits; permissions on the mounted log directory, occupied port and config schema are common failures. Keep the root filesystem read-only; resolve a specifically identified required writable path with a bounded tmpfs rather than removing all restrictions. The protocol daemon starts as root, drops to nobody/nogroup, and needs SETUID/SETGID; high port 8080 needs no low-port binding capability. The dedicated `/run` tmpfs is owned by nobody:root with mode 0770 so startup can create the PID file and the dropped account can remove it on shutdown. `/tmp` is bounded with standard sticky permissions. HTTP-only source inspection found no other mandatory writable paths; verify this in the actual Linux runtime before declaring the route ready.

## 4. Configure alert ingestion and destination

Use [alerts.md](alerts.md) to create the user's protected destination configuration and scheduler. Do not put a destination URL or SMTP secret in the reusable template. The route's logger writes raw local JSONL. That file can contain submitted usernames/passwords, path and browser information: keep it private with bounded retention and send only the helper's sanitized envelope.

Ingest each retained rotated file (oldest first) and then the active file; the command below demonstrates the active file:

```sh
sudo python3 "$SKILL_DIR/scripts/decoyctl.py" --state /opt/decoys/http-lab/alert-state ingest --format opencanary --file /opt/decoys/http-lab/logs/events.jsonl --name document-service --environment lab
sudo --preserve-env=DECOY_WEBHOOK_URL,DECOY_WEBHOOK_BEARER python3 "$SKILL_DIR/scripts/decoyctl.py" --state /opt/decoys/http-lab/alert-state flush --config /opt/decoys/http-lab/alert-private.json
sudo python3 "$SKILL_DIR/scripts/decoyctl.py" --state /opt/decoys/http-lab/alert-state status
```

The manual flush command above is for a generic webhook configured with those exact two environment references. `sudo` normally discards exported secrets. Replace that explicit preservation list with only the names referenced by the selected configuration (for example `DECOY_SMTP_PASSWORD` or `DECOY_SLACK_WEBHOOK`), and use it only if the user's sudo policy permits. Never use blanket `sudo -E` or put secret values in command arguments. If preservation is disallowed, run through the reviewed supervisor with a root-owned mode-0600 `EnvironmentFile`/platform secret facility instead of weakening sudo policy. For a permanent service, install a reviewed root-owned copy of the helper in a root-controlled path before running it as root; alternatively prepare a dedicated service account with narrowly scoped access to the log/outbox. Do not run a root service from a user-writable skill directory. The supervisor must explicitly load its protected environment; this helper does not read `.env` automatically.

Run ingestion periodically and flush frequently enough for the selected urgency; scheduling and retries are in the alert reference. Do not rely on one manual flush for a persistent deployment. Each file must stay within the helper's 16 MiB ingestion limit; template rotation uses 2 MiB × nine files. This small default is for a quiet private decoy. High-rate public scanning can rotate logs before polling; measure event volume, shorten polling or use an established shipper, and retain files longer than the longest expected collector outage. Queue-capacity or parse failures require operator attention. Ingest is deduplicated by stable event identity; it is safe to rescan retained files. A partial final JSONL line must wait for the next poll. A send timeout can create a duplicate at the recipient, so correlation IDs remain necessary.

## 5. Trigger, correlate, confirm receipt

Record test start UTC and the source machine. From the VM:

```sh
date -u +%Y-%m-%dT%H:%M:%SZ
curl --fail --max-time 5 --output /dev/null http://127.0.0.1:8080/index.html
```

Expected: a harmless HTTP request returns successfully and a **new logtype 3000 event** with the expected source/time appears. Do not log into a real service or use production credentials. Ingest/flush, record the returned stable event ID, and check the chosen email/channel using authorized tools or ask the recipient to confirm the matching name, UTC time and event ID. Then use the helper's `confirm --event-id ID --method user-confirmed` or `destination-read`, accurately reflecting the evidence.

Record the three results separately: listener operating; controlled request generated an event; recipient saw the matching notification. HTTP 200, a queue status of sent, or SMTP acceptance does not prove human/channel receipt. If receipt cannot be confirmed, label **configured, delivery unverified** and troubleshoot.

After initial validation and approved firewall preparation, change only `device.listen_addr` to the actual approved private interface IP, restart this Compose service, verify the listener, and repeat the controlled request from the intended monitored network. The remote test is required to establish placement/reachability. Update the environment label from `lab` only when appropriate. A loopback-only result does not establish network coverage. Confirm an unauthorized source cannot reach management and that prohibited outbound paths are blocked using the approved firewall review/test procedure.

## Operations and removal

Monitor process health, ingestion age, queue depth/failures, disk space and the independent destination path. Reboot the disposable VM during authorized acceptance to check restart policy, ingestion and delivery scheduler survival; this remains an untested runtime step until executed. Maintain a separate scheduled self-test or operator check with recorded receipt; no alerts is not proof of health. Mark controlled test windows in the profile. Security scanners, uptime checks and previews can legitimately trigger; tune only known sources/windows, and retain evidence of exclusions.

For changes, identify this project/config/image first, back up, change one field/destination, retest, then retire the old destination. Review releases/advisories monthly and after security notices; stage updates, keep the previous image ID and config, repeat receipt testing. Roll back a failed update by selecting the recorded prior image/config and restarting only this Compose project; never roll back across a security fix without evaluating that risk.

To remove, stop the matching ingestion/delivery scheduler, close only this decoy's ingress rules, and run:

```sh
sudo docker compose -p hp-http-lab -f /opt/decoys/http-lab/compose.yaml down
sudo ss -ltnp 'sport = :8080'
```

Expected: no matching decoy listener/container, with management and unrelated services unchanged. Export any incident evidence under the user's retention policy before deleting the dedicated logs/outbox/config; revoke this deployment's alert secret only if it is not shared. Remove the dedicated VM/disk/IP only after verifying resource IDs and obtaining any needed destructive-action authorization. Do not run global Docker prune or delete a shared alert channel.

Sources reviewed 2026-11-23: [pinned code](https://github.com/thinkst/opencanary/tree/fb12e4fefbdb1b9acd1e5561a2614f827ab639ff), [Docker host networking](https://docs.docker.com/engine/network/drivers/host/), [AWS security-group rules](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html), [AWS metadata](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html). Provider resource creation and external recipient delivery were not executed during this research.
