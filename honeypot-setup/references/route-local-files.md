# Dedicated local file decoy

Use only when the goal is noticing a modification, replacement or deletion of a **dedicated harmless decoy file**. This shipped polling watcher does not detect reads, copies, exfiltration or a secret being used. It does not identify ransomware and is not prevention. A change can be legitimate editing, backup restoration, synchronization or security software. For stolen-credential use choose a genuine instrumented token; an arbitrary fake key has no alert mechanism.

Supported helper environment: Python 3.10+ on a persistent local machine or isolated Linux host. Local validation ran on macOS; Linux is source-reviewed. Windows now has implemented and tested ACL handling for sensitive local state, but this does not prove scheduler compatibility or reliable background execution after sleep, logout or reboot. Windows ACL support was validated on Windows 11 with Python 3.13.14. No root is required for a file the service user can stat and a private state directory it can write. No inbound port. Needs process/scheduler lifetime, persistent SQLite, and outbound HTTPS or TLS SMTP. A sleeping/offline machine cannot observe/deliver changes in real time.

The watcher compares existence, device/inode, size and modification time. It never reads file contents and ignores access time. A change that is restored completely between polls, filesystem timestamp quirks, denied permissions, stopped monitoring or an attacker able to edit the watcher/state can defeat it. Stat errors fail visibly. Symlinks/directories are refused. Treat metadata as a narrow signal, not full file-audit coverage; use an existing OS/EDR audit facility if read-level evidence is required, after validating that product's actual event support.

## One step at a time

1. **Placement and preflight.** Identify the user-owned folder in which a decoy would be meaningful and not routinely edited. Choose a new filename; check it is absent. Record the path in private inventory. Pick a local monitoring account, persistent directory and notification destination. Expected: clear ownership and a file that will not become production configuration. If every available location is ephemeral, choose a hosted callback token or persistent host instead.
2. **Create harmless bait without overwriting.** With `DECOY_FILE` set locally to the approved absolute path, run:

   ```sh
   python3 -c 'import os,pathlib; p=pathlib.Path(os.environ["DECOY_FILE"]); p.open("x").write("Demonstration decoy. No real account or customer data.\n")'
   ```

   Export `DECOY_FILE` first (it is a path, not a secret). Expected: one new file. Existing file: inspect/verify its identity and resume; never delete it to force the command to pass. Store no real keys. This helper deliberately avoids credential-looking production config that software might accidentally load.
3. **Configure alerts** following [alerts.md](alerts.md). Expected: private config and a delivery-only test whose receipt can be confirmed. If missing, fix transport before the mechanism test.
4. **Register without resetting an existing baseline.** Set `SKILL_DIR` and `DECOY_STATE` to the verified private paths, then:

   ```sh
   python3 "$SKILL_DIR/scripts/decoyctl.py" --state "$DECOY_STATE" watch-add --name "Local file decoy" --file "$DECOY_FILE"
   python3 "$SKILL_DIR/scripts/decoyctl.py" --state "$DECOY_STATE" watch-poll --environment local
   ```

   Expected: first registration or `existing: true`; initial poll queues zero. Re-registering the same path/name preserves its baseline. A mismatched path is an identity error, not permission to overwrite.
5. **Controlled trigger.** Note UTC start time; append a harmless line to this dedicated decoy only:

   ```sh
   python3 -c 'import os,pathlib; p=pathlib.Path(os.environ["DECOY_FILE"]); p.open("a").write("Authorized alert self-test\n")'
   python3 "$SKILL_DIR/scripts/decoyctl.py" --state "$DECOY_STATE" watch-poll --environment local
   python3 "$SKILL_DIR/scripts/decoyctl.py" --state "$DECOY_STATE" flush --config "$DECOY_STATE/alert.json"
   python3 "$SKILL_DIR/scripts/decoyctl.py" --state "$DECOY_STATE" status
   ```

   Expected: one `file_changed` event with ID/time, followed by delivery status. A restored initial file may trigger a second legitimate event; record it. The watcher does not know that an edit is authorized, so correlate using the test window. Recover from no event by checking path, permission and registration, then from missing notification using the outbox ledger.
6. **Acceptance.** Inspect or ask the user to confirm the matching event at the chosen destination. Record separate evidence for registration/poll operation, observed change and receipt. Read the file without modifying it as a negative check: no alert is expected, which demonstrates the coverage boundary.
7. **Persistence.** Configure the user's existing scheduler/supervisor for `watch-poll` followed by repeated `flush` calls using absolute paths and protected environment. Agree on a poll interval and check restart/reboot/sleep behavior. Expected: two later supervised checks succeed and a fresh file test arrives within the selected latency. If no persistent runner is installed, label the setup **manual-only**, not continuously monitored. Use an independent operations check for stalled schedules and outbox failures.

Setup estimate: 15–30 minutes when Python and a working alert destination exist, plus scheduler work. No new hosting fee on an existing machine; message/service fees and maintenance remain. This estimate is engineering judgment, not measured for every OS.

## Windows ACL policy

On Windows, POSIX mode bits are not sufficient. The helper inspects the actual DACL for the state directory, configuration file and SQLite database.

Trusted principals:

- The current Windows user's SID.
- LocalSystem (`S-1-5-18`).
- BUILTIN Administrators (`S-1-5-32-544`).

Other principals receive no access grants. The validator accepts only standard allow ACEs for approved SIDs, with the full-control mask emitted by this helper and the expected directory/file inheritance flags. Deny, object, callback, audit and other unsupported ACE types, unexpected masks/flags, malformed ACE/SID data, and inherited grants to Everyone, Authenticated Users, Users or any other unapproved principal are rejected. This is a deliberately narrow DACL policy, not a general Windows effective-access evaluator. Existing directories and configuration files are validated but never silently rewritten. Symlinks and reparse points are rejected. ACL or Windows API failures fail closed with a `ConfigError`.

SQLite's main database and every pre-existing `-wal`, `-shm` and `-journal` sidecar are checked before SQLite is allowed to open the database, including orphan sidecars when the main database is absent. Newly created sidecars must inherit the already-validated private state-directory DACL; the helper does not attempt to repair a sidecar after SQLite may have written sensitive data.

If an ACL check fails, restrict access to your Windows user, SYSTEM and Administrators before continuing. Do not weaken the check or rely on `chmod` success on Windows.

Windows ACL support does not prove scheduler compatibility, reliable background execution after sleep, logout or reboot, or full local-file monitoring support. The watcher still only observes documented file metadata changes.

## Removal and rollback

Verify the watch name and absolute path, then use `watch-remove --name "Local file decoy" --expected-file "$DECOY_FILE"` with the same script/state prefix. This removes only the watch, never the file. Remove only its exact scheduled job. Inspect ownership and contents of the decoy before deleting it; retain or remove private logs/outbox according to the agreed policy. Revoke only dedicated destination secrets no other integration uses. If a step failed before monitoring began, remove the newly created decoy only after verifying it is still the file you created.
