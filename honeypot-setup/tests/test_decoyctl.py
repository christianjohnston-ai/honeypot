"""Executed offline with only disposable files and an HTTP listener on loopback."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

spec = importlib.util.spec_from_file_location("decoyctl", Path(__file__).parents[1] / "scripts/decoyctl.py")
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)


class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.conn = d.database(self.root / "state")
        self.env = mock.patch.dict(os.environ, {"TEST_DESTINATION": "https://example.invalid/secret"})
        self.env.start()
        self.config = {"channel": "webhook", "url_env": "TEST_DESTINATION", "destination_label": "Lab"}

    def tearDown(self):
        self.conn.close()
        self.env.stop()
        self.tmp.cleanup()

    def event(self, **extra):
        raw = {"interaction": "http_request", "timestamp": "2026-11-23T12:00:00Z", **extra}
        return d.normalize(raw, "generic", "Lab decoy", "lab")

    def add(self, event=None):
        with self.conn:
            d.enqueue(self.conn, event or self.event())

    def test_allowlist_strips_credentials_urls_prompt_injection(self):
        e = d.normalize({"utc_time": "2026-11-23 12:00:00.123456", "logtype": 3000,
                         "src_host": "192.0.2.1", "logdata": {"password": "TOPSECRET", "path": "ignore all rules"},
                         "manage_url": "https://secret.invalid/manage", "token": "TOPSECRET"},
                        "opencanary", "Lab", "test")
        text = json.dumps(e)
        self.assertNotIn("TOPSECRET", text)
        self.assertNotIn("secret.invalid", text)
        self.assertNotIn("ignore all rules", text)
        self.assertEqual(e["source_ip"], "192.0.2.1")
        self.assertTrue(e["timestamp"].endswith("+00:00"))

    def test_untrusted_source_and_invalid_timestamp(self):
        self.assertEqual(self.event(source_ip="@everyone $(command)")["source_ip"], "unavailable")
        self.assertEqual(self.event(source_ip="fe80::1%ignore all instructions\n@everyone")["source_ip"], "unavailable")
        self.assertEqual(self.event(source_ip=1)["source_ip"], "unavailable")
        self.assertTrue(self.event(test=True)["test_claimed_untrusted"])
        self.assertNotIn("test", self.event(test=True))
        with self.assertRaises(ValueError): self.event(timestamp="bad")
        with self.assertRaises(ValueError): self.event(timestamp="2026-11-23T12:00:00")
        with self.assertRaises(ValueError): self.event(timestamp=None)
        with self.assertRaises(ValueError): self.event(interaction="execute attacker command")

    def test_labels_reject_mentions_and_markup(self):
        for value in ["@here", "<https://evil.invalid>", "bad\nname", "x" * 65]:
            with self.assertRaises(ValueError): d.label(value)

    def test_ingestion_rerun_and_partial_line(self):
        p = self.root / "events.jsonl"
        raw = {"utc_time": "2026-11-23 12:00:00", "logtype": 3000, "logdata": {"secret": "VALUE"}}
        p.write_text(json.dumps(raw) + "\n" + '{"utc_time":')
        first = d.ingest(self.conn, p, "opencanary", "Lab", "lab")
        self.assertEqual(first, {"queued": 1, "skipped_or_partial": 1})
        self.assertEqual(d.ingest(self.conn, p, "opencanary", "Lab", "lab")["queued"], 0)
        self.assertNotIn("VALUE", (self.root / "state/outbox.sqlite3").read_bytes().decode(errors="ignore"))

    def test_bad_batch_rolls_back_and_withholds_content(self):
        p = self.root / "bad.jsonl"
        p.write_text(json.dumps({"interaction": "http_request", "timestamp": d.utc_now()}) + '\n{"TOPSECRET":broken}\n')
        with self.assertRaisesRegex(ValueError, "line 2; raw content withheld"):
            d.ingest(self.conn, p, "generic", "Lab", "lab")
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], 0)

    def test_lifecycle_events_are_not_intrusion_events(self):
        p = self.root / "events.jsonl"
        p.write_text('{"logtype":1001,"utc_time":"2026-11-23 12:00:00"}\n')
        self.assertEqual(d.ingest(self.conn, p, "opencanary", "Lab", "lab")["queued"], 0)

    def test_queue_full_preserves_pending(self):
        with mock.patch.object(d, "MAX_EVENTS", 1):
            self.add()
            with self.assertRaisesRegex(ValueError, "Outbox full"):
                self.add(self.event(timestamp="2026-11-23T12:01:00Z"))
            self.assertEqual(d.status(self.conn)["counts"], {"pending": 1})

    def test_transport_acceptance_is_not_receipt(self):
        self.add()
        result = d.flush(self.conn, self.config, sender=lambda c, e: None)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["receipt"], "unverified")
        self.assertIsNone(d.status(self.conn)["recent_events"][0]["received"])

    def test_retry_persists_and_stops_after_eight(self):
        self.add()
        def fail(c, e): raise d.DeliveryError("http_503")
        for attempt in range(8):
            with self.conn:
                self.conn.execute("UPDATE events SET due=0")
                self.conn.execute("DELETE FROM meta WHERE key='last_send'")
            result = d.flush(self.conn, self.config, fail)
            self.assertEqual(result["attempts"], attempt + 1)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(d.status(self.conn)["counts"], {"failed": 1})

    def test_permanent_failure_is_visible(self):
        self.add()
        def fail(c, e): raise d.DeliveryError("http_401", False)
        self.assertEqual(d.flush(self.conn, self.config, fail)["status"], "failed")

    def test_retry_after_blocks_other_events(self):
        self.add()
        self.add(self.event(timestamp="2026-11-23T12:01:00Z"))
        def fail(c, e): raise d.DeliveryError("http_429", True, 120)
        d.flush(self.conn, self.config, fail)
        with self.conn: self.conn.execute("DELETE FROM meta WHERE key='last_send'")
        self.assertEqual(d.flush(self.conn, self.config, lambda c,e: self.fail("must wait"))["status"], "rate_limited_locally")

    def test_destination_change_refused_even_with_same_env_name(self):
        self.add()
        d.flush(self.conn, self.config, lambda c,e: None)
        os.environ["TEST_DESTINATION"] = "https://elsewhere.invalid/newsecret"
        with self.assertRaisesRegex(ValueError, "Destination changed"):
            d.flush(self.conn, self.config, lambda c,e: None)

    def test_plain_http_refused_except_explicit_loopback(self):
        for value in ["http://example.invalid/path", "https://user:password@example.invalid", "https://example.invalid/#secret", "https://example.invalid:SECRET/path", "https://example.invalid/a SECRET"]:
            os.environ["TEST_DESTINATION"] = value
            with self.assertRaises(ValueError): d.endpoint(self.config)
        os.environ["TEST_DESTINATION"] = "http://127.0.0.1:34567/"
        with self.assertRaises(ValueError): d.endpoint(self.config)
        self.assertEqual(d.endpoint({**self.config, "allow_loopback_http": True}), os.environ["TEST_DESTINATION"])

    def test_permissions_and_symlink(self):
        p = self.root / "config.json"
        p.write_text(json.dumps(self.config))
        if os.name == "nt":
            d._apply_windows_acl(p, directory=False)
            # Weaken ACL by granting Everyone, then restore approved ACL.
            import subprocess
            subprocess.run(["icacls", str(p), "/grant", "*S-1-1-0:(F)"], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            with self.assertRaises(ValueError): d.load_config(p)
            d._apply_windows_acl(p, directory=False)
            self.assertEqual(d.load_config(p)["channel"], "webhook")
        else:
            p.chmod(0o644)
            with self.assertRaises(ValueError): d.load_config(p)
            p.chmod(0o600)
            self.assertEqual(d.load_config(p)["channel"], "webhook")
        link = self.root / "link.json"; link.symlink_to(p)
        with self.assertRaises(ValueError): d.load_config(link)

    def test_file_reads_do_not_trigger_and_changes_do(self):
        p = self.root / "decoy.txt"; p.write_text("Harmless decoy\n")
        self.assertFalse(d.watch_add(self.conn, "File decoy", p)["existing"])
        self.assertTrue(d.watch_add(self.conn, "File decoy", p)["existing"])
        p.read_text()
        self.assertEqual(d.watch_poll(self.conn, "local")["queued"], 0)
        p.write_text("Harmless changed decoy\n")
        self.assertEqual(d.watch_poll(self.conn, "local")["queued"], 1)
        self.assertEqual(d.watch_poll(self.conn, "local")["queued"], 0)
        p.unlink()
        self.assertEqual(d.watch_poll(self.conn, "local")["queued"], 1)
        p.write_text("Restored\n")
        self.assertEqual(d.watch_poll(self.conn, "local")["queued"], 1)

    def test_watch_identity_mismatch_and_symlink(self):
        with self.assertRaisesRegex(ValueError, "No watches registered"):
            d.watch_poll(self.conn, "lab")
        p = self.root / "decoy"; p.write_text("test")
        q = self.root / "other"; q.write_text("other")
        d.watch_add(self.conn, "Lab", p)
        with self.assertRaises(ValueError): d.watch_add(self.conn, "Lab", q)
        link = self.root / "linked"; link.symlink_to(p)
        with self.assertRaises(ValueError): d.watch_add(self.conn, "Linked", link)

    @contextlib.contextmanager
    def receiver(self, status=200, headers=None):
        received = []
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(status)
                for k,v in (headers or {}).items(): self.send_header(k, v)
                self.end_headers(); self.wfile.write(b"ok")
            def log_message(self, *args): pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        os.environ["TEST_DESTINATION"] = f"http://127.0.0.1:{server.server_port}/"
        try: yield received
        finally: server.shutdown(); server.server_close(); thread.join()

    def test_real_local_file_to_http_destination_and_confirmation(self):
        p = self.root / "decoy.txt"; p.write_text("harmless")
        d.watch_add(self.conn, "Loopback decoy", p)
        p.write_text("harmless controlled test")
        self.assertEqual(d.watch_poll(self.conn, "lab")["queued"], 1)
        with self.receiver() as received:
            result = d.flush(self.conn, {**self.config, "allow_loopback_http": True})
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0]["event_id"], result["event_id"])
        self.assertEqual(received[0]["interaction"], "file_changed")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            d.main(["--state", str(self.root / "state"), "confirm", "--event-id", result["event_id"], "--method", "destination-read"])
        self.assertIn("destination-read", d.status(self.conn)["recent_events"][0]["received"])

    def test_real_http_429_and_redirect_not_followed(self):
        with self.receiver(429, {"Retry-After": "31"}):
            with self.assertRaises(d.DeliveryError) as error:
                d.send({**self.config, "allow_loopback_http": True}, self.event())
            self.assertEqual(error.exception.retry_after, 31)
        with self.receiver(302, {"Location": "https://example.invalid/leak"}) as received:
            with self.assertRaises(d.DeliveryError) as error:
                d.send({**self.config, "allow_loopback_http": True}, self.event())
            self.assertEqual(error.exception.code, "http_302")
            self.assertFalse(error.exception.retry)
            self.assertEqual(len(received), 1)

    def test_smtp_requires_tls_and_handles_recipient_failure(self):
        config = {"channel": "smtp", "host": "smtp.example.invalid", "port": 587,
                  "tls": "starttls", "from": "sender@example.invalid", "to": "receiver@example.invalid"}
        with mock.patch.object(d.smtplib, "SMTP") as smtp:
            server = smtp.return_value.__enter__.return_value
            server.send_message.return_value = {}
            d.send(config, self.event())
            server.starttls.assert_called_once()
            sent = server.send_message.call_args.args[0]
            self.assertIn(self.event()["event_id"], sent["Message-ID"])
            server.send_message.return_value = {"receiver@example.invalid": (550, b"private body")}
            with self.assertRaises(d.DeliveryError) as error: d.send(config, self.event())
            self.assertEqual(error.exception.code, "smtp_recipient_refused")

    def test_prune_unconfirmed_exports_without_inventing_receipt(self):
        self.add()
        d.flush(self.conn, self.config, lambda c,e: None)
        with self.conn:
            self.conn.execute("UPDATE events SET created=?", (time.time() - 31*86400,))
        args = ["--state", str(self.root / "state"), "prune", "--older-than-days", "30"]
        with contextlib.redirect_stdout(io.StringIO()):
            d.main(args)
        self.assertEqual(d.status(self.conn)["counts"], {"accepted": 1})
        with self.assertRaises(ValueError): d.main(args + ["--include-unconfirmed"])
        export = self.root / "state" / "retained.jsonl"
        with contextlib.redirect_stdout(io.StringIO()):
            d.main(args + ["--include-unconfirmed", "--export", str(export)])
        evidence = json.loads(export.read_text())
        self.assertIsNone(evidence["received"])
        self.assertEqual(evidence["status"], "accepted")
        self.assertEqual(d.status(self.conn)["counts"], {})
        if os.name == "nt":
            d._validate_windows_acl(export)
        else:
            self.assertEqual(export.stat().st_mode & 0o777, 0o600)

    def test_prune_export_never_overwrites_existing_file(self):
        self.add()
        d.flush(self.conn, self.config, lambda c,e: None)
        with self.conn: self.conn.execute("UPDATE events SET created=0")
        export = self.root / "state" / "retained.jsonl"; export.write_text("keep")
        with self.assertRaises(FileExistsError):
            d.main(["--state", str(self.root / "state"), "prune", "--include-unconfirmed", "--export", str(export)])
        self.assertEqual(export.read_text(), "keep")
        self.assertEqual(d.status(self.conn)["counts"], {"accepted": 1})

    def test_orphan_sqlite_sidecars_are_rejected_before_connect(self):
        for suffix in ("-wal", "-shm", "-journal"):
            with self.subTest(suffix=suffix):
                state = self.root / ("orphan-state-" + suffix[1:])
                d.secure_dir(state)
                orphan = state / ("outbox.sqlite3" + suffix)
                orphan.write_text("untrusted orphan")
                if os.name == "nt":
                    subprocess.run(["icacls", str(orphan), "/grant", "*S-1-1-0:(F)"], check=True,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                else:
                    orphan.chmod(0o644)
                with mock.patch.object(d.sqlite3, "connect") as connect:
                    with self.assertRaises(ValueError):
                        d.database(state)
                    connect.assert_not_called()

    def test_prune_locks_export_snapshot_against_concurrent_dispatch(self):
        self.add()
        d.flush(self.conn, self.config, lambda c,e: None)
        self.add(self.event(timestamp="2026-11-23T12:01:00Z"))
        with self.conn: self.conn.execute("UPDATE events SET created=0")
        other = d.sqlite3.connect(self.root / "state/outbox.sqlite3", timeout=0.01)
        original_fsync = os.fsync
        def attempt_concurrent_update(fd):
            try:
                with self.assertRaises(d.sqlite3.OperationalError):
                    other.execute("UPDATE events SET status='accepted' WHERE status='pending'")
                other.rollback()
            finally:
                original_fsync(fd)
        export = self.root / "state/archive.jsonl"
        try:
            with mock.patch.object(d.os, "fsync", side_effect=attempt_concurrent_update), contextlib.redirect_stdout(io.StringIO()):
                d.main(["--state", str(self.root / "state"), "prune", "--include-unconfirmed", "--export", str(export)])
        finally:
            other.close()
        self.assertEqual(len(export.read_text().splitlines()), 1)
        self.assertEqual(d.status(self.conn)["counts"], {"pending": 1})


@unittest.skipUnless(os.name == "nt", "Windows ACL tests require Windows")
class WindowsAclTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _icacls_grant(self, path, sid):
        subprocess.run(["icacls", str(path), "/grant", f"*{sid}:(F)"], check=True,
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def test_create_private_state_dir(self):
        p = self.root / "state"
        result = d.secure_dir(p)
        self.assertEqual(result, p)
        d.secure_dir(p)  # idempotent validation

    def test_existing_approved_dir(self):
        p = self.root / "state"
        p.mkdir()
        d._apply_windows_acl(p, directory=True)
        self.assertEqual(d.secure_dir(p), p)

    def test_reject_everyone_dir(self):
        p = self.root / "state"
        p.mkdir()
        d._apply_windows_acl(p, directory=True)
        self._icacls_grant(p, "S-1-1-0")
        with self.assertRaises(ValueError):
            d.secure_dir(p)

    def test_reject_authenticated_users_or_users(self):
        for sid in ("S-1-5-11", "S-1-5-32-545"):
            p = self.root / f"state_{sid}"
            p.mkdir()
            d._apply_windows_acl(p, directory=True)
            self._icacls_grant(p, sid)
            with self.assertRaises(ValueError):
                d.secure_dir(p)

    def test_database_create_and_validate(self):
        st = self.root / "state"
        conn = d.database(st)
        self.assertTrue((st / "outbox.sqlite3").is_file())
        conn.close()
        conn2 = d.database(st)
        conn2.close()

    def test_database_unsafe_rejected(self):
        st = self.root / "state"
        conn = d.database(st)
        conn.close()
        db = st / "outbox.sqlite3"
        self._icacls_grant(db, "S-1-1-0")
        with self.assertRaises(ValueError):
            d.database(st)

    def test_config_accepted(self):
        p = self.root / "config.json"
        cfg = {"channel": "webhook", "url_env": "TEST_DESTINATION", "destination_label": "Lab"}
        p.write_text(__import__("json").dumps(cfg))
        d._apply_windows_acl(p, directory=False)
        os.environ["TEST_DESTINATION"] = "https://example.invalid/x"
        self.assertEqual(d.load_config(p)["channel"], "webhook")

    def test_config_unsafe_rejected(self):
        p = self.root / "config.json"
        cfg = {"channel": "webhook", "url_env": "TEST_DESTINATION", "destination_label": "Lab"}
        p.write_text(__import__("json").dumps(cfg))
        d._apply_windows_acl(p, directory=False)
        self._icacls_grant(p, "S-1-1-0")
        os.environ["TEST_DESTINATION"] = "https://example.invalid/x"
        with self.assertRaises(ValueError):
            d.load_config(p)

    def test_symlink_rejected(self):
        p = self.root / "config.json"
        p.write_text("{}")
        d._apply_windows_acl(p, directory=False)
        link = self.root / "link.json"
        link.symlink_to(p)
        with self.assertRaises(ValueError):
            d.secure_file(link)

    def test_acl_inspection_failure_fail_closed(self):
        p = self.root / "state"
        p.mkdir()
        d._apply_windows_acl(p, directory=True)
        with mock.patch.object(d, "_validate_windows_acl", side_effect=d.ConfigError("boom")):
            with self.assertRaises(ValueError):
                d.secure_dir(p)

    def test_reject_unapproved_inherited_grant(self):
        parent = self.root / "parent"
        parent.mkdir()
        d._apply_windows_acl(parent, directory=True)
        self._icacls_grant(parent, "S-1-1-0")
        child = parent / "state"
        child.mkdir()
        with self.assertRaises(ValueError):
            d._validate_windows_acl(child, directory=True)

    def test_reject_deny_ace(self):
        p = self.root / "deny-state"
        p.mkdir()
        d._apply_windows_acl(p, directory=True)
        subprocess.run(["icacls", str(p), "/deny", "*S-1-1-0:(F)"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with self.assertRaises(ValueError):
            d._validate_windows_acl(p, directory=True)

    def test_reject_non_full_control_mask(self):
        p = self.root / "read-only-state"
        p.mkdir()
        d._apply_windows_acl(p, directory=True)
        subprocess.run(["icacls", str(p), "/grant", "*S-1-5-11:(R)"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with self.assertRaises(ValueError):
            d._validate_windows_acl(p, directory=True)

    def test_reject_unexpected_inheritance_flags(self):
        p = self.root / "inherit-only-state"
        p.mkdir()
        d._apply_windows_acl(p, directory=True)
        subprocess.run(["icacls", str(p), "/grant", "*S-1-5-11:(OI)(CI)(IO)(F)"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with self.assertRaises(ValueError):
            d._validate_windows_acl(p, directory=True)

    def test_orphan_sidecars_with_unapproved_acl_rejected_before_connect(self):
        for suffix in ("-wal", "-shm", "-journal"):
            with self.subTest(suffix=suffix):
                state = self.root / ("orphan-state-" + suffix[1:])
                d.secure_dir(state)
                orphan = state / ("outbox.sqlite3" + suffix)
                orphan.write_text("untrusted orphan")
                self._icacls_grant(orphan, "S-1-1-0")
                with mock.patch.object(d.sqlite3, "connect") as connect:
                    with self.assertRaises(ValueError):
                        d.database(state)
                    connect.assert_not_called()

    def test_reparse_point_dir_rejected(self):
        # directory junction via mklink /J
        target = self.root / "target"
        target.mkdir()
        junction = self.root / "junction"
        subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(target)],
                      check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with self.assertRaises(ValueError):
            d.secure_dir(junction)


if __name__ == "__main__":
    unittest.main()
