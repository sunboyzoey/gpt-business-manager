from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from sqlalchemy import inspect, text
from sqlmodel import Session, create_engine, select

from services import gmail_store as store
from services import gmail_import_jobs as jobs


class GmailStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.temp.name) / 'gmail.sqlite'}",
                                    connect_args={"check_same_thread": False, "timeout": 10})
        self.engine_patch = patch.object(store, "engine", self.engine)
        self.engine_patch.start()
        self.env_patch = patch.dict("os.environ", {"APP_CREDENTIAL_ENCRYPTION_KEY": base64.urlsafe_b64encode(b"g" * 32).decode()})
        self.env_patch.start()
        store.init_tables(self.engine)
        self.manager = jobs.GmailImportJobManager()
        self.check_patch = patch.object(store, "_check_app_password")
        self.check_patch.start()
        self.jobs_patch = patch.object(jobs, "manager", self.manager)
        self.jobs_patch.start()
        self.verify_patch = patch("services.gmail_verifier.verify_login", return_value={"ok": True, "code": "verified", "method": "web"})
        self.verify_patch.start()

    def tearDown(self):
        self.manager.shutdown(3)
        self.verify_patch.stop()
        self.jobs_patch.stop()
        self.check_patch.stop()
        self.env_patch.stop()
        self.engine_patch.stop()
        self.engine.dispose()
        self.temp.cleanup()

    def import_sources(self, data):
        start = store.import_sources(data)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            result = self.manager.get(start["job_id"])
            if result["status"] in {"completed", "cancelled"}:
                return result
            time.sleep(0.005)
        self.fail("import job did not complete")

    def source(self, email="owner@gmail.com"):
        return store.create_source(email, "abcd efgh ijkl mnop")

    def test_only_gmail_tables_are_created(self):
        self.assertEqual(set(inspect(self.engine).get_table_names()), {"gmail_sources", "gmail_aliases"})

    def test_source_is_canonical_encrypted_and_public_dto_has_no_credentials(self):
        source = self.source(" Ow.Ner@GMAIL.COM ")
        self.assertEqual(source["email"], "owner@gmail.com")
        self.assertTrue(source["has_password"])
        public = json.dumps(store.list_sources(), default=str)
        self.assertNotIn("abcdefghijklmnop", public)
        self.assertNotIn("ciphertext", public)
        with Session(self.engine) as session:
            row = session.get(store.GmailSource, source["id"])
            self.assertNotIn("abcdefghijklmnop", row.app_password_ciphertext)
            self.assertTrue(row.app_password_ciphertext.startswith("gmail-source:"))
        snapshot = store.network_snapshot(source["id"])
        self.assertEqual(store.decrypt_snapshot_password(snapshot), "abcdefghijklmnop")
        self.assertNotIn(snapshot.password_ciphertext, repr(snapshot))

    def test_duplicate_dotted_case_source_rejected(self):
        self.source("owner@gmail.com")
        with self.assertRaises(store.GmailStoreError) as caught:
            self.source("Ow.Ner@gmail.com")
        self.assertEqual(caught.exception.code, "duplicate_source")

    def test_source_validation_and_password_messages_never_echo_input(self):
        for email in ("owner+tag@gmail.com", "owner@googlemail.com", "owner@example.com", "o..wner@gmail.com", "x\r\n@gmail.com"):
            with self.subTest(email=email), self.assertRaises(store.GmailStoreError):
                self.source(email)
        secret = "password-is-secret"
        with self.assertRaises(store.GmailStoreError) as caught:
            store.create_source("owner@gmail.com", secret)
        self.assertNotIn(secret, str(caught.exception))

    def test_generated_aliases_keep_binding_and_monotonic_sequence(self):
        source = self.source()
        first = store.generate_aliases(source["id"], count=2, prefix="demo-")
        second = store.generate_aliases(source["id"], count=1, prefix="other")
        self.assertEqual([row["email"] for row in first + second], ["owner+demo-1@gmail.com", "owner+demo-2@gmail.com", "owner+other3@gmail.com"])
        self.assertTrue(all(row["source_id"] == source["id"] for row in first + second))
        self.assertEqual(store.list_sources()[0]["alias_count"], 3)

    def test_alias_allocation_serializes_concurrent_batches(self):
        source = self.source()
        def generate(_):
            try:
                return store.generate_aliases(source["id"], count=1, prefix="test")
            except store.GmailStoreError as exc:
                self.assertEqual(exc.code, "source_alias_limit")
                return []
        with ThreadPoolExecutor(max_workers=8) as executor:
            batches = list(executor.map(generate, range(8)))
        emails = [row["email"] for batch in batches for row in batch]
        self.assertEqual(len(emails), 3)
        self.assertEqual(len(set(emails)), 3)
        with Session(self.engine) as session:
            self.assertEqual(session.get(store.GmailSource, source["id"]).next_alias_sequence, 4)
        self.assertFalse(store.list_sources()[0]["can_generate_aliases"])
        self.assertEqual(store.list_sources()[0]["remaining_alias_count"], 0)

    def test_rejected_batch_and_rolled_back_nv_transaction_do_not_consume_capacity(self):
        source = self.source()
        store.generate_aliases(source["id"], count=2, prefix="child")
        with self.assertRaises(store.GmailStoreError) as caught:
            store.generate_aliases(source["id"], count=2, prefix="child")
        self.assertEqual(caught.exception.code, "source_alias_limit")
        self.assertEqual(len(store.list_aliases(source["id"])), 2)
        with Session(self.engine) as session:
            created = store.generate_aliases_in_session(session, source["id"], count=1, prefix="child")
            self.assertEqual(created[0].email, "owner+child3@gmail.com")
            session.rollback()
        self.assertEqual(store.list_sources()[0]["remaining_alias_count"], 1)
        self.assertEqual(store.generate_aliases(source["id"], count=1, prefix="child")[0]["email"], "owner+child3@gmail.com")

    def test_deleted_alias_does_not_release_lifetime_capacity(self):
        source = self.source()
        children = store.generate_aliases(source["id"], count=3, prefix="child")
        with Session(self.engine) as session:
            session.delete(session.get(store.GmailAlias, children[0]["id"]))
            session.commit()
        state = store.list_sources()[0]
        self.assertEqual(state["alias_count"], 2)
        self.assertEqual(state["generated_alias_count"], 3)
        self.assertEqual(state["remaining_alias_count"], 0)
        with self.assertRaises(store.GmailStoreError) as caught:
            store.generate_aliases(source["id"], count=1, prefix="another")
        self.assertEqual(caught.exception.code, "source_alias_limit")

    def test_legacy_over_limit_aliases_are_preserved_but_excluded_from_new_registration(self):
        source = self.source()
        with Session(self.engine) as session:
            for number in range(1, 6):
                session.add(store.GmailAlias(source_id=source["id"], tag=f"legacy{number}", email=f"owner+legacy{number}@gmail.com"))
            session.commit()
        state = store.list_sources()[0]
        self.assertEqual(state["alias_count"], 5)
        self.assertEqual(state["remaining_alias_count"], 0)
        self.assertFalse(state["can_generate_aliases"])
        aliases = store.list_aliases(source["id"])
        self.assertEqual([item["alias_limit_exceeded"] for item in aliases], [True, True, False, False, False])
        with self.assertRaises(store.GmailStoreError):
            store.generate_aliases(source["id"], count=1, prefix="new")
        self.assertEqual(len(store.list_aliases(source["id"])), 5)

    def test_alias_numeric_prefix_collision_is_skipped(self):
        source = self.source()
        one = store.generate_aliases(source["id"], count=1, prefix="a1")
        with Session(self.engine) as session:
            row = session.get(store.GmailSource, source["id"])
            row.next_alias_sequence = 11
            session.add(row)
            session.commit()
        more = store.generate_aliases(source["id"], count=2, prefix="a")
        self.assertEqual(one[0]["email"], "owner+a11@gmail.com")
        self.assertEqual(len({row["email"] for row in one + more}), 3)
        self.assertEqual(more[-1]["email"], "owner+a13@gmail.com")

    def test_disabled_source_rejects_new_aliases_and_network_but_allows_reads(self):
        source = self.source()
        store.generate_aliases(source["id"], count=1, prefix="test")
        disabled = store.update_source(source["id"], enabled=False)
        self.assertFalse(disabled["enabled"])
        self.assertEqual(len(store.list_aliases(source["id"])), 1)
        for action in (lambda: store.generate_aliases(source["id"], count=1, prefix="test"), lambda: store.network_snapshot(source["id"])):
            with self.assertRaises(store.GmailStoreError) as caught:
                action()
            self.assertEqual(caught.exception.code, "source_disabled")

    def test_alias_source_filter_and_network_snapshot_are_scoped(self):
        first, second = self.source(), self.source("other@gmail.com")
        alias = store.generate_aliases(first["id"], count=1, prefix="test")[0]
        self.assertEqual(store.list_aliases(second["id"]), [])
        with self.assertRaises(store.GmailStoreError) as caught:
            store.network_snapshot(second["id"], alias["id"])
        self.assertEqual(caught.exception.code, "alias_mismatch")

    def test_invalid_alias_requests_do_not_consume_sequence(self):
        source = self.source()
        for count, prefix in ((0, "a"), (4, "a"), (101, "a"), (True, "a"), (1, ""), (1, "UPPER"), (1, "x@y"), (1, "a" * 33)):
            with self.subTest(count=count, prefix=prefix), self.assertRaises(store.GmailStoreError):
                store.generate_aliases(source["id"], count=count, prefix=prefix)
        self.assertEqual(store.generate_aliases(source["id"], count=1, prefix="a")[0]["email"], "owner+a1@gmail.com")

    def test_password_or_enabled_change_fences_stale_network_results(self):
        source = self.source()
        alias = store.generate_aliases(source["id"], count=1, prefix="test")[0]
        snapshot = store.network_snapshot(source["id"], alias["id"])
        store.update_source(source["id"], app_password="ponmlkjihgfedcba")
        self.assertFalse(store.record_network_result(snapshot, status="auth_required", message="old failure", checked_at=store.utcnow(), test_receive=True))
        self.assertEqual(store.list_sources()[0]["status"], "ok")
        self.assertEqual(store.list_aliases()[0]["last_test_status"], "untested")
        fresh = store.network_snapshot(source["id"], alias["id"])
        self.assertTrue(store.record_network_result(fresh, status="ok", message="ok", checked_at=store.utcnow(), test_receive=True))
        self.assertEqual(store.list_aliases()[0]["last_test_status"], "ok")
        store.update_source(source["id"], enabled=False)
        self.assertFalse(store.record_network_result(fresh, status="ok", message="ok", checked_at=store.utcnow()))

    def test_proxy_validation_and_revision_change(self):
        source = self.source()
        snapshot = store.network_snapshot(source["id"])
        changed = store.update_source(source["id"], proxy_url="socks5h://127.0.0.1:7890")
        self.assertEqual(changed["proxy_url"], "socks5h://127.0.0.1:7890")
        self.assertGreater(store.network_snapshot(source["id"]).revision, snapshot.revision)
        for proxy in ("https://localhost:7890", "http://localhost", "http://user:secret@localhost:7890", "http://localhost:7890/", "http://localhost:7890?q=secret", "http://localhost:99999"):
            with self.subTest(proxy=proxy), self.assertRaises(store.GmailStoreError) as caught:
                store.update_source(source["id"], proxy_url=proxy)
            self.assertNotIn("secret", str(caught.exception))
        self.assertEqual(store.update_source(source["id"], proxy_url="")["proxy_url"], "")

    def import_line(self, email="owner@gmail.com", password="login password only", recovery="backup@example.com",
                    totp="JBSWY3DPEHPK3PXP", url="https://codes.example.com/read?token=private-url-token"):
        return "----".join((email, password, recovery, totp, url))

    def test_import_encrypts_each_secret_and_does_not_grant_receive_authorization(self):
        from core.gmail_crypto import decrypt_gmail_secret

        result = self.import_sources(self.import_line(email=" Ow.Ner@GMAIL.COM ", password="  login password only  ",
                                                       totp="jbsw y3dp ehpk 3pxp"))
        self.assertEqual((result["created"], result["updated"], result["skipped"], result["failed"]), (1, 0, 0, 0))
        item = result["items"][0]
        self.assertEqual(item["email"], "owner@gmail.com")
        self.assertEqual(item["recovery_email"], "backup@example.com")
        self.assertEqual(item["status"], "credentials_imported")
        self.assertEqual(item["credential_format"], "five_field")
        self.assertTrue(all(item[key] for key in ("has_login_password", "has_totp_secret", "has_verification_url")))
        self.assertFalse(item["has_password"])
        self.assertFalse(item["has_app_password"])
        self.assertFalse(item["receive_ready"])
        public = json.dumps(result, default=str)
        for secret in ("login password only", "JBSWY3DPEHPK3PXP", "private-url-token", "codes.example.com", "ciphertext"):
            self.assertNotIn(secret, public)
        with Session(self.engine) as session:
            row = session.get(store.GmailSource, item["id"])
            self.assertEqual(row.app_password_ciphertext, "")
            for name, expected in (("login_password", "login password only"), ("totp_secret", "JBSWY3DPEHPK3PXP"),
                                   ("verification_url", "https://codes.example.com/read?token=private-url-token")):
                ciphertext = getattr(row, f"{name}_ciphertext")
                self.assertNotIn(expected, ciphertext)
                self.assertEqual(decrypt_gmail_secret(row.email, name, ciphertext), expected)
        alias = store.generate_aliases(item["id"], count=1, prefix="import")[0]
        self.assertEqual(alias["email"], "owner+import1@gmail.com")
        with self.assertRaises(store.GmailStoreError) as caught:
            store.network_snapshot(item["id"], alias["id"])
        self.assertEqual(caught.exception.code, "receive_auth_required")

    def test_import_is_idempotent_with_normalized_duplicates_and_blank_lines(self):
        result = self.import_sources("\n" + self.import_line() + "\n\n" + self.import_line(email="Ow.Ner@GMAIL.COM"))
        self.assertEqual((result["created"], result["skipped"]), (1, 1))
        self.assertEqual(len(result["items"]), 1)
        with Session(self.engine) as session:
            before = session.get(store.GmailSource, result["items"][0]["id"]).model_dump()
        repeated = self.import_sources(self.import_line())
        self.assertEqual((repeated["created"], repeated["updated"], repeated["skipped"]), (0, 0, 1))
        with Session(self.engine) as session:
            after = session.get(store.GmailSource, before["id"]).model_dump()
            for key in ("login_password_ciphertext", "totp_secret_ciphertext", "verification_url_ciphertext", "recovery_email"):
                self.assertEqual(before[key], after[key])
            self.assertGreater(after["credential_revision"], before["credential_revision"])

    def test_import_preserves_app_authorization_aliases_proxy_and_network_state(self):
        source = self.source()
        store.update_source(source["id"], proxy_url="http://localhost:7890")
        alias = store.generate_aliases(source["id"], count=1, prefix="kept")[0]
        snapshot = store.network_snapshot(source["id"], alias["id"])
        store.record_network_result(snapshot, status="auth_required", message="saved status", checked_at=store.utcnow())
        with Session(self.engine) as session:
            before = session.get(store.GmailSource, source["id"]).model_dump()
        first = self.import_sources(self.import_line())
        self.assertEqual(first["updated"], 1)
        changed = self.import_sources(self.import_line(password="new login password", recovery="new-backup@example.com"))
        self.assertEqual(changed["updated"], 1)
        with Session(self.engine) as session:
            after = session.get(store.GmailSource, source["id"]).model_dump()
        for key in ("app_password_ciphertext", "proxy_url", "status", "last_error", "last_checked_at",
                    "next_alias_sequence", "enabled", "created_at"):
            self.assertEqual(before[key], after[key], key)
        self.assertEqual(store.list_aliases(), [alias])
        self.assertFalse(changed["items"][0]["receive_ready"])
        self.assertTrue(changed["items"][0]["can_generate_aliases"])
        self.assertEqual(store.decrypt_snapshot_password(snapshot), "abcdefghijklmnop")

    def test_invalid_import_rows_are_atomic_numbered_and_do_not_echo_secrets(self):
        invalid = [
            "sentinel-secret----too-few",
            self.import_line() + "----extra-secret",
            self.import_line(email="secret+tag@gmail.com"),
            self.import_line(password=""), self.import_line(recovery="invalid-recovery-secret"),
            self.import_line(totp="INVALID-SECRET-0"), self.import_line(totp="ABC"),
            self.import_line(url="javascript:private-token"), self.import_line(url="https://host:99999/private-token"),
            self.import_line(url="https://host/private token"),
        ]
        result = self.import_sources("\n".join([invalid[0], self.import_line(), *invalid[1:]]))
        self.assertEqual(result["failed"], len(invalid))
        self.assertEqual(result["created"], 1)
        self.assertEqual([item["line"] for item in result["errors"]], [1, *range(3, len(invalid) + 2)])
        errors = json.dumps(result["errors"], ensure_ascii=False)
        for secret in ("sentinel-secret", "extra-secret", "secret+tag", "invalid-recovery-secret", "INVALID-SECRET", "private-token"):
            self.assertNotIn(secret, errors)
        self.assertEqual(len(store.list_sources()), 1)

    def test_import_crypto_failure_does_not_partially_update_credentials(self):
        self.import_sources(self.import_line())
        with Session(self.engine) as session:
            before = session.exec(select(store.GmailSource)).one().model_dump()
        with patch("core.gmail_crypto.encrypt_gmail_secret", side_effect=ValueError("private-key-details")):
            result = self.import_sources(self.import_line(password="changed-secret"))
        self.assertEqual(result["failed"], 1)
        self.assertNotIn("private-key-details", str(result))
        with Session(self.engine) as session:
            self.assertEqual(before, session.exec(select(store.GmailSource)).one().model_dump())

    def test_import_batch_limit_is_checked_before_saving(self):
        with self.assertRaises(store.GmailStoreError):
            self.import_sources("\n".join([self.import_line()] * 1001))
        self.assertEqual(store.list_sources(), [])

    def test_import_serializes_concurrent_duplicate_sources(self):
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(lambda _: self.import_sources(self.import_line()), range(4)))
        self.assertEqual(sum(result["created"] for result in results), 1)
        self.assertEqual(sum(result["skipped"] for result in results), 3)
        self.assertEqual(sum(result["failed"] for result in results), 0)

    def test_imported_source_enable_state_never_claims_authorization(self):
        source = self.import_sources(self.import_line())["items"][0]
        disabled = store.update_source(source["id"], enabled=False)
        self.assertFalse(disabled["enabled"])
        enabled = store.update_source(source["id"], enabled=True)
        self.assertEqual(enabled["status"], "credentials_imported")
        self.assertFalse(enabled["receive_ready"])
        authorized = store.update_source(source["id"], app_password="abcdefghijklmnop")
        self.assertTrue(authorized["receive_ready"])
        self.assertEqual(authorized["status"], "ok")

    def test_existing_schema_migration_preserves_encrypted_authorization_and_aliases(self):
        from core.gmail_crypto import encrypt_gmail_password

        old_engine = create_engine(f"sqlite:///{Path(self.temp.name) / 'old-schema.sqlite'}")
        ciphertext = encrypt_gmail_password("owner@gmail.com", "abcdefghijklmnop")
        try:
            with old_engine.begin() as connection:
                connection.execute(text("""CREATE TABLE gmail_sources (
                    id INTEGER PRIMARY KEY, email VARCHAR(254) NOT NULL UNIQUE,
                    app_password_ciphertext VARCHAR NOT NULL, proxy_url VARCHAR NOT NULL,
                    enabled BOOLEAN NOT NULL, status VARCHAR NOT NULL, last_error VARCHAR NOT NULL,
                    last_checked_at DATETIME, next_alias_sequence INTEGER NOT NULL,
                    credential_revision INTEGER NOT NULL, created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL
                )"""))
                connection.execute(text("""INSERT INTO gmail_sources VALUES
                    (1, 'owner@gmail.com', :ciphertext, 'http://localhost:7890', 1, 'ok', '',
                     '2026-09-16 00:00:00', 2, 3, '2026-09-16 00:00:00', '2026-09-16 00:00:00')
                """), {"ciphertext": ciphertext})
            store.init_tables(old_engine)
            with Session(old_engine) as session:
                session.add(store.GmailAlias(source_id=1, email="owner+kept1@gmail.com", tag="kept1"))
                session.commit()
            store.init_tables(old_engine)
            with patch.object(store, "engine", old_engine):
                migrated = store.list_sources()[0]
                self.assertEqual(migrated["status"], "ok")
                self.assertEqual(migrated["alias_count"], 1)
                self.assertEqual(migrated["generated_alias_count"], 1)
                self.assertEqual(migrated["remaining_alias_count"], 2)
                self.assertFalse(migrated["has_login_password"])
                snapshot = store.network_snapshot(1)
                self.assertEqual(snapshot.password_ciphertext, ciphertext)
                self.assertEqual(store.decrypt_snapshot_password(snapshot), "abcdefghijklmnop")
                self.assertEqual(snapshot.revision, 3)
                self.assertEqual(self.import_sources(self.import_line())["updated"], 1)
                self.assertEqual(store.list_sources()[0]["status"], "ok")
                self.assertEqual(store.list_aliases()[0]["email"], "owner+kept1@gmail.com")
        finally:
            old_engine.dispose()


if __name__ == "__main__":
    unittest.main()
