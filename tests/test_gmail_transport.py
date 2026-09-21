import imaplib
import smtplib
import socket
import ssl
import unittest
from email.message import EmailMessage
from unittest import mock

from services.gmail_transport import (
    GmailTransport,
    GmailTransportError,
    _DirectIPIMAP4SSL,
    _ProxyIMAP4SSL,
    _ProxySMTPSSL,
    _direct_ip_tls_socket,
    _proxy_tls_socket,
)


SOURCE = "owner.name@gmail.com"
ALIAS = "owner.name+alpha@gmail.com"
PASSWORD = "abcdefghijklmnop"


def mail(to=ALIAS, text="Your code is 123456", **headers):
    message = EmailMessage()
    message["From"] = "Example <sender@example.com>"
    message["To"] = to
    message["Subject"] = "验证码"
    for key, value in headers.items():
        message[key.replace("_", "-")] = value
    message.set_content(text)
    return message.as_bytes()


class FakeIMAP:
    def __init__(self, folders=None):
        self.folders = folders if folders is not None else {"INBOX": [(b"81", mail())]}
        self.sock = mock.Mock()
        self.calls = []
        self.selected = None
        self.validity = b"700"
        self.count = None
        self.logged_out = False
        self.shutdown = mock.Mock()

    def login(self, email, password):
        self.credentials = (email, password)
        return "OK", []

    def noop(self):
        return "OK", []

    def logout(self):
        self.logged_out = True
        return "BYE", []

    def list(self):
        flags = {"INBOX": b"\\HasNoChildren", "[Gmail]/All Mail": b"\\All", "[Gmail]/Spam": b"\\Junk"}
        return "OK", [b"(" + flags[name] + b') "/" "' + name.encode() + b'"' for name in self.folders]

    def select(self, mailbox, readonly=False):
        self.calls.append(("select", mailbox, readonly))
        self.selected = mailbox.strip('"')
        return "OK", [str(self.count if self.count is not None else len(self.folders[self.selected])).encode()]

    def response(self, code):
        assert code == "UIDVALIDITY"
        return code, [self.validity]

    def uid(self, command, *args):
        self.calls.append((command, *args))
        messages = self.folders[self.selected]
        if command == "SEARCH":
            return "OK", [b" ".join(uid for uid, _ in messages)]
        assert command == "FETCH"
        uid, fields = args
        raw = next(raw for candidate, raw in messages if candidate == uid)
        if "HEADER.FIELDS" in fields:
            raw = raw.split(b"\n\n", 1)[0] + b"\n\n"
        return "OK", [(b'1 (UID ' + uid + b' INTERNALDATE "16-Sep-2026 11:15:00 +0800" BODY[] {1}', raw), b")"]


class GmailTransportTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeIMAP()
        self.doh_patch = mock.patch("services.gmail_transport._doh_ipv4_addresses", return_value=[])
        self.doh = self.doh_patch.start()
        self.addCleanup(self.doh_patch.stop)
        self.factory_patch = mock.patch("services.gmail_transport.imaplib.IMAP4_SSL", return_value=self.fake)
        self.factory = self.factory_patch.start()
        self.addCleanup(self.factory_patch.stop)
        self.transport = GmailTransport(SOURCE, PASSWORD)
        self.addCleanup(self.transport.close)

    def test_tls_endpoint_context_and_read_only_fetch(self):
        with self.transport as transport:
            rows = transport.list_messages(ALIAS)
        self.assertEqual(len(rows), 1)
        args, kwargs = self.factory.call_args
        self.assertEqual(args, ("imap.gmail.com", 993))
        self.assertLessEqual(kwargs["timeout"], 15)
        self.assertTrue(kwargs["ssl_context"].check_hostname)
        self.assertEqual(kwargs["ssl_context"].verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(self.fake.logged_out)
        self.assertTrue(all(call[2] is True for call in self.fake.calls if call[0] == "select"))
        fetches = [call for call in self.fake.calls if call[0] == "FETCH"]
        self.assertTrue(all("BODY.PEEK[" in call[2] for call in fetches))
        self.assertEqual(set(rows[0]), {"id", "from", "subject", "text", "received_at", "recipients"})
        self.assertEqual(rows[0]["received_at"], "2026-09-16T03:15:00+00:00")
        self.assertEqual(rows[0]["subject"], "验证码")

    def test_candidate_substring_and_base_matches_do_not_cross_aliases(self):
        other = "owner.name+beta@gmail.com"
        self.fake.folders["INBOX"] = [
            (b"1", mail(other)),
            (b"2", mail(SOURCE)),
            (b"3", mail("owner.name+alphabet@gmail.com")),
            (b"4", mail(f'"{ALIAS}" <unrelated@example.com>')),
            (b"5", mail('"Team" <OWNER.NAME+ALPHA@GMAIL.COM>')),
            (b"6", mail("unrelated@example.com", Delivered_To=ALIAS)),
            (b"7", mail("unrelated@example.com", Cc=f"Group <{ALIAS}>")),
            (b"8", mail("ownername+alpha@gmail.com")),
        ]
        rows = self.transport.list_messages(ALIAS)
        self.assertEqual({row["id"].rsplit(":", 1)[1] for row in rows}, {"5", "6", "7"})
        bodies = [call[1] for call in self.fake.calls if call[0] == "FETCH"]
        self.assertEqual(set(bodies), {str(i).encode() for i in range(1, 9)})

    def test_body_is_rechecked_after_header_candidate(self):
        uid = self.fake.uid

        def inconsistent(command, *args):
            status, data = uid(command, *args)
            if command == "FETCH" and "HEADER.FIELDS" not in args[1]:
                return status, [(data[0][0], mail("owner.name+beta@gmail.com"))]
            return status, data

        self.fake.uid = inconsistent
        self.assertEqual(self.transport.list_messages(ALIAS), [])

    def test_logout_timeout_still_shuts_down_socket(self):
        self.transport.connect_test()
        self.fake.logout = mock.Mock(side_effect=socket.timeout(PASSWORD))
        self.transport.close()
        self.fake.shutdown.assert_called_once()
        self.fake.sock.settimeout.assert_called_with(1.0)
        self.assertIsNone(self.transport._imap)

    def test_discovers_all_mail_and_junk_and_identity_is_stable(self):
        self.fake.folders = {
            "INBOX": [(b"81", mail())],
            "[Gmail]/All Mail": [(b"81", mail(text="Archived code"))],
            "[Gmail]/Spam": [(b"81", mail(text="Spam code"))],
        }
        first = self.transport.list_messages(ALIAS)
        second = self.transport.list_messages(ALIAS)
        self.assertEqual([row["id"] for row in first], [row["id"] for row in second])
        self.assertEqual(len({row["id"] for row in first}), 2)
        self.assertFalse(any(":INBOX:" in row["id"] for row in first))
        self.assertTrue(all(":700:81" in row["id"] for row in first))
        self.fake.validity = b"701"
        self.assertFalse({row["id"] for row in first} & {row["id"] for row in self.transport.list_messages(ALIAS)})

    def test_missing_uidvalidity_is_an_error(self):
        self.fake.validity = b""
        with self.assertRaises(GmailTransportError) as raised:
            self.transport.list_messages(ALIAS)
        self.assertEqual(raised.exception.code, "imap_error")

    def test_bounded_recent_window_and_text(self):
        self.fake.count = 50000
        self.fake.folders["INBOX"] = [(str(i).encode(), mail(text="x" * 13000)) for i in range(1, 121)]
        rows = self.transport.list_messages(ALIAS, limit=500)
        searches = [call for call in self.fake.calls if call[0] == "SEARCH"]
        self.assertEqual(len(searches), 1)
        self.assertEqual(searches[0][:3], ("SEARCH", None, "49901:50000"))
        self.assertIn('HEADER Delivered-To "' + ALIAS + '"', searches[0][3])
        self.assertEqual(len(rows), 100)
        self.assertTrue(all(len(row["text"]) == 12000 for row in rows))
        self.assertEqual(len([call for call in self.fake.calls if call[0] == "FETCH"]), 100)

    def test_list_deduplicates_copies_but_keeps_distinct_content(self):
        first = mail(Message_ID="<same-id@example.com>")
        self.fake.folders = {
            "INBOX": [(b"1", first)],
            "[Gmail]/All Mail": [(b"2", first), (b"3", mail(text="Another code", Message_ID="<same-id@example.com>"))],
        }
        rows = self.transport.list_messages(ALIAS)
        self.assertEqual(len(rows), 2)
        self.assertEqual(len(self.transport._scan(ALIAS, 100)), 2)

    def test_list_has_a_total_deadline_and_restores_it_after_timeout(self):
        with mock.patch("services.gmail_transport.time.monotonic", side_effect=[0, 46]):
            with self.assertRaises(GmailTransportError) as raised:
                self.transport.list_messages(ALIAS)
        self.assertEqual(raised.exception.code, "timeout")
        self.assertIsNone(self.transport._deadline)

    def test_caller_deadline_bounds_connect_login_noop_and_scan(self):
        now = [100.0]
        def connect(*args, **kwargs):
            self.assertEqual(kwargs["timeout"], 7.0)
            now[0] += 2
            return self.fake
        def login(*args):
            self.fake.sock.settimeout.assert_called_with(5.0)
            now[0] += 2
            return "OK", []
        def noop():
            self.fake.sock.settimeout.assert_called_with(3.0)
            now[0] += 1
            return "OK", []
        self.factory.side_effect = connect
        self.fake.login = login
        self.fake.noop = noop
        transport = GmailTransport(SOURCE, PASSWORD, deadline=107.0)
        with mock.patch("services.gmail_transport.time.monotonic", side_effect=lambda: now[0]):
            with transport:
                rows = transport.list_messages(ALIAS)
                self.assertEqual(len(rows), 1)
                self.assertEqual(transport._deadline, 107.0)
                self.fake.sock.settimeout.assert_called_with(2.0)
        self.assertIsNone(transport._imap)

    def test_elapsed_caller_deadline_never_opens_connection(self):
        transport = GmailTransport(SOURCE, PASSWORD, deadline=107.0)
        with mock.patch("services.gmail_transport.time.monotonic", return_value=107.0):
            with self.assertRaises(GmailTransportError) as raised:
                with transport:
                    self.fail("An expired wait cannot start a new connection")
        self.assertEqual(raised.exception.code, "timeout")
        self.factory.assert_not_called()
        self.assertIsNone(transport._imap)

    def test_invalid_caller_deadline_is_rejected_without_network(self):
        for deadline in [True, "107", 0, -1, float("nan"), float("inf")]:
            with self.subTest(deadline=deadline), self.assertRaises(GmailTransportError) as raised:
                GmailTransport(SOURCE, PASSWORD, deadline=deadline)
            self.assertEqual(raised.exception.code, "invalid_deadline")
        self.factory.assert_not_called()

    def test_rejects_unowned_aliases_without_network(self):
        for alias in [SOURCE, "owner.name+@gmail.com", "other+alpha@gmail.com", "ownername+alpha@gmail.com", "owner.name+alpha@example.com", ALIAS + "\r\nBcc:x@example.com"]:
            with self.subTest(alias=alias), self.assertRaises(GmailTransportError):
                self.transport.list_messages(alias)
        self.factory.assert_not_called()
        for source in ["owner+tag@gmail.com", "owner@example.com", "Name <owner@gmail.com>"]:
            with self.subTest(source=source), self.assertRaises(GmailTransportError):
                GmailTransport(source, PASSWORD)

    def test_authentication_tls_network_timeout_errors_are_safe(self):
        cases = [
            (imaplib.IMAP4.error(PASSWORD), "authentication_failed", "login"),
            (ssl.SSLError(PASSWORD), "tls_error", "connect"),
            (socket.timeout(PASSWORD), "timeout", "connect"),
            (OSError(PASSWORD), "network_error", "connect"),
        ]
        for error, code, where in cases:
            self.transport.close()
            self.factory.side_effect = error if where == "connect" else None
            self.fake.login = mock.Mock(side_effect=error) if where == "login" else mock.Mock(return_value=("OK", []))
            with self.subTest(code=code), self.assertRaises(GmailTransportError) as raised:
                self.transport.connect_test()
            self.assertEqual(raised.exception.code, code)
            self.assertNotIn(PASSWORD, str(raised.exception))
            self.assertTrue(raised.exception.__suppress_context__)

    def test_tls_eof_is_retryable_but_certificate_failure_remains_tls_error(self):
        for error, code in [
            (ssl.SSLEOFError(8, "UNEXPECTED_EOF_WHILE_READING " + PASSWORD), "network_error"),
            (ssl.SSLCertVerificationError(1, "CERTIFICATE_VERIFY_FAILED " + PASSWORD), "tls_error"),
        ]:
            with self.subTest(exception=type(error).__name__):
                self.factory.side_effect = error
                with self.assertRaises(GmailTransportError) as raised:
                    self.transport.connect_test()
                self.assertEqual(raised.exception.code, code)
                self.assertNotIn(PASSWORD, str(raised.exception))
                self.assertTrue(raised.exception.__suppress_context__)
                self.assertIsNone(self.transport._imap)
                context = self.factory.call_args.kwargs["ssl_context"]
                self.assertTrue(context.check_hostname)
                self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)

    def test_network_failure_retries_public_doh_ip_with_original_tls_hostname(self):
        self.factory.side_effect = ssl.SSLEOFError(8, "UNEXPECTED_EOF_WHILE_READING")
        self.doh.return_value = ["142.250.141.109"]
        with mock.patch("services.gmail_transport._DirectIPIMAP4SSL", return_value=self.fake) as direct:
            self.transport.connect_test()
        direct.assert_called_once()
        self.assertEqual(direct.call_args.args, ("imap.gmail.com", 993))
        self.assertEqual(direct.call_args.kwargs["connect_ip"], "142.250.141.109")
        self.assertTrue(direct.call_args.kwargs["ssl_context"].check_hostname)

    def test_explicit_proxy_failure_never_bypasses_proxy(self):
        transport = GmailTransport(SOURCE, PASSWORD, proxy_url="http://127.0.0.1:7890")
        with mock.patch("services.gmail_transport._ProxyIMAP4SSL", side_effect=OSError("closed")), \
                mock.patch("services.gmail_transport._doh_ipv4_addresses") as doh:
            with self.assertRaises(GmailTransportError):
                transport.connect_test()
        doh.assert_not_called()


class GmailDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.transport = GmailTransport(SOURCE, PASSWORD)
        self.fake = FakeIMAP({"INBOX": [], "[Gmail]/All Mail": []})
        self.imap_patch = mock.patch("services.gmail_transport.imaplib.IMAP4_SSL", return_value=self.fake)
        self.imap_patch.start()
        self.addCleanup(self.imap_patch.stop)
        self.addCleanup(self.transport.close)
        self.smtp_patch = mock.patch("services.gmail_transport.smtplib.SMTP_SSL")
        self.smtp_factory = self.smtp_patch.start()
        self.addCleanup(self.smtp_patch.stop)
        self.smtp = self.smtp_factory.return_value.__enter__.return_value
        self.smtp.send_message.return_value = {}
        self.now = 0.0
        patches = [
            mock.patch("services.gmail_transport.time.monotonic", side_effect=lambda: self.now),
            mock.patch("services.gmail_transport.time.sleep", side_effect=self.advance),
            mock.patch("services.gmail_transport.secrets.token_hex", return_value="unique-test-token"),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def advance(self, seconds):
        self.now += seconds

    def delivered(self, message, **kwargs):
        message["Delivered-To"] = ALIAS
        self.fake.folders["INBOX"] = [(b"99", message.as_bytes())]
        self.fake.folders["[Gmail]/All Mail"] = [(b"99", message.as_bytes())]
        return {}

    def test_fixed_self_test_message_is_confirmed_exactly(self):
        self.smtp.send_message.side_effect = self.delivered
        result = self.transport.test_delivery(ALIAS, timeout=3)
        self.assertTrue(result["ok"])
        args, kwargs = self.smtp_factory.call_args
        self.assertEqual(args, ("smtp.gmail.com", 465))
        self.assertLessEqual(kwargs["timeout"], 15)
        self.assertTrue(kwargs["context"].check_hostname)
        sent = self.smtp.send_message.call_args
        self.assertEqual(sent.kwargs, {"from_addr": SOURCE, "to_addrs": [ALIAS]})
        self.assertNotIn(PASSWORD, str(sent.args[0]))
        self.assertEqual(result["message_id"], sent.args[0]["Message-ID"])
        self.assertTrue(result["received_at"])

    def test_old_mail_substrings_other_alias_and_sent_copy_cannot_confirm(self):
        def send(message, **kwargs):
            outgoing = message.as_bytes()
            delivered = EmailMessage()
            for key, value in message.items():
                delivered[key] = value
            delivered["Delivered-To"] = ALIAS
            delivered.set_content(message.get_content())
            old = delivered.as_bytes().replace(b"<gmail-alias-test.", b"<old-gmail-alias-test.")
            wrong_marker = delivered.as_bytes().replace(b"Gmail alias delivery test: unique-test-token", b"prefix Gmail alias delivery test: unique-test-token suffix")
            wrong_alias = delivered.as_bytes().replace(ALIAS.encode(), b"owner.name+beta@gmail.com")
            self.fake.folders["[Gmail]/All Mail"] = [(b"1", outgoing), (b"2", old), (b"3", wrong_marker), (b"4", wrong_alias)]
            return {}

        self.smtp.send_message.side_effect = send
        result = self.transport.test_delivery(ALIAS, timeout=3)
        self.assertFalse(result["ok"])
        self.assertIn("未确认", result["message"])
        self.assertIn("不代表无法收信", result["message"])
        self.assertEqual(self.now, 3)

    def test_smtp_auth_timeout_and_recipient_validation(self):
        self.smtp.login.side_effect = smtplib.SMTPAuthenticationError(535, PASSWORD.encode())
        with self.assertRaises(GmailTransportError) as raised:
            self.transport.test_delivery(ALIAS)
        self.assertEqual(raised.exception.code, "authentication_failed")
        self.assertNotIn(PASSWORD, str(raised.exception))
        self.smtp.login.side_effect = socket.timeout(PASSWORD)
        with self.assertRaises(GmailTransportError) as raised:
            self.transport.test_delivery(ALIAS)
        self.assertEqual(raised.exception.code, "timeout")
        self.smtp_factory.reset_mock()
        with self.assertRaises(GmailTransportError):
            self.transport.test_delivery("unowned+alias@gmail.com")
        self.smtp_factory.assert_not_called()


class GmailProxyTests(unittest.TestCase):
    def test_proxy_validation_rejects_credentials_or_nonproxy_urls(self):
        for url in ["http://user:secret@127.0.0.1:7890", "https://127.0.0.1:7890", "http://127.0.0.1", "http://127.0.0.1:7890/path", "socks5://127.0.0.1:70000"]:
            with self.subTest(url=url), self.assertRaises(GmailTransportError) as raised:
                GmailTransport(SOURCE, PASSWORD, proxy_url=url)
            self.assertEqual(raised.exception.code, "invalid_proxy")
            self.assertNotIn("secret", str(raised.exception))
        for url in ["http://127.0.0.1:7890", "socks5://localhost:1080", "socks5h://127.0.0.1:1080"]:
            self.assertIsNotNone(GmailTransport(SOURCE, PASSWORD, proxy_url=url)._proxy)

    def test_per_connection_proxy_socket_preserves_tls_hostname(self):
        transport = GmailTransport(SOURCE, PASSWORD, proxy_url="socks5h://127.0.0.1:1080")
        context = mock.Mock()
        with mock.patch("services.gmail_transport.socks.create_connection") as connect:
            result = _proxy_tls_socket("imap.gmail.com", 993, 15, context, transport._proxy)
            self.assertIs(result, context.wrap_socket.return_value)
            connect.assert_called_once_with(("imap.gmail.com", 993), timeout=15,
                                            proxy_type=transport._proxy[0], proxy_addr="127.0.0.1", proxy_port=1080, proxy_rdns=True)
            context.wrap_socket.assert_called_once_with(connect.return_value, server_hostname="imap.gmail.com")
            context.wrap_socket.side_effect = ssl.SSLError("secret")
            with self.assertRaises(ssl.SSLError):
                _proxy_tls_socket("smtp.gmail.com", 465, 15, context, transport._proxy)
            connect.return_value.close.assert_called_once()

    def test_proxy_subclasses_use_their_connection_context(self):
        imap = object.__new__(_ProxyIMAP4SSL)
        imap.host, imap.port, imap.ssl_context, imap._proxy = "imap.gmail.com", 993, mock.Mock(), (1, "localhost", 1080, True)
        smtp = object.__new__(_ProxySMTPSSL)
        smtp.context, smtp._proxy = mock.Mock(), imap._proxy
        with mock.patch("services.gmail_transport._proxy_tls_socket") as connect:
            imap._create_socket(7)
            connect.assert_called_with("imap.gmail.com", 993, 7, imap.ssl_context, imap._proxy)
            smtp._get_socket("smtp.gmail.com", 465, 8)
            connect.assert_called_with("smtp.gmail.com", 465, 8, smtp.context, smtp._proxy)

    def test_direct_ip_subclass_preserves_google_tls_hostname(self):
        imap = object.__new__(_DirectIPIMAP4SSL)
        imap.host, imap.port, imap.ssl_context = "imap.gmail.com", 993, mock.Mock()
        imap._connect_ip = "142.250.141.109"
        with mock.patch("services.gmail_transport._direct_ip_tls_socket") as connect:
            imap._create_socket(7)
        connect.assert_called_once_with(
            "imap.gmail.com", "142.250.141.109", 993, 7, imap.ssl_context,
        )

    def test_direct_ip_socket_connects_ip_but_verifies_google_name(self):
        context = mock.Mock()
        with mock.patch("services.gmail_transport.socket.create_connection") as connect:
            result = _direct_ip_tls_socket("imap.gmail.com", "142.250.141.109", 993, 8, context)
        self.assertIs(result, context.wrap_socket.return_value)
        connect.assert_called_once_with(("142.250.141.109", 993), timeout=8)
        context.wrap_socket.assert_called_once_with(connect.return_value, server_hostname="imap.gmail.com")

    def test_proxy_transport_errors_do_not_expose_proxy_or_password(self):
        transport = GmailTransport(SOURCE, PASSWORD, proxy_url="http://127.0.0.1:7890")
        with mock.patch("services.gmail_transport._ProxyIMAP4SSL", side_effect=OSError("proxy secret " + PASSWORD)) as factory:
            with self.assertRaises(GmailTransportError) as raised:
                transport.connect_test()
        self.assertEqual(raised.exception.code, "network_error")
        self.assertNotIn(PASSWORD, str(raised.exception))
        self.assertNotIn("secret", str(raised.exception))
        self.assertEqual(factory.call_args.args, ("imap.gmail.com", 993))
        self.assertIn("proxy", factory.call_args.kwargs)


if __name__ == "__main__":
    unittest.main()
