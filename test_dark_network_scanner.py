"""Unit tests for DARK NETWORK SCANNER. Run with: python3 -m unittest -v

All network-touching code is tested with mocks — these tests never make a
real socket connection, so they run identically offline, in CI, and on any
platform.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

import dark_network_scanner as cli
from scanner import discovery, portscan, premium, report
from scanner.services import TOP_PORTS, parse_port_spec, service_name


class _FakeStdin(io.StringIO):
    """A StringIO whose isatty() is controllable, to simulate an interactive
    terminal that still has scripted input queued up (input() reads from it
    normally; only isatty() is overridden)."""

    def __init__(self, text: str, tty: bool):
        super().__init__(text)
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


def run_cli(*argv, stdin_text: str | None = None, stdin_isatty: bool = False):
    out, err = io.StringIO(), io.StringIO()
    patches = [contextlib.redirect_stdout(out), contextlib.redirect_stderr(err)]
    if stdin_text is not None:
        patches.append(mock.patch("sys.stdin", _FakeStdin(stdin_text, tty=stdin_isatty)))
    with contextlib.ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


# ==========================================================
#  services.py
# ==========================================================
class ServicesTests(unittest.TestCase):
    def test_known_port_name(self):
        self.assertEqual(service_name(22), "ssh")
        self.assertEqual(service_name(443), "https")

    def test_top_ports_sorted_unique(self):
        self.assertEqual(TOP_PORTS, sorted(set(TOP_PORTS)))

    def test_parse_simple_list(self):
        self.assertEqual(parse_port_spec("22,80,443"), [22, 80, 443])

    def test_parse_range(self):
        self.assertEqual(parse_port_spec("20-23"), [20, 21, 22, 23])

    def test_parse_mixed_and_dedup(self):
        self.assertEqual(parse_port_spec("22,20-23,80"), [20, 21, 22, 23, 80])

    def test_parse_reversed_range(self):
        self.assertEqual(parse_port_spec("23-20"), [20, 21, 22, 23])

    def test_parse_rejects_bad_token(self):
        with self.assertRaises(ValueError):
            parse_port_spec("abc")

    def test_parse_rejects_out_of_range(self):
        with self.assertRaises(ValueError):
            parse_port_spec("0")
        with self.assertRaises(ValueError):
            parse_port_spec("70000")


# ==========================================================
#  discovery.py
# ==========================================================
class DiscoveryTests(unittest.TestCase):
    def test_single_host_passthrough(self):
        self.assertEqual(discovery.expand_targets("192.168.1.5"), ["192.168.1.5"])

    def test_cidr_expands_to_usable_hosts(self):
        hosts = discovery.expand_targets("192.168.1.0/30")
        self.assertEqual(hosts, ["192.168.1.1", "192.168.1.2"])

    def test_slash_32_returns_single_address(self):
        self.assertEqual(discovery.expand_targets("192.168.1.5/32"), ["192.168.1.5"])

    def test_oversized_range_rejected_fast(self):
        with self.assertRaises(ValueError):
            discovery.expand_targets("10.0.0.0/8")

    def test_invalid_cidr_rejected(self):
        with self.assertRaises(ValueError):
            discovery.expand_targets("not-an-ip/24")

    @mock.patch("scanner.discovery._tcp_probe", return_value=True)
    @mock.patch("scanner.discovery._ping_once", return_value=False)
    def test_probe_host_falls_back_to_tcp(self, mock_ping, mock_tcp):
        status = discovery.probe_host("10.0.0.1", timeout=0.1)
        self.assertTrue(status.alive)
        self.assertEqual(status.method, "tcp-probe")

    @mock.patch("scanner.discovery._tcp_probe", return_value=False)
    @mock.patch("scanner.discovery._ping_once", return_value=False)
    def test_probe_host_unreachable(self, mock_ping, mock_tcp):
        status = discovery.probe_host("10.0.0.1", timeout=0.1)
        self.assertFalse(status.alive)
        self.assertEqual(status.method, "unreachable")

    @mock.patch("scanner.discovery.probe_host")
    def test_discover_runs_all_targets(self, mock_probe):
        mock_probe.side_effect = lambda h, timeout=1.0: discovery.HostStatus(h, True, "ping")
        results = discovery.discover("192.168.1.0/30", timeout=0.1)
        self.assertEqual({r.host for r in results}, {"192.168.1.1", "192.168.1.2"})


# ==========================================================
#  portscan.py / banner.py
# ==========================================================
class PortScanTests(unittest.TestCase):
    @mock.patch("socket.create_connection")
    def test_open_port_detected(self, mock_conn):
        mock_conn.return_value.__enter__.return_value = mock.MagicMock()
        result = portscan.scan_port("10.0.0.1", 22, timeout=0.1)
        self.assertTrue(result.open)
        self.assertEqual(result.service, "ssh")

    @mock.patch("socket.create_connection", side_effect=OSError("refused"))
    def test_closed_port_detected(self, mock_conn):
        result = portscan.scan_port("10.0.0.1", 9999, timeout=0.1)
        self.assertFalse(result.open)

    @mock.patch("socket.create_connection")
    def test_scan_ports_returns_sorted_results(self, mock_conn):
        mock_conn.return_value.__enter__.return_value = mock.MagicMock()
        results = portscan.scan_ports("10.0.0.1", [443, 22, 80], timeout=0.1)
        self.assertEqual([r.port for r in results], [22, 80, 443])
        self.assertTrue(all(r.open for r in results))

    def test_banner_http_sends_head_request(self):
        fake_sock = mock.MagicMock()
        fake_sock.recv.return_value = b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n"
        from scanner.banner import read_banner

        text = read_banner(fake_sock, 80, "example.com", timeout=0.5)
        fake_sock.sendall.assert_called_once()
        self.assertIn("HTTP/1.1 200 OK", text)

    def test_banner_non_http_just_reads(self):
        fake_sock = mock.MagicMock()
        fake_sock.recv.return_value = b"SSH-2.0-OpenSSH_9.0\r\n"
        from scanner.banner import read_banner

        text = read_banner(fake_sock, 22, "example.com", timeout=0.5)
        fake_sock.sendall.assert_not_called()
        self.assertIn("SSH-2.0-OpenSSH", text)

    def test_banner_handles_no_data(self):
        fake_sock = mock.MagicMock()
        fake_sock.recv.return_value = b""
        from scanner.banner import read_banner

        self.assertIsNone(read_banner(fake_sock, 22, "example.com", timeout=0.5))


# ==========================================================
#  premium.py
# ==========================================================
class PremiumTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._patch = mock.patch("scanner.premium._LICENSE_FILE", os.path.join(self._tmp.name, "license.key"))
        self._patch.start()
        os.environ.pop(premium._ENV_VAR, None)

    def tearDown(self):
        self._patch.stop()
        self._tmp.cleanup()

    def test_demo_key_is_valid(self):
        key = premium.make_demo_key()
        self.assertTrue(premium._valid_checksum(key))

    def test_garbage_key_is_invalid(self):
        self.assertFalse(premium._valid_checksum("NOT-A-REAL-KEY0"))

    def test_activate_persists_key(self):
        key = premium.make_demo_key("MY-OWN-KEYX")
        self.assertFalse(premium.is_premium())
        self.assertTrue(premium.activate(key))
        self.assertTrue(premium.is_premium())

    def test_env_var_overrides_file(self):
        key = premium.make_demo_key("ENVX-KEYY-ZZZZ")
        os.environ[premium._ENV_VAR] = key
        try:
            self.assertTrue(premium.is_premium())
        finally:
            del os.environ[premium._ENV_VAR]

    def test_activate_rejects_invalid_key(self):
        self.assertFalse(premium.activate("GARBAGE-KEY-0000-0000"))
        self.assertFalse(premium.is_premium())


# ==========================================================
#  report.py
# ==========================================================
class ReportTests(unittest.TestCase):
    def setUp(self):
        hosts = [discovery.HostStatus("10.0.0.1", True, "ping")]
        ports = {"10.0.0.1": [portscan.PortResult(22, True, "ssh", "SSH-2.0-OpenSSH")]}
        self.data = report.results_to_dict("10.0.0.1", hosts, ports)

    def test_to_json_round_trips(self):
        parsed = json.loads(report.to_json(self.data))
        self.assertEqual(parsed["hosts"][0]["ports"][0]["port"], 22)

    def test_to_csv_has_header_and_row(self):
        text = report.to_csv(self.data)
        lines = text.strip().splitlines()
        self.assertEqual(lines[0], "host,alive,method,port,service,banner")
        self.assertIn("22", lines[1])

    def test_to_html_contains_host_and_port(self):
        html = report.to_html(self.data)
        self.assertIn("10.0.0.1", html)
        self.assertIn("22", html)

    def test_to_csv_handles_host_with_no_open_ports(self):
        hosts = [discovery.HostStatus("10.0.0.2", False, "unreachable")]
        data = report.results_to_dict("10.0.0.2", hosts, {})
        text = report.to_csv(data)
        self.assertIn("10.0.0.2", text)


# ==========================================================
#  CLI
# ==========================================================
class CliTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._patch = mock.patch("scanner.premium._LICENSE_FILE", os.path.join(self._tmp.name, "license.key"))
        self._patch.start()
        os.environ.pop(premium._ENV_VAR, None)

    def tearDown(self):
        self._patch.stop()
        self._tmp.cleanup()

    def test_no_target_errors(self):
        code, _, err = run_cli("--yes")
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("target is required", err)

    def test_yes_flag_skips_prompt(self):
        with mock.patch("dark_network_scanner.discover", return_value=[]):
            code, out, _ = run_cli("10.0.0.1", "--discover-only", "--yes", "--no-color")
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("Authorization confirmed", out)

    def test_decline_in_interactive_prompt_aborts(self):
        code, _, err = run_cli("10.0.0.1", "--discover-only", "--no-color",
                               stdin_text="no\n", stdin_isatty=True)
        self.assertEqual(code, cli.EXIT_NOT_AUTHORIZED)
        self.assertIn("Not authorized", err)

    def test_accept_in_interactive_prompt_proceeds(self):
        with mock.patch("dark_network_scanner.discover", return_value=[]):
            code, out, _ = run_cli("10.0.0.1", "--discover-only", "--no-color",
                                   stdin_text="yes\n", stdin_isatty=True)
        self.assertEqual(code, cli.EXIT_OK)

    def test_non_interactive_without_yes_is_refused(self):
        code, _, err = run_cli("10.0.0.1", "--discover-only", "--no-color", stdin_text="")
        self.assertEqual(code, cli.EXIT_NOT_AUTHORIZED)
        self.assertIn("Refusing to scan", err)

    def test_bad_port_spec_errors(self):
        code, _, err = run_cli("10.0.0.1", "-p", "notaport", "--yes", "--no-color")
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("Invalid port", err)

    def test_demo_key_prints_valid_key(self):
        code, out, _ = run_cli("--demo-key")
        self.assertEqual(code, cli.EXIT_OK)
        self.assertTrue(premium._valid_checksum(out.strip()))

    def test_activate_then_premium_flag_accepted(self):
        key = premium.make_demo_key()
        code, _, _ = run_cli("--activate", key)
        self.assertEqual(code, cli.EXIT_OK)
        self.assertTrue(premium.is_premium())

    def test_premium_export_blocked_without_license(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_path = os.path.join(tmp, "report.json")
            code, _, err = run_cli("10.0.0.1", "--discover-only", "--yes", "--no-color", "--json", out_path)
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("Premium feature", err)
        self.assertFalse(os.path.exists(out_path))

    def test_premium_json_export_after_activation(self):
        key = premium.make_demo_key()
        premium.activate(key)
        with tempfile.TemporaryDirectory() as tmp:
            out_path = os.path.join(tmp, "report.json")
            with mock.patch("dark_network_scanner.discover",
                             return_value=[discovery.HostStatus("10.0.0.1", True, "ping")]), \
                 mock.patch("dark_network_scanner.scan_ports", return_value=[]):
                code, _, _ = run_cli("10.0.0.1", "--discover-only", "--yes", "--no-color", "--json", out_path)
            self.assertEqual(code, cli.EXIT_OK)
            with open(out_path, encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertEqual(data["hosts"][0]["host"], "10.0.0.1")

    def test_version_flag_exits_zero(self):
        with self.assertRaises(SystemExit) as ctx:
            run_cli("-V")
        self.assertEqual(ctx.exception.code, 0)

    def test_help_with_no_args_shows_banner_and_usage(self):
        code, out, _ = run_cli()
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("usage:", out)

    def test_single_host_scanned_even_if_discovery_says_down(self):
        down_host = discovery.HostStatus("10.0.0.1", False, "unreachable")
        with mock.patch("dark_network_scanner.discover", return_value=[down_host]), \
             mock.patch("dark_network_scanner.scan_ports") as mock_scan:
            mock_scan.return_value = [portscan.PortResult(22, True, "ssh")]
            code, out, _ = run_cli("10.0.0.1", "--yes", "--no-color", "-p", "22")
        self.assertEqual(code, cli.EXIT_OK)
        mock_scan.assert_called_once()  # port scan ran despite "down" status
        self.assertIn("scanning anyway", out)


if __name__ == "__main__":
    unittest.main()
