import socket
import threading
import time

from netsentry.scanner import grab_banner, is_port_open, parse_port_range, scan_host


def _start_fake_server(banner: bytes) -> int:
    """Start a throwaway TCP server on a free port that sends `banner` on connect."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]

    def serve(n_connections: int = 3):
        srv.settimeout(3)
        try:
            for _ in range(n_connections):
                conn, _ = srv.accept()
                conn.sendall(banner)
                try:
                    conn.recv(1024)
                except OSError:
                    pass
                conn.close()
        except OSError:
            pass
        finally:
            srv.close()

    threading.Thread(target=serve, daemon=True).start()
    time.sleep(0.1)
    return port


def test_parse_port_range():
    assert parse_port_range("22,80,1000-1003") == [22, 80, 1000, 1001, 1002, 1003]


def test_is_port_open_true():
    port = _start_fake_server(b"220 (vsftpd 2.3.4)\r\n")
    assert is_port_open("127.0.0.1", port) is True


def test_is_port_open_false():
    # Port 1 is essentially never open on a test box.
    assert is_port_open("127.0.0.1", 1, timeout=0.3) is False


def test_grab_banner_fake_ssh():
    port = _start_fake_server(b"SSH-2.0-OpenSSH_7.4\r\n")
    banner = grab_banner("127.0.0.1", port)
    assert "OpenSSH" in banner


def test_scan_host_finds_fake_service():
    port = _start_fake_server(b"220 (vsftpd 2.3.4)\r\n")
    results = scan_host("127.0.0.1", ports=[port], timeout=0.5)
    assert results[0]["open"] is True
    assert "vsftpd" in results[0]["banner"]
