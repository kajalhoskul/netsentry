from netsentry.fingerprint import fingerprint


def test_openssh_banner():
    fp = fingerprint("SSH-2.0-OpenSSH_7.4")
    assert fp["service"] == "OpenSSH"
    assert fp["version"] == "7.4"


def test_apache_banner():
    fp = fingerprint("HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\n")
    assert fp["service"] == "Apache"
    assert fp["version"] == "2.4.49"


def test_vsftpd_banner():
    fp = fingerprint("220 (vsftpd 2.3.4)")
    assert fp["service"] == "vsftpd"
    assert fp["version"] == "2.3.4"


def test_unknown_banner():
    fp = fingerprint("totally unrecognized string")
    assert fp["service"] is None
