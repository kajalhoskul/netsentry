from netsentry.vuln_db import lookup


def test_vulnerable_vsftpd():
    findings = lookup("vsftpd", "2.3.4")
    assert any(f["cve"] == "CVE-2011-2523" for f in findings)


def test_patched_apache_not_flagged():
    findings = lookup("Apache", "2.4.51")
    assert not any(f["cve"] == "CVE-2021-41773" for f in findings)


def test_vulnerable_apache_flagged():
    findings = lookup("Apache", "2.4.49")
    assert any(f["cve"] == "CVE-2021-41773" for f in findings)


def test_unknown_service_returns_empty():
    assert lookup("SomeRandomThing", "1.0") == []


def test_old_openssh_flagged():
    findings = lookup("OpenSSH", "6.6")
    assert any(f["cve"] == "CVE-2016-10009" for f in findings)


def test_new_openssh_clean():
    findings = lookup("OpenSSH", "9.6")
    assert findings == []
